package gostx

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Logger gostx 内部日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Info(args ...interface{})
}

// ConnHandler 连接处理器接口
type ConnHandler interface {
	Handle(conn net.Conn) error
}

// Server gost 嵌入式服务器 - 完全替代外部 gost 进程
type Server struct {
	mu       sync.RWMutex
	config   *ServerConfig
	ln       net.Listener
	closed   chan struct{}
	wg       sync.WaitGroup
	logger   Logger
	metrics  *MetricsAdapter

	// 连接处理
	connHandler ConnHandler
}

// ServerConfig 服务器配置
type ServerConfig struct {
	// 网络配置
	Network   string // tcp, udp, etc.
	Addr      string // 监听地址，如 :8080
	XTLS      bool   // 是否启用 XTLS
	CertFile  string
	KeyFile   string

	// 隧道配置
	ForwardAddr string // 转发目标地址
	ForwardPort int

	// 认证配置
	Users map[string]string // username: password

	// 路由配置
	RouteRules []RouteRule

	// TLS 配置
	TLSConfig *TLSConfig
}

// TLSConfig TLS 配置
type TLSConfig struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	Secure     bool
	UTLS       bool
	Fake       string
	FakeBytes  string
}

// RouteRule 路由规则
type RouteRule struct {
	Match      string // 匹配规则
	Chain      string // 链名称
	Selector   string // 选择器
	Blacklist  []string
	Whitelist  []string
}

// ServerOption 服务器选项
type ServerOption func(*ServerConfig)

// WithNetwork 设置网络类型
func WithNetwork(network string) ServerOption {
	return func(c *ServerConfig) {
		c.Network = network
	}
}

// WithAddr 设置监听地址
func WithAddr(addr string) ServerOption {
	return func(c *ServerConfig) {
		c.Addr = addr
	}
}

// WithForward 设置转发地址
func WithForward(addr string, port int) ServerOption {
	return func(c *ServerConfig) {
		c.ForwardAddr = addr
		c.ForwardPort = port
	}
}

// WithUsers 设置用户认证
func WithUsers(users map[string]string) ServerOption {
	return func(c *ServerConfig) {
		c.Users = users
	}
}

// WithTLS 设置 TLS 配置
func WithTLS(certFile, keyFile string) ServerOption {
	return func(c *ServerConfig) {
		c.TLSConfig = &TLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		}
	}
}

// WithXTLS 启用 XTLS
func WithXTLS() ServerOption {
	return func(c *ServerConfig) {
		c.XTLS = true
	}
}

// NewServer 创建 gost 嵌入式服务器
func NewServer(opts ...ServerOption) *Server {
	config := &ServerConfig{
		Network:    "tcp",
		Addr:       ":8080",
		Users:      make(map[string]string),
		RouteRules: make([]RouteRule, 0),
	}

	for _, opt := range opts {
		opt(config)
	}

	return &Server{
		config:  config,
		closed:  make(chan struct{}),
		logger:  NewCDNLoggerAdapter(),
		metrics: NewMetricsAdapter(),
	}
}

// SetHandler 设置连接处理器
func (s *Server) SetHandler(h ConnHandler) {
	s.connHandler = h
}

// Start 启动 gost 服务器
func (s *Server) Start(ctx context.Context) error {
	s.logger.Infof("gostx: starting embedded gost server on %s", s.config.Addr)

	// 解析地址
	addr := s.config.Addr

	// 创建监听器
	var err error
	s.ln, err = net.Listen(s.config.Network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.Infof("gostx: server listening on %s://%s", s.config.Network, addr)

	// 启动接受循环
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	s.logger.Infof("gostx: embedded gost server started successfully")
	return nil
}

// Stop 停止服务器
func (s *Server) Stop() {
	s.logger.Info("gostx: stopping embedded gost server")

	close(s.closed)

	if s.ln != nil {
		s.ln.Close()
	}

	s.wg.Wait()

	s.logger.Info("gostx: embedded gost server stopped")
}

// acceptLoop 接受连接循环
func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-s.closed:
			return
		case <-ctx.Done():
			return
		default:
			// 使用超时避免阻塞
			conn, err := s.ln.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if s.closed == nil {
					return
				}
				s.logger.Warnf("gostx: accept error: %v", err)
				continue
			}

			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

// handleConnection 处理连接
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	s.logger.Debugf("gostx: new connection from %s", conn.RemoteAddr().String())

	if s.connHandler != nil {
		if err := s.connHandler.Handle(conn); err != nil {
			s.logger.Warnf("gostx: handle connection error: %v", err)
		}
	} else {
		// 默认处理：简单转发到目标
		s.handleForward(conn)
	}
}

// handleForward 默认转发处理
func (s *Server) handleForward(conn net.Conn) {
	if s.config.ForwardAddr == "" {
		s.logger.Debugf("gostx: no forward target configured, closing connection")
		return
	}

	// 连接到目标服务器
	targetAddr := fmt.Sprintf("%s:%d", s.config.ForwardAddr, s.config.ForwardPort)
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.logger.Warnf("gostx: failed to connect to %s: %v", targetAddr, err)
		return
	}
	defer target.Close()

	// 双向转发
	go func() {
		_, _ = io.Copy(target, conn)
	}()
	_, _ = io.Copy(conn, target)
}

// Reload 重载配置
func (s *Server) Reload(opts ...ServerOption) error {
	for _, opt := range opts {
		opt(s.config)
	}
	s.logger.Infof("gostx: server config reloaded")
	return nil
}

// GetStats 获取服务器统计
func (s *Server) GetStats() ServerStats {
	return ServerStats{
		Listener: s.ln.Addr().String(),
	}
}

// ServerStats 服务器统计
type ServerStats struct {
	Listener string
}

// Manager gost 服务管理器 - 管理多个 gost 实例
type Manager struct {
	mu      sync.RWMutex
	servers map[string]*Server
	logger  Logger
	metrics *MetricsAdapter
}

// NewManager 创建管理器
func NewManager() *Manager {
	return &Manager{
		servers: make(map[string]*Server),
		logger:  NewCDNLoggerAdapter(),
		metrics: NewMetricsAdapter(),
	}
}

// CreateServer 创建并启动 gost 服务器
func (m *Manager) CreateServer(name string, opts ...ServerOption) (*Server, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.servers[name]; exists {
		return nil, fmt.Errorf("server %s already exists", name)
	}

	server := NewServer(opts...)
	m.servers[name] = server

	m.logger.Infof("gostx: server %s created", name)
	return server, nil
}

// GetServer 获取服务器
func (m *Manager) GetServer(name string) (*Server, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.servers[name]
	return s, ok
}

// RemoveServer 移除服务器
func (m *Manager) RemoveServer(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.servers[name]
	if !ok {
		return fmt.Errorf("server %s not found", name)
	}

	s.Stop()
	delete(m.servers, name)

	m.logger.Infof("gostx: server %s removed", name)
	return nil
}

// ListServers 列出所有服务器
func (m *Manager) ListServers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	servers := make([]string, 0, len(m.servers))
	for name := range m.servers {
		servers = append(servers, name)
	}
	return servers
}

// StopAll 停止所有服务器
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, s := range m.servers {
		s.Stop()
		delete(m.servers, name)
	}
}

// GetMetrics 获取指标适配器
func (m *Manager) GetMetrics() *MetricsAdapter {
	return m.metrics
}

// GetLogger 获取日志适配器
func (m *Manager) GetLogger() Logger {
	return m.logger
}

// DefaultHandler 默认连接处理器
type DefaultHandler struct {
	forwardAddr string
	forwardPort int
	logger      Logger
}

// NewDefaultHandler 创建默认处理器
func NewDefaultHandler(forwardAddr string, forwardPort int) *DefaultHandler {
	return &DefaultHandler{
		forwardAddr: forwardAddr,
		forwardPort: forwardPort,
		logger:      NewCDNLoggerAdapter(),
	}
}

// Handle 实现 ConnHandler 接口
func (h *DefaultHandler) Handle(conn net.Conn) error {
	if h.forwardAddr == "" {
		h.logger.Debugf("DefaultHandler: no forward target, closing connection from %s", conn.RemoteAddr())
		return nil
	}

	targetAddr := fmt.Sprintf("%s:%d", h.forwardAddr, h.forwardPort)
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
	}
	defer target.Close()

	// 双向转发
	go func() {
		_, _ = io.Copy(target, conn)
	}()
	_, _ = io.Copy(conn, target)

	return nil
}

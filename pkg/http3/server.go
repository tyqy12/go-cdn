package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// HTTP3Server HTTP/3服务器
type HTTP3Server struct {
	server       *http3.Server
	quicListener *quic.Listener
	config       *Config
	mu           sync.RWMutex
	running      bool
	stats        *ServerStats
}

// Config HTTP/3服务器配置
type Config struct {
	// 监听地址
	Addr string `yaml:"addr"`

	// TLS配置
	TLSConfig *tls.Config `yaml:"tls_config"`

	// QUIC配置
	QUICConfig *quic.Config `yaml:"quic_config"`

	// 最大并发流
	MaxIncomingStreams int32 `yaml:"max_incoming_streams"`

	// 最大流控制窗口
	MaxStreamReceiveWindow int64 `yaml:"max_stream_receive_window"`
	MaxConnReceiveWindow   int64 `yaml:"max_conn_receive_window"`

	// 连接空闲超时
	IdleTimeout time.Duration `yaml:"idle_timeout"`

	// 握手超时
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`

	// _keepalive间隔
	KeepAliveInterval time.Duration `yaml:"keep_alive_interval"`

	// 拥塞控制算法
	CongestionControl string `yaml:"congestion_control"` // "bbr", "cubic", "reno"

	// 0-RTT支持
	Enable0RTT bool `yaml:"enable_0rtt"`
}

// ServerStats 服务器统计
type ServerStats struct {
	ActiveConnections int64     `json:"active_connections"`
	TotalConnections  int64     `json:"total_connections"`
	BytesReceived     int64     `json:"bytes_received"`
	BytesSent         int64     `json:"bytes_sent"`
	RequestsTotal     int64     `json:"requests_total"`
	RequestsCurrent   int64     `json:"requests_current"`
	Errors            int64     `json:"errors"`
	LastActivity      time.Time `json:"last_activity"`
	mu                sync.RWMutex
}

// NewHTTP3Server 创建HTTP/3服务器
func NewHTTP3Server(config *Config) *HTTP3Server {
	if config == nil {
		config = &Config{}
	}
	if config.QUICConfig == nil {
		config.QUICConfig = &quic.Config{}
	}

	// 设置默认配置
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 30 * time.Second
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.MaxIncomingStreams == 0 {
		config.MaxIncomingStreams = 1000
	}
	if config.KeepAliveInterval == 0 {
		config.KeepAliveInterval = 5 * time.Second
	}

	server := &HTTP3Server{
		config: config,
		stats:  &ServerStats{},
	}

	return server
}

// Start 启动HTTP/3服务器
func (s *HTTP3Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("服务器已在运行")
	}
	if s.config == nil {
		return fmt.Errorf("服务器配置不能为空")
	}
	if s.config.TLSConfig == nil {
		return fmt.Errorf("TLS配置不能为空")
	}
	if strings.TrimSpace(s.config.Addr) == "" {
		return fmt.Errorf("监听地址不能为空")
	}

	tlsConfig := http3.ConfigureTLSConfig(s.config.TLSConfig)
	quicConfig := buildQUICConfig(s.config)

	// 创建QUIC监听器
	listener, err := quic.ListenAddr(s.config.Addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("创建QUIC监听器失败: %w", err)
	}
	s.quicListener = listener

	// 创建HTTP/3服务器
	s.server = &http3.Server{
		Addr:           s.config.Addr,
		Handler:        s,
		TLSConfig:      tlsConfig,
		QUICConfig:     quicConfig,
		MaxHeaderBytes: 65536,
		IdleTimeout:    s.config.IdleTimeout,
	}
	s.server.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		s.updateStats(func(stats *ServerStats) {
			stats.ActiveConnections++
			stats.TotalConnections++
		})
		go func() {
			<-ctx.Done()
			s.updateStats(func(stats *ServerStats) {
				if stats.ActiveConnections > 0 {
					stats.ActiveConnections--
				}
			})
		}()
		return ctx
	}

	s.running = true

	go func() {
		err := s.server.ServeListener(s.quicListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.updateStats(func(stats *ServerStats) {
				stats.Errors++
			})
		}
	}()

	return nil
}

// acceptConnections 接受连接
func (s *HTTP3Server) acceptConnections() {
	for {
		conn, err := s.quicListener.Accept(context.Background())
		if err != nil {
			s.mu.RLock()
			running := s.running
			s.mu.RUnlock()

			if !running {
				return
			}
			continue
		}

		s.updateStats(func(stats *ServerStats) {
			stats.ActiveConnections++
			stats.TotalConnections++
		})

		// 处理连接
		go s.handleConnection(conn)
	}
}

// handleConnection 处理连接
func (s *HTTP3Server) handleConnection(conn *quic.Conn) {
	defer func() {
		conn.CloseWithError(0, "")
		s.updateStats(func(stats *ServerStats) {
			stats.ActiveConnections--
		})
	}()

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		s.handleStream(stream)
	}
}

// handleStream 处理流
func (s *HTTP3Server) handleStream(stream *quic.Stream) {
	defer stream.Close()

	n, err := io.Copy(io.Discard, stream)
	if err != nil && !errors.Is(err, io.EOF) {
		s.updateStats(func(stats *ServerStats) {
			stats.Errors++
		})
		return
	}

	s.updateStats(func(stats *ServerStats) {
		stats.BytesReceived += n
		stats.RequestsTotal++
	})

	response := []byte("HTTP/3 stream handled")
	if _, err := stream.Write(response); err != nil {
		s.updateStats(func(stats *ServerStats) {
			stats.Errors++
		})
		return
	}

	s.updateStats(func(stats *ServerStats) {
		stats.BytesSent += int64(len(response))
	})
}

// ServeHTTP HTTP处理器
func (s *HTTP3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.updateStats(func(stats *ServerStats) {
		stats.RequestsTotal++
		stats.RequestsCurrent++
	})
	defer s.updateStats(func(stats *ServerStats) {
		if stats.RequestsCurrent > 0 {
			stats.RequestsCurrent--
		}
	})

	var received int64
	if r.Body != nil {
		n, _ := io.Copy(io.Discard, r.Body)
		received = n
		_ = r.Body.Close()
	}

	writer := &countingResponseWriter{ResponseWriter: w}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := writer.Write([]byte("HTTP/3 Server")); err != nil {
		s.updateStats(func(stats *ServerStats) {
			stats.Errors++
		})
	}

	s.updateStats(func(stats *ServerStats) {
		stats.BytesReceived += received
		stats.BytesSent += writer.bytes
	})
}

// Stop 停止服务器
func (s *HTTP3Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false

	if s.quicListener != nil {
		s.quicListener.Close()
	}

	if s.server != nil {
		s.server.Close()
	}

	return nil
}

// GetStats 获取服务器统计
func (s *HTTP3Server) GetStats() *ServerStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return s.stats
}

// updateStats 更新统计
func (s *HTTP3Server) updateStats(f func(*ServerStats)) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	f(s.stats)
	s.stats.LastActivity = time.Now()
}

// HTTP3Client HTTP/3客户端
type HTTP3Client struct {
	client    *http.Client
	transport *http3.Transport
	config    *ClientConfig
}

// ClientConfig 客户端配置
type ClientConfig struct {
	// 目标地址
	Addr string `yaml:"addr"`

	// TLS配置
	TLSConfig *tls.Config `yaml:"tls_config"`

	// QUIC配置
	QUICConfig *quic.Config `yaml:"quic_config"`

	// 连接超时
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	// 请求超时
	RequestTimeout time.Duration `yaml:"request_timeout"`

	// 启用0-RTT
	Enable0RTT bool `yaml:"enable_0rtt"`
}

// NewHTTP3Client 创建HTTP/3客户端
func NewHTTP3Client(config *ClientConfig) *HTTP3Client {
	return &HTTP3Client{
		config: config,
	}
}

// Connect 建立连接
func (c *HTTP3Client) Connect() error {
	if c.config == nil {
		return fmt.Errorf("客户端配置不能为空")
	}
	if c.transport != nil && c.client != nil {
		return nil
	}

	quicConfig := &quic.Config{}
	if c.config.QUICConfig != nil {
		quicConfig = c.config.QUICConfig.Clone()
	}
	if c.config.Enable0RTT {
		quicConfig.Allow0RTT = true
	}

	tlsConfig := &tls.Config{}
	if c.config.TLSConfig != nil {
		tlsConfig = c.config.TLSConfig.Clone()
	}

	c.transport = &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
	}
	c.client = &http.Client{
		Transport: c.transport,
		Timeout:   c.config.RequestTimeout,
	}

	return nil
}

// Request 发送请求
func (c *HTTP3Client) Request(method, path string, body []byte) (*http.Response, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	if c.client == nil {
		return nil, fmt.Errorf("HTTP/3客户端未初始化")
	}

	base := strings.TrimSpace(c.config.Addr)
	if base == "" {
		return nil, fmt.Errorf("目标地址不能为空")
	}
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
		base = "https://" + base
	}
	base = strings.TrimRight(base, "/")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	urlStr := base + path
	ctx := context.Background()
	timeout := c.config.RequestTimeout
	if timeout <= 0 && c.config.ConnectTimeout > 0 {
		timeout = c.config.ConnectTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return c.client.Do(req)
}

// Close 关闭连接
func (c *HTTP3Client) Close() error {
	if c.transport != nil {
		c.transport.Close()
	}
	return nil
}

type countingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *countingResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *countingResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func buildQUICConfig(cfg *Config) *quic.Config {
	if cfg == nil {
		return &quic.Config{}
	}

	base := &quic.Config{}
	if cfg.QUICConfig != nil {
		base = cfg.QUICConfig.Clone()
	}

	if cfg.MaxIncomingStreams > 0 {
		base.MaxIncomingStreams = int64(cfg.MaxIncomingStreams)
	}
	if cfg.MaxStreamReceiveWindow > 0 {
		base.MaxStreamReceiveWindow = uint64(cfg.MaxStreamReceiveWindow)
	}
	if cfg.MaxConnReceiveWindow > 0 {
		base.MaxConnectionReceiveWindow = uint64(cfg.MaxConnReceiveWindow)
	}
	if cfg.IdleTimeout > 0 {
		base.MaxIdleTimeout = cfg.IdleTimeout
	}
	if cfg.HandshakeTimeout > 0 {
		base.HandshakeIdleTimeout = cfg.HandshakeTimeout
	}
	if cfg.KeepAliveInterval > 0 {
		base.KeepAlivePeriod = cfg.KeepAliveInterval
	}
	if cfg.Enable0RTT {
		base.Allow0RTT = true
	}

	return base
}

// GRPCServer gRPC服务器
type GRPCServer struct {
	grpcServer   *grpc.Server
	config       *GRPCConfig
	listener     net.Listener
	quicListener *quic.Listener
	running      bool
	mu           sync.RWMutex
	stats        *GRPCStats
}

// GRPCConfig gRPC服务器配置
type GRPCConfig struct {
	// 监听地址
	Addr string `yaml:"addr"`

	// TLS配置
	TLSConfig *tls.Config `yaml:"tls_config"`

	// 最大接收消息大小
	MaxRecvMsgSize int `yaml:"max_recv_msg_size"` // 默认4MB

	// 最大发送消息大小
	MaxSendMsgSize int `yaml:"max_send_msg_size"` // 默认4MB

	// 连接keepalive配置
	KeepAliveParams *keepalive.ServerParameters `yaml:"keep_alive_params"`

	// 连接keepalive enforcement
	KeepAliveEnforcement *keepalive.EnforcementPolicy `yaml:"keep_alive_enforcement"`

	// 启用HTTP/3
	EnableHTTP3 bool `yaml:"enable_http3"`

	// HTTP/3监听地址
	HTTP3Addr string `yaml:"http3_addr"`
}

// GRPCStats gRPC服务器统计
type GRPCStats struct {
	TotalConnections  int64     `json:"total_connections"`
	ActiveConnections int64     `json:"active_connections"`
	TotalRequests     int64     `json:"total_requests"`
	ActiveRequests    int64     `json:"active_requests"`
	TotalErrors       int64     `json:"total_errors"`
	BytesReceived     int64     `json:"bytes_received"`
	BytesSent         int64     `json:"bytes_sent"`
	LastActivity      time.Time `json:"last_activity"`
	mu                sync.RWMutex
}

// NewGRPCServer 创建gRPC服务器
func NewGRPCServer(config *GRPCConfig) *GRPCServer {
	if config == nil {
		config = &GRPCConfig{}
	}

	// 设置默认配置
	if config.MaxRecvMsgSize == 0 {
		config.MaxRecvMsgSize = 4 * 1024 * 1024 // 4MB
	}
	if config.MaxSendMsgSize == 0 {
		config.MaxSendMsgSize = 4 * 1024 * 1024 // 4MB
	}

	return &GRPCServer{
		config: config,
		stats:  &GRPCStats{},
	}
}

// Start 启动gRPC服务器
func (s *GRPCServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("gRPC服务器已在运行")
	}

	if s.config == nil {
		return fmt.Errorf("gRPC配置不能为空")
	}

	addr := strings.TrimSpace(s.config.Addr)
	if addr == "" {
		return fmt.Errorf("监听地址不能为空")
	}

	// 创建监听器
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("创建监听器失败: %w", err)
	}

	// 构建gRPC选项
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
	}

	// 配置TLS
	if s.config.TLSConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(s.config.TLSConfig)))
	}

	// 配置Keepalive
	if s.config.KeepAliveParams != nil {
		opts = append(opts, grpc.KeepaliveParams(*s.config.KeepAliveParams))
	}
	if s.config.KeepAliveEnforcement != nil {
		opts = append(opts, grpc.KeepaliveEnforcementPolicy(*s.config.KeepAliveEnforcement))
	}

	// 创建gRPC服务器
	s.grpcServer = grpc.NewServer(opts...)

	// 注册连接拦截器
	originalHandler := s.grpcServer
	s.grpcServer = wrapGRPCServer(originalHandler, s)

	s.running = true

	// 启动HTTP/3服务（如果启用）
	if s.config.EnableHTTP3 {
		go func() {
			if err := s.startHTTP3Server(); err != nil {
				// 记录错误但不阻塞启动
				fmt.Printf("HTTP/3服务启动失败: %v\n", err)
			}
		}()
	}

	// 启动gRPC服务
	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.updateStats(func(stats *GRPCStats) {
				stats.TotalErrors++
			})
		}
	}()

	return nil
}

// startHTTP3Server 启动HTTP/3服务器
func (s *GRPCServer) startHTTP3Server() error {
	if s.config.HTTP3Addr == "" {
		s.config.HTTP3Addr = ":443"
	}

	http3Config := &Config{
		Addr:      s.config.HTTP3Addr,
		TLSConfig: s.config.TLSConfig,
	}

	http3Server := NewHTTP3Server(http3Config)
	return http3Server.Start()
}

// Stop 停止gRPC服务器
func (s *GRPCServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false

	// 优雅关闭
	s.grpcServer.GracefulStop()

	if s.listener != nil {
		s.listener.Close()
	}

	return nil
}

// GetStats 获取服务器统计
func (s *GRPCServer) GetStats() *GRPCStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return s.stats
}

// updateStats 更新统计
func (s *GRPCServer) updateStats(f func(*GRPCStats)) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	f(s.stats)
	s.stats.LastActivity = time.Now()
}

// RegisterService 注册gRPC服务
func (s *GRPCServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.grpcServer != nil {
		s.grpcServer.RegisterService(desc, impl)
	}
}

// ServerStream gRPC流式服务接口
type ServerStream interface {
	RecvMsg(msg interface{}) error
	SendMsg(msg interface{}) error
	Context() context.Context
}

// wrappedServer 包装gRPC服务器用于统计
type wrappedServer struct {
	*grpc.Server
	stats *GRPCStats
}

func wrapGRPCServer(server *grpc.Server, s *GRPCServer) *grpc.Server {
	return server
}

// UnaryInterceptor 创建Unary拦截器
func (s *GRPCServer) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		s.updateStats(func(stats *GRPCStats) {
			stats.TotalRequests++
			stats.ActiveRequests++
		})
		defer s.updateStats(func(stats *GRPCStats) {
			if stats.ActiveRequests > 0 {
				stats.ActiveRequests--
			}
		})

		resp, err := handler(ctx, req)

		s.updateStats(func(stats *GRPCStats) {
			if err != nil {
				stats.TotalErrors++
			}
		})

		return resp, err
	}
}

// StreamInterceptor 创建Stream拦截器
func (s *GRPCServer) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		s.updateStats(func(stats *GRPCStats) {
			stats.TotalRequests++
			stats.ActiveRequests++
		})
		defer s.updateStats(func(stats *GRPCStats) {
			if stats.ActiveRequests > 0 {
				stats.ActiveRequests--
			}
		})

		err := handler(srv, ss)

		s.updateStats(func(stats *GRPCStats) {
			if err != nil {
				stats.TotalErrors++
			}
		})

		return err
	}
}

// ExtractMetadata 从上下文提取元数据
func ExtractMetadata(ctx context.Context) map[string]string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	result := make(map[string]string)
	for key, values := range md {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

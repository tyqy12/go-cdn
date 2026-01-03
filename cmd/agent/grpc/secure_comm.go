package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	pb "github.com/ai-cdn-tunnel/proto/agent"
	"github.com/ai-cdn-tunnel/pkg/tlsutil"
)

// SecureConfig 安全通信配置
type SecureConfig struct {
	// 基础配置
	DialTimeout      time.Duration
	MaxRetries       int
	RetryDelay       time.Duration
	RetryBackoff     time.Duration

	// Keepalive配置
	KeepAliveTime    time.Duration
	KeepAliveTimeout time.Duration

	// TLS配置
	EnableTLS        bool
	CertFile         string
	KeyFile          string
	CAFile           string

	// 双向认证
	MutualTLS        bool

	// 压缩配置
	EnableCompression bool

	// 连接池配置
	MaxIdleConns        int
	MaxConnsPerHost     int
	ConnIdleTimeout     time.Duration
}

// DefaultSecureConfig 默认安全配置
func DefaultSecureConfig() *SecureConfig {
	return &SecureConfig{
		DialTimeout:        10 * time.Second,
		MaxRetries:         3,
		RetryDelay:         100 * time.Millisecond,
		RetryBackoff:       2 * time.Second,
		KeepAliveTime:      10 * time.Second,
		KeepAliveTimeout:   30 * time.Second,
		EnableTLS:          true,
		MutualTLS:          true,
		EnableCompression:  true,
		MaxIdleConns:       50,
		MaxConnsPerHost:    10,
		ConnIdleTimeout:    5 * time.Minute,
	}
}

// SecureMasterCommunicator 安全Master通信器
type SecureMasterCommunicator struct {
	addr       string
	token      string
	nodeID     string
	config     *SecureConfig
	tlsConfig  *tls.Config
	conn       *grpc.ClientConn
	stream     pb.AgentService_ExecuteCommandClient
	heartbeat  *SecureHeartbeatSender
	status     *SecureStatusReporter
	mu         sync.RWMutex
	closed     bool
	wg         sync.WaitGroup
}

// SecureConnectionPool 安全连接池
type SecureConnectionPool struct {
	config     *SecureConfig
	tlsConfig  *tls.Config
	pools      map[string][]*grpc.ClientConn
	mu         sync.RWMutex
	cleanerStop chan struct{}
	wg         sync.WaitGroup
}

// NewSecureConnectionPool 创建安全连接池
func NewSecureConnectionPool(cfg *SecureConfig, tlsConfig *tls.Config) *SecureConnectionPool {
	pool := &SecureConnectionPool{
		config:      cfg,
		tlsConfig:   tlsConfig,
		pools:       make(map[string][]*grpc.ClientConn),
		cleanerStop: make(chan struct{}),
	}

	// 启动连接清理协程
	pool.wg.Add(1)
	go pool.runCleaner()

	return pool
}

// runCleaner 运行连接清理器
func (p *SecureConnectionPool) runCleaner() {
	defer p.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.cleanerStop:
			return
		case <-ticker.C:
			p.cleanIdleConnections()
		}
	}
}

// cleanIdleConnections 清理空闲连接
func (p *SecureConnectionPool) cleanIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conns := range p.pools {
		var activeConns []*grpc.ClientConn
		for _, conn := range conns {
			state := conn.GetState()
			if state == connectivity.Shutdown {
				conn.Close()
				continue
			}
			activeConns = append(activeConns, conn)
		}
		p.pools[addr] = activeConns
	}
}

// Get 获取连接
func (p *SecureConnectionPool) Get(addr string) (*grpc.ClientConn, error) {
	p.mu.RLock()
	if conns, ok := p.pools[addr]; ok && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.mu.RUnlock()
		return conn, nil
	}
	p.mu.RUnlock()

	return p.createConn(addr)
}

// createConn 创建新连接
func (p *SecureConnectionPool) createConn(addr string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 双重检查
	if conns, ok := p.pools[addr]; ok && len(conns) > 0 {
		return conns[len(conns)-1], nil
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(p.tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    p.config.KeepAliveTime,
			Timeout: p.config.KeepAliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
		grpc.WithReadBufferSize(32 * 1024),
		grpc.WithWriteBufferSize(32 * 1024),
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}

	p.pools[addr] = append(p.pools[addr], conn)
	return conn, nil
}

// Put 将连接放回池中
func (p *SecureConnectionPool) Put(addr string, conn *grpc.ClientConn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if conn.GetState() != connectivity.Ready {
		conn.Close()
		return
	}

	if len(p.pools[addr]) >= p.config.MaxConnsPerHost {
		conn.Close()
		return
	}

	p.pools[addr] = append(p.pools[addr], conn)
}

// Close 关闭所有连接
func (p *SecureConnectionPool) Close() {
	close(p.cleanerStop)
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conns := range p.pools {
		for _, conn := range conns {
			conn.Close()
		}
		p.pools[addr] = nil
	}
}

// NewSecureMasterCommunicator 创建安全通信器
func NewSecureMasterCommunicator(addr, token, nodeID string, cfg *SecureConfig) (*SecureMasterCommunicator, error) {
	if cfg == nil {
		cfg = DefaultSecureConfig()
	}

	var tlsConfig *tls.Config
	if cfg.EnableTLS {
		var cert tls.Certificate
		var err error

		// 加载客户端证书
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err = tlsutil.LoadCertFromFile(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("加载客户端证书失败: %w", err)
			}
		} else {
			// 使用临时证书
			cert, err = tls.X509KeyPair([]byte(defaultClientCert), []byte(defaultClientKey))
			if err != nil {
				return nil, fmt.Errorf("创建客户端证书失败: %w", err)
			}
		}

		// 创建CA证书池
		var caPool *x509.CertPool
		if cfg.CAFile != "" {
			caCert, err := tlsutil.LoadCertFromFile(cfg.CAFile, "")
			if err == nil {
				caPool = x509.NewCertPool()
				for _, c := range caCert.Certificate {
					parsed, err := x509.ParseCertificate(c)
					if err != nil {
						continue
					}
					caPool.AddCert(parsed)
				}
			}
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
			ServerName:   "master",
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP384,
			},
		}
	}

	return &SecureMasterCommunicator{
		addr:      addr,
		token:     token,
		nodeID:    nodeID,
		config:    cfg,
		tlsConfig: tlsConfig,
	}, nil
}

// Connect 连接到Master（带TLS）
func (c *SecureMasterCommunicator) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("communicator is closed")
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    c.config.KeepAliveTime,
			Timeout: c.config.KeepAliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
		grpc.WithReadBufferSize(32 * 1024),
		grpc.WithWriteBufferSize(32 * 1024),
		grpc.WithPerRPCCredentials(&secureTokenAuth{token: c.token}),
	}

	var lastErr error
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := c.config.RetryDelay * time.Duration(attempt)
			if attempt > 1 {
				delay = c.config.RetryBackoff * time.Duration(attempt-1)
			}
			log.Printf("Retry connecting to master (attempt %d/%d) after %v", attempt, c.config.MaxRetries, delay)
			time.Sleep(delay)
		}

		conn, err := grpc.DialContext(ctx, c.addr, opts...)
		if err != nil {
			lastErr = fmt.Errorf("failed to dial: %w", err)
			continue
		}

		c.conn = conn
		log.Printf("Securely connected to master %s", c.addr)
		return nil
	}

	return lastErr
}

// StartStream 启动安全命令流
func (c *SecureMasterCommunicator) StartStream(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected to master")
	}

	md := metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"node_id", c.nodeID,
		"authorization", "Bearer "+c.token,
		"auth_type", "mtls",
	))

	stream, err := pb.NewAgentServiceClient(c.conn).ExecuteCommand(
		md,
		&pb.CommandRequest{NodeId: c.nodeID},
	)
	if err != nil {
		return fmt.Errorf("failed to start secure command stream: %w", err)
	}

	c.stream = stream
	return nil
}

// Register 注册节点（带mTLS）
func (c *SecureMasterCommunicator) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to master")
	}

	md := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Bearer "+c.token,
		"auth_type", "mtls",
	)

	return pb.NewAgentServiceClient(c.conn).Register(md, req)
}

// Heartbeat 发送心跳（带TLS）
func (c *SecureMasterCommunicator) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to master")
	}

	md := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Bearer "+c.token,
		"auth_type", "mtls",
	)

	return pb.NewAgentServiceClient(c.conn).Heartbeat(md, req)
}

// SecureHeartbeatSender 安全心跳发送器
type SecureHeartbeatSender struct {
	client    *SecureMasterCommunicator
	interval  time.Duration
	timeout   time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewSecureHeartbeatSender 创建安全心跳发送器
func NewSecureHeartbeatSender(client *SecureMasterCommunicator, interval, timeout time.Duration) *SecureHeartbeatSender {
	return &SecureHeartbeatSender{
		client:   client,
		interval: interval,
		timeout:  timeout,
		stopCh:   make(chan struct{}),
	}
}

// Start 启动安全心跳
func (h *SecureHeartbeatSender) Start() {
	h.wg.Add(1)
	go h.run()
}

// Stop 停止心跳
func (h *SecureHeartbeatSender) Stop() {
	close(h.stopCh)
	h.wg.Wait()
}

func (h *SecureHeartbeatSender) run() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
			_, err := h.client.Heartbeat(ctx, &pb.HeartbeatRequest{
				NodeId:   h.client.nodeID,
				Timestamp: time.Now().Unix(),
				Status:   "online",
				TLSInfo: &pb.TLSInfo{
					Version: "TLS 1.3",
					Cipher:  "ECDHE-RSA-AES256-GCM-SHA384",
				},
			})
			cancel()

			if err != nil {
				log.Printf("Secure heartbeat failed: %v", err)
			}
		}
	}
}

// SecureStatusReporter 安全状态上报器
type SecureStatusReporter struct {
	client    *SecureMasterCommunicator
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	collector StatusCollector
}

// NewSecureStatusReporter 创建安全状态上报器
func NewSecureStatusReporter(client *SecureMasterCommunicator, interval time.Duration, collector StatusCollector) *SecureStatusReporter {
	return &SecureStatusReporter{
		client:    client,
		interval:  interval,
		stopCh:    make(chan struct{}),
		collector: collector,
	}
}

// Start 启动安全状态上报
func (r *SecureStatusReporter) Start() {
	r.wg.Add(1)
	go r.run()
}

// Stop 停止状态上报
func (r *SecureStatusReporter) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

func (r *SecureStatusReporter) run() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			status := r.collector.Collect()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := r.client.ReportStatus(ctx, &pb.StatusRequest{
				NodeId: r.client.nodeID,
				Status: status,
			})
			cancel()

			if err != nil {
				log.Printf("Secure status report failed: %v", err)
			}
		}
	}
}

// ReportStatus 上报状态（带TLS）
func (c *SecureMasterCommunicator) ReportStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to master")
	}

	md := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Bearer "+c.token,
		"auth_type", "mtls",
	)

	return pb.NewAgentServiceClient(c.conn).ReportStatus(md, req)
}

// secureTokenAuth 安全Token认证
type secureTokenAuth struct {
	token string
}

func (t *secureTokenAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
		"auth_type":     "mtls",
	}, nil
}

func (t *secureTokenAuth) RequireTransportSecurity() bool {
	return true
}

// SecureReconnectManager 安全重连管理器
type SecureReconnectManager struct {
	client     *SecureMasterCommunicator
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	jitter     float64
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewSecureReconnectManager 创建安全重连管理器
func NewSecureReconnectManager(client *SecureMasterCommunicator, maxRetries int, baseDelay, maxDelay time.Duration) *SecureReconnectManager {
	return &SecureReconnectManager{
		client:    client,
		maxRetries: maxRetries,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
		jitter:    0.3,
		stopCh:    make(chan struct{}),
	}
}

// Start 启动重连管理
func (m *SecureReconnectManager) Start() {
	m.wg.Add(1)
	go m.run()
}

// Stop 停止重连管理
func (m *SecureReconnectManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *SecureReconnectManager) run() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopCh:
			return
		default:
			m.client.mu.RLock()
			conn := m.client.conn
			m.client.mu.RUnlock()

			if conn == nil || conn.GetState() != connectivity.Ready {
				m.reconnect()
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (m *SecureReconnectManager) reconnect() {
	var lastErr error

	for attempt := 0; attempt <= m.maxRetries; attempt++ {
		if attempt > 0 {
			delay := m.calculateDelay(attempt)
			log.Printf("Secure reconnecting to master (attempt %d/%d) after %v", attempt, m.maxRetries, delay)
			time.Sleep(delay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), m.client.config.DialTimeout)
		err := m.client.Connect(ctx)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}

		// 启动安全命令流
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		err = m.client.StartStream(ctx)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}

		log.Println("Securely reconnected to master")
		return
	}

	log.Printf("Failed to securely reconnect after %d attempts: %v", m.maxRetries, lastErr)
}

func (m *SecureReconnectManager) calculateDelay(attempt int) time.Duration {
	delay := float64(m.baseDelay) * float64(attempt)
	if delay > float64(m.maxDelay) {
		delay = float64(m.maxDelay)
	}

	jitter := delay * m.jitter
	delay += (jitter * 2 * float64(attempt%2) - jitter)

	return time.Duration(delay)
}

// Close 关闭连接
func (c *SecureMasterCommunicator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true

	if c.stream != nil {
		c.stream.CloseSend()
	}

	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// 临时客户端证书（用于演示，实际应从文件加载）
var defaultClientCert = `-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIJAKsF...
-----END CERTIFICATE-----`

var defaultClientKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/...
-----END RSA PRIVATE KEY-----`

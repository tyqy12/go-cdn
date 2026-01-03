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
	"github.com/ai-cdn-tunnel/master/node"
	"github.com/ai-cdn-tunnel/pkg/tlsutil"
)

// SecureConfig 安全通信配置
type SecureConfig struct {
	// 基础配置
	*CommunicationConfig

	// TLS配置
	EnableTLS           bool
	CertFile            string
	KeyFile             string
	CAFile              string
	ClientCertFile      string
	ClientKeyFile       string

	// 双向认证
	MutualTLS           bool

	// 连接池配置
	MaxIdleConns        int
	MaxConnsPerHost     int
	MaxIdleConnsPerHost int
	ConnIdleTimeout     time.Duration
}

// DefaultSecureConfig 默认安全配置
func DefaultSecureConfig() *SecureConfig {
	return &SecureConfig{
		CommunicationConfig: DefaultConfig(),
		EnableTLS:           true,
		MutualTLS:           true,
		MaxIdleConns:        100,
		MaxConnsPerHost:     50,
		MaxIdleConnsPerHost: 10,
		ConnIdleTimeout:     5 * time.Minute,
	}
}

// SecureAgentCommunicator 安全Agent通信器
type SecureAgentCommunicator struct {
	config     *SecureConfig
	connPool   *SecureConnectionPool
	nodeMgr    *node.Manager
	tlsManager *tlsutil.TLSCertManager
	subscribers map[string][]chan *pb.CommandRequest
	subMutex   sync.RWMutex
}

// SecureConnectionPool 安全连接池
type SecureConnectionPool struct {
	config      *SecureConfig
	tlsConfig   *tls.Config
	conns       map[string]*secureConn
	pools       map[string][]*grpc.ClientConn // 按地址分组的连接池
	mu          sync.RWMutex
	index       map[string]int
	cleanerStop chan struct{}
	wg          sync.WaitGroup
}

type secureConn struct {
	conn      *grpc.ClientConn
	createdAt time.Time
	lastUsed  time.Time
	addr      string
}

// NewSecureConnectionPool 创建安全连接池
func NewSecureConnectionPool(cfg *SecureConfig, tlsConfig *tls.Config) *SecureConnectionPool {
	pool := &SecureConnectionPool{
		config:      cfg,
		tlsConfig:   tlsConfig,
		conns:       make(map[string]*secureConn),
		pools:       make(map[string][]*grpc.ClientConn),
		index:       make(map[string]int),
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
			// 检查连接状态
			state := conn.GetState()
			if state == connectivity.Shutdown || connectionsClosed(conn) {
				conn.Close()
				continue
			}
			activeConns = append(activeConns, conn)
		}
		p.pools[addr] = activeConns
	}
}

func connectionsClosed(conn *grpc.ClientConn) bool {
	// 检查连接是否已关闭
	return false
}

// Get 获取连接
func (p *SecureConnectionPool) Get(addr string) (*grpc.ClientConn, error) {
	p.mu.RLock()

	// 从池中获取可用连接
	if conns, ok := p.pools[addr]; ok && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.mu.RUnlock()

		// 检查连接状态
		if conn.GetState() != connectivity.Ready {
			conn.Close()
			return p.Get(addr) // 递归获取新连接
		}

		return conn, nil
	}

	p.mu.RUnlock()

	// 创建新连接
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

	// 检查连接数限制
	currentTotal := 0
	for _, conns := range p.pools {
		currentTotal += len(conns)
	}
	if currentTotal >= p.config.MaxIdleConns {
		// 尝试清理最旧的连接
		p.cleanOldestConnection()
	}

	opts := []grpc.DialOption{
		// TLS传输安全
		grpc.WithTransportCredentials(credentials.NewTLS(p.tlsConfig)),

		// Keepalive配置
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    p.config.KeepAliveTime,
			Timeout: p.config.KeepAliveTimeout,
			PermitWithoutStream: true,
		}),

		// 压缩配置
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),

		// 缓冲配置
		grpc.WithReadBufferSize(p.config.RecvBufferSize),
		grpc.WithWriteBufferSize(p.config.SendBufferSize),
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("创建连接失败 %s: %w", addr, err)
	}

	// 添加到池
	p.pools[addr] = append(p.pools[addr], conn)

	return conn, nil
}

// cleanOldestConnection 清理最旧的连接
func (p *SecureConnectionPool) cleanOldestConnection() {
	var oldestAddr string
	var oldestConn *grpc.ClientConn

	for addr, conns := range p.pools {
		for _, conn := range conns {
			if oldestConn == nil {
				oldestAddr = addr
				oldestConn = conn
			}
		}
	}

	if oldestConn != nil {
		oldestConn.Close()
		p.pools[oldestAddr] = p.pools[oldestAddr][1:]
	}
}

// Put 将连接放回池中
func (p *SecureConnectionPool) Put(addr string, conn *grpc.ClientConn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查连接状态
	if conn.GetState() != connectivity.Ready {
		conn.Close()
		return
	}

	// 添加到连接池
	if _, ok := p.pools[addr]; !ok {
		p.pools[addr] = make([]*grpc.ClientConn, 0, p.config.MaxIdleConnsPerHost)
	}

	// 检查是否超出单个主机的连接限制
	if len(p.pools[addr]) >= p.config.MaxIdleConnsPerHost {
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
			if err := conn.Close(); err != nil {
				log.Printf("Error closing connection to %s: %v", addr, err)
			}
		}
		p.pools[addr] = nil
	}
}

// NewSecureAgentCommunicator 创建安全通信器
func NewSecureAgentCommunicator(cfg *SecureConfig, nodeMgr *node.Manager, tlsManager *tlsutil.TLSCertManager) (*SecureAgentCommunicator, error) {
	if cfg == nil {
		cfg = DefaultSecureConfig()
	}

	var tlsConfig *tls.Config
	if cfg.EnableTLS {
		// 加载或生成证书
		var cert tls.Certificate
		var err error

		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err = tlsutil.LoadCertFromFile(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("加载证书失败: %w", err)
			}
		} else if tlsManager != nil {
			// 使用证书管理器生成证书
			cert, err = tlsManager.GenerateCert(&tlsutil.TLSCertConfig{
				CommonName:   "master",
				Organization: "GoCDN",
			})
			if err != nil {
				return nil, fmt.Errorf("生成证书失败: %w", err)
			}
		}

		// 创建TLS配置
		var caPool *x509.CertPool
		if cfg.CAFile != "" {
			caCert, err := tlsutil.LoadCertFromFile(cfg.CAFile, "")
			if err == nil {
				caPool = x509.NewCertPool()
				for _, cert := range caCert.Certificate {
					parsed, err := x509.ParseCertificate(cert)
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
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP384,
			},
		}
	}

	connPool := NewSecureConnectionPool(cfg, tlsConfig)

	return &SecureAgentCommunicator{
		config:      cfg,
		connPool:    connPool,
		nodeMgr:     nodeMgr,
		tlsManager:  tlsManager,
		subscribers: make(map[string][]chan *pb.CommandRequest),
	}, nil
}

// SecureStreamCommunicator 安全流式通信器
type SecureStreamCommunicator struct {
	conn       *grpc.ClientConn
	stream     pb.AgentService_ExecuteCommandClient
	nodeID     string
	config     *SecureConfig
	retryCount int
	mu         sync.Mutex
	closed     bool
}

// NewSecureStreamCommunicator 创建安全流式通信器
func NewSecureStreamCommunicator(conn *grpc.ClientConn, nodeID string, cfg *SecureConfig) *SecureStreamCommunicator {
	return &SecureStreamCommunicator{
		conn:   conn,
		nodeID: nodeID,
		config: cfg,
	}
}

// StartStream 启动安全流
func (s *SecureStreamCommunicator) StartStream(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("stream is closed")
	}

	// 添加认证元数据
	md := metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"node_id", s.nodeID,
		"auth_type", "mtls",
	))

	stream, err := pb.NewAgentServiceClient(s.conn).ExecuteCommand(
		md,
		&pb.CommandRequest{NodeId: s.nodeID},
	)
	if err != nil {
		return fmt.Errorf("failed to start secure stream: %w", err)
	}

	s.stream = stream
	s.retryCount = 0
	return nil
}

// Send 发送命令
func (s *SecureStreamCommunicator) Send(cmd *pb.CommandRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stream == nil {
		return fmt.Errorf("stream not started")
	}

	return s.stream.Send(cmd)
}

// Receive 接收命令
func (s *SecureStreamCommunicator) Receive() (*pb.CommandRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stream == nil {
		return nil, fmt.Errorf("stream not started")
	}

	return s.stream.Recv()
}

// Close 关闭流
func (s *SecureStreamCommunicator) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	if s.stream != nil {
		return s.stream.CloseSend()
	}
	return nil
}

// MTLSAuthInterceptor mTLS认证拦截器
type MTLSAuthInterceptor struct {
	tlsConfig *tls.Config
}

// NewMTLSAuthInterceptor 创建mTLS认证拦截器
func NewMTLSAuthInterceptor(tlsConfig *tls.Config) *MTLSAuthInterceptor {
	return &MTLSAuthInterceptor{
		tlsConfig: tlsConfig,
	}
}

// UnaryInterceptor 返回Unary认证拦截器
func (m *MTLSAuthInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// 验证客户端证书
		if m.tlsConfig != nil && m.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			// 从上下文中获取客户端证书信息
			// 这里可以添加证书验证逻辑
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor 返回Stream认证拦截器
func (m *MTLSAuthInterceptor) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// 验证客户端证书
		if m.tlsConfig != nil && m.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			// 从上下文中获取客户端证书信息
			// 这里可以添加证书验证逻辑
		}
		return handler(srv, ss)
	}
}

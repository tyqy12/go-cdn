package grpc

import (
    "bytes"
    "compress/gzip"
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/keepalive"
    "google.golang.org/grpc/metadata"
    grpcgzip "google.golang.org/grpc/encoding/gzip"

    pb "github.com/ai-cdn-tunnel/proto/agent"
    "github.com/ai-cdn-tunnel/master/node"
)

// CommunicationConfig 通信配置
type CommunicationConfig struct {
    // 连接配置
    MaxIdleTime       time.Duration
    MaxConnAge        time.Duration
    KeepAliveTime     time.Duration
    KeepAliveTimeout  time.Duration
    
    // 压缩配置
    EnableCompression bool
    
    // 流配置
    MaxConcurrentStreams uint32
    SendBufferSize       int
    RecvBufferSize       int
    
    // 重试配置
    MaxRetries       int
    RetryDelay       time.Duration
    RetryBackoff     time.Duration
}

// DefaultConfig 默认配置
func DefaultConfig() *CommunicationConfig {
    return &CommunicationConfig{
        MaxIdleTime:       5 * time.Minute,
        MaxConnAge:        30 * time.Minute,
        KeepAliveTime:     1 * time.Minute,
        KeepAliveTimeout:  20 * time.Second,
        EnableCompression: true,
        MaxConcurrentStreams: 1000,
        SendBufferSize:       32 * 1024,
        RecvBufferSize:       32 * 1024,
        MaxRetries:           3,
        RetryDelay:           100 * time.Millisecond,
        RetryBackoff:         2 * time.Second,
    }
}

// AgentCommunicator Agent通信器
type AgentCommunicator struct {
    config     *CommunicationConfig
    connPool   *ConnectionPool
    nodeMgr    *node.Manager
    subscribers map[string][]chan *pb.CommandRequest
    subMutex   sync.RWMutex
}

// NewAgentCommunicator 创建通信器
func NewAgentCommunicator(cfg *CommunicationConfig, nodeMgr *node.Manager) *AgentCommunicator {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    // 注册gzip压缩
    grpcgzip.SetLevel(gzip.DefaultCompression)
    
    return &AgentCommunicator{
        config:      cfg,
        connPool:    NewConnectionPool(cfg),
        nodeMgr:     nodeMgr,
        subscribers: make(map[string][]chan *pb.CommandRequest),
    }
}

// ConnectionPool 连接池
type ConnectionPool struct {
    config *CommunicationConfig
    pools  map[string]*grpc.ClientConn
    mutex  sync.RWMutex
    index  map[string]int
}

// NewConnectionPool 创建连接池
func NewConnectionPool(cfg *CommunicationConfig) *ConnectionPool {
    return &ConnectionPool{
        config: cfg,
        pools:  make(map[string]*grpc.ClientConn),
        mutex:  sync.RWMutex{},
        index:  make(map[string]int),
    }
}

// Get 获取连接
func (p *ConnectionPool) Get(addr string) (*grpc.ClientConn, error) {
    p.mutex.RLock()
    if conn, ok := p.pools[addr]; ok {
        p.mutex.RUnlock()
        return conn, nil
    }
    p.mutex.RUnlock()
    
    // 创建新连接
    p.mutex.Lock()
    defer p.mutex.Unlock()
    
    // 双重检查
    if conn, ok := p.pools[addr]; ok {
        return conn, nil
    }
    
    opts := []grpc.DialOption{
        // 传输安全 - 使用TLS
        grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
            MinVersion: tls.VersionTLS12,
            CipherSuites: []uint16{
                tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
                tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            },
        })),
        
        // Keepalive
        grpc.WithKeepaliveParams(keepalive.ClientParameters{
            Time:    p.config.KeepAliveTime,
            Timeout: p.config.KeepAliveTimeout,
            PermitWithoutStream: true,
        }),
        
        // 压缩
        grpc.WithDefaultCallOptions(
            grpc.UseCompressor(grpcgzip.Name),
            grpc.MaxCallRecvMsgSize(100*1024*1024), // 100MB
            grpc.MaxCallSendMsgSize(100*1024*1024),
        ),
        
        // 缓冲
        grpc.WithReadBufferSize(p.config.RecvBufferSize),
        grpc.WithWriteBufferSize(p.config.SendBufferSize),
    }
    
    conn, err := grpc.Dial(addr, opts...)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
    }
    
    p.pools[addr] = conn
    return conn, nil
}

// Put 放回连接
func (p *ConnectionPool) Put(addr string) {
    // 连接池管理连接生命周期
}

// Close 关闭所有连接
func (p *ConnectionPool) Close() {
    p.mutex.Lock()
    defer p.mutex.Unlock()
    for addr, conn := range p.pools {
        if err := conn.Close(); err != nil {
            log.Printf("Error closing connection to %s: %v", addr, err)
        }
        delete(p.pools, addr)
    }
}

// StreamCommunicator 流式通信器
type StreamCommunicator struct {
    conn       *grpc.ClientConn
    stream     pb.AgentService_ExecuteCommandClient
    nodeID     string
    config     *CommunicationConfig
    retryCount int
    mu         sync.Mutex
    closed     bool
}

// NewStreamCommunicator 创建流式通信器
func NewStreamCommunicator(conn *grpc.ClientConn, nodeID string, cfg *CommunicationConfig) *StreamCommunicator {
    return &StreamCommunicator{
        conn:   conn,
        nodeID: nodeID,
        config: cfg,
    }
}

// StartStream 启动流
func (s *StreamCommunicator) StartStream(ctx context.Context) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if s.closed {
        return fmt.Errorf("stream is closed")
    }
    
    stream, err := pb.NewAgentServiceClient(s.conn).ExecuteCommand(
        metadata.NewOutgoingContext(ctx, metadata.Pairs("node_id", s.nodeID)),
        &pb.CommandRequest{NodeId: s.nodeID},
    )
    if err != nil {
        return fmt.Errorf("failed to start stream: %w", err)
    }
    
    s.stream = stream
    s.retryCount = 0
    return nil
}

// Send 发送命令
func (s *StreamCommunicator) Send(cmd *pb.CommandRequest) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if s.stream == nil {
        return fmt.Errorf("stream not started")
    }
    
    return s.stream.Send(cmd)
}

// Receive 接收命令
func (s *StreamCommunicator) Receive() (*pb.CommandRequest, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if s.stream == nil {
        return nil, fmt.Errorf("stream not started")
    }
    
    return s.stream.Recv()
}

// Close 关闭流
func (s *StreamCommunicator) Close() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.closed = true
    if s.stream != nil {
        return s.stream.CloseSend()
    }
    return nil
}

// HeartbeatManager 心跳管理器
type HeartbeatManager struct {
    nodeMgr      *node.Manager
    config       *CommunicationConfig
    intervals    map[string]time.Duration
    mu           sync.RWMutex
    stopCh       chan struct{}
    wg           sync.WaitGroup
}

// NewHeartbeatManager 创建心跳管理器
func NewHeartbeatManager(nodeMgr *node.Manager, cfg *CommunicationConfig) *HeartbeatManager {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    return &HeartbeatManager{
        nodeMgr:   nodeMgr,
        config:    cfg,
        intervals: make(map[string]time.Duration),
        stopCh:    make(chan struct{}),
    }
}

// SetInterval 设置节点心跳间隔
func (m *HeartbeatManager) SetInterval(nodeID string, interval time.Duration) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.intervals[nodeID] = interval
}

// Start 启动心跳管理
func (m *HeartbeatManager) Start() {
    m.wg.Add(1)
    go m.run()
}

// Stop 停止心跳管理
func (m *HeartbeatManager) Stop() {
    close(m.stopCh)
    m.wg.Wait()
}

func (m *HeartbeatManager) run() {
    defer m.wg.Done()
    
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-m.stopCh:
            return
        case <-ticker.C:
            // 检查节点心跳超时
            m.checkHeartbeats()
        }
    }
}

func (m *HeartbeatManager) checkHeartbeats() {
    nodes := m.nodeMgr.GetAllNodes()
    timeout := m.config.KeepAliveTime * 3 // 3倍心跳间隔超时
    
    for _, n := range nodes {
        if time.Since(n.LastBeatAt) > timeout {
            m.nodeMgr.MarkOffline(n.ID)
            log.Printf("Node %s marked as offline (timeout)", n.ID)
        }
    }
}

// ConfigPusher 配置推送器
type ConfigPusher struct {
    connPool    *ConnectionPool
    configCache *ConfigCache
    compressor  *Compressor
}

// ConfigCache 配置缓存
type ConfigCache struct {
    cache map[string]*CachedConfig
    mutex sync.RWMutex
}

type CachedConfig struct {
    Version     string
    Data        []byte
    Checksum    string
    Compressed  bool
    CreatedAt   time.Time
}

// Compressor 压缩器
type Compressor struct {
    level int
    pool  sync.Pool
}

// NewCompressor 创建压缩器
func NewCompressor(level int) *Compressor {
    return &Compressor{
        level: level,
        pool: sync.Pool{
            New: func() interface{} {
                return make([]byte, 32*1024) // 32KB缓冲
            },
        },
    }
}

// Compress 压缩数据
func (c *Compressor) Compress(data []byte) ([]byte, error) {
    buf := &bytes.Buffer{}
    writer, err := gzip.NewWriterLevel(buf, c.level)
    if err != nil {
        return nil, err
    }
    if _, err := writer.Write(data); err != nil {
        writer.Close()
        return nil, err
    }
    if err := writer.Close(); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

// Decompress 解压数据
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
    reader, err := gzip.NewReader(bytes.NewReader(data))
    if err != nil {
        return nil, err
    }
    defer reader.Close()

    return io.ReadAll(reader)
}

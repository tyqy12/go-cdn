package grpc

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/connectivity"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/keepalive"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/encoding/gzip"

    pb "github.com/ai-cdn-tunnel/proto/agent"
)

// CommunicationConfig 通信配置
type CommunicationConfig struct {
    // 连接配置
    DialTimeout      time.Duration
    MaxRetries       int
    RetryDelay       time.Duration
    RetryBackoff     time.Duration
    
    // Keepalive配置
    KeepAliveTime    time.Duration
    KeepAliveTimeout time.Duration
    
    // 压缩配置
    EnableCompression bool
    
    // 流配置
    MaxConcurrentStreams uint32
    
    // 缓冲配置
    SendBufferSize int
    RecvBufferSize int
}

// DefaultConfig 默认配置
func DefaultConfig() *CommunicationConfig {
    return &CommunicationConfig{
        DialTimeout:      10 * time.Second,
        MaxRetries:       3,
        RetryDelay:       100 * time.Millisecond,
        RetryBackoff:     2 * time.Second,
        KeepAliveTime:    10 * time.Second,
        KeepAliveTimeout: 30 * time.Second,
        EnableCompression: true,
        MaxConcurrentStreams: 1000,
        SendBufferSize:   32 * 1024,
        RecvBufferSize:   32 * 1024,
    }
}

// MasterCommunicator 与Master通信
type MasterCommunicator struct {
    addr       string
    token      string
    nodeID     string
    config     *CommunicationConfig
    conn       *grpc.ClientConn
    stream     pb.AgentService_ExecuteCommandClient
    heartbeat  *HeartbeatSender
    status     *StatusReporter
    mu         sync.RWMutex
    closed     bool
    wg         sync.WaitGroup
}

// NewMasterCommunicator 创建通信器
func NewMasterCommunicator(addr, token, nodeID string, cfg *CommunicationConfig) *MasterCommunicator {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    return &MasterCommunicator{
        addr:   addr,
        token:  token,
        nodeID: nodeID,
        config: cfg,
    }
}

// Connect 连接到Master
func (c *MasterCommunicator) Connect(ctx context.Context) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.closed {
        return fmt.Errorf("communicator is closed")
    }
    
    // 创建连接选项
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
            Time:    c.config.KeepAliveTime,
            Timeout: c.config.KeepAliveTimeout,
            PermitWithoutStream: true,
        }),
        
        // 压缩
        grpc.WithDefaultCallOptions(
            grpc.UseCompressor(gzip.Name),
            grpc.MaxCallRecvMsgSize(100*1024*1024),
            grpc.MaxCallSendMsgSize(100*1024*1024),
        ),
        
        // 缓冲
        grpc.WithReadBufferSize(c.config.RecvBufferSize),
        grpc.WithWriteBufferSize(c.config.SendBufferSize),
        
        // 认证
        grpc.WithPerRPCCredentials(&tokenAuth{token: c.token}),
    }
    
    // 带重试的连接
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
        log.Printf("Connected to master %s", c.addr)
        return nil
    }
    
    return lastErr
}

// StartStream 启动命令流
func (c *MasterCommunicator) StartStream(ctx context.Context) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.conn == nil {
        return fmt.Errorf("not connected to master")
    }
    
    // 创建流
    stream, err := pb.NewAgentServiceClient(c.conn).ExecuteCommand(
        metadata.NewOutgoingContext(ctx, metadata.Pairs(
            "node_id", c.nodeID,
            "authorization", "Bearer "+c.token,
        )),
        &pb.CommandRequest{NodeId: c.nodeID},
    )
    if err != nil {
        return fmt.Errorf("failed to start command stream: %w", err)
    }
    
    c.stream = stream
    return nil
}

// Register 注册节点
func (c *MasterCommunicator) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
    if c.conn == nil {
        return nil, fmt.Errorf("not connected to master")
    }
    
    // 添加认证
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
    
    return pb.NewAgentServiceClient(c.conn).Register(ctx, req)
}

// Heartbeat 发送心跳
func (c *MasterCommunicator) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
    if c.conn == nil {
        return nil, fmt.Errorf("not connected to master")
    }
    
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
    
    return pb.NewAgentServiceClient(c.conn).Heartbeat(ctx, req)
}

// PushConfig 推送配置
func (c *MasterCommunicator) PushConfig(ctx context.Context, req *pb.PushConfigRequest) (*pb.PushConfigResponse, error) {
    if c.conn == nil {
        return nil, fmt.Errorf("not connected to master")
    }
    
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
    
    return pb.NewAgentServiceClient(c.conn).PushConfig(ctx, req)
}

// ReportStatus 上报状态
func (c *MasterCommunicator) ReportStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
    if c.conn == nil {
        return nil, fmt.Errorf("not connected to master")
    }
    
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
    
    return pb.NewAgentServiceClient(c.conn).ReportStatus(ctx, req)
}

// ReceiveCommand 从流接收命令
func (c *MasterCommunicator) ReceiveCommand() (*pb.CommandRequest, error) {
    c.mu.RLock()
    stream := c.stream
    c.mu.RUnlock()
    
    if stream == nil {
        return nil, fmt.Errorf("stream not started")
    }
    
    return stream.Recv()
}

// SendCommandResult 发送命令结果
func (c *MasterCommunicator) SendCommandResult(resp *pb.CommandResponse) error {
    c.mu.RLock()
    stream := c.stream
    c.mu.RUnlock()
    
    if stream == nil {
        return fmt.Errorf("stream not started")
    }
    
    return stream.SendMsg(resp)
}

// Close 关闭连接
func (c *MasterCommunicator) Close() error {
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

// HeartbeatSender 心跳发送器
type HeartbeatSender struct {
    client   *MasterCommunicator
    interval time.Duration
    timeout  time.Duration
    stopCh   chan struct{}
    wg       sync.WaitGroup
}

// NewHeartbeatSender 创建心跳发送器
func NewHeartbeatSender(client *MasterCommunicator, interval, timeout time.Duration) *HeartbeatSender {
    return &HeartbeatSender{
        client:   client,
        interval: interval,
        timeout:  timeout,
        stopCh:   make(chan struct{}),
    }
}

// Start 启动心跳
func (h *HeartbeatSender) Start() {
    h.wg.Add(1)
    go h.run()
}

// Stop 停止心跳
func (h *HeartbeatSender) Stop() {
    close(h.stopCh)
    h.wg.Wait()
}

func (h *HeartbeatSender) run() {
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
            })
            cancel()
            
            if err != nil {
                log.Printf("Heartbeat failed: %v", err)
            }
        }
    }
}

// StatusReporter 状态上报器
type StatusReporter struct {
    client    *MasterCommunicator
    interval  time.Duration
    stopCh    chan struct{}
    wg        sync.WaitGroup
    collector StatusCollector
}

// StatusCollector 状态收集器接口
type StatusCollector interface {
    Collect() *pb.StatusData
}

// NewStatusReporter 创建状态上报器
func NewStatusReporter(client *MasterCommunicator, interval time.Duration, collector StatusCollector) *StatusReporter {
    return &StatusReporter{
        client:    client,
        interval:  interval,
        stopCh:    make(chan struct{}),
        collector: collector,
    }
}

// Start 启动状态上报
func (r *StatusReporter) Start() {
    r.wg.Add(1)
    go r.run()
}

// Stop 停止状态上报
func (r *StatusReporter) Stop() {
    close(r.stopCh)
    r.wg.Wait()
}

func (r *StatusReporter) run() {
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
                log.Printf("Status report failed: %v", err)
            }
        }
    }
}

// tokenAuth token认证
type tokenAuth struct {
    token string
}

func (t *tokenAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
    return map[string]string{
        "authorization": "Bearer " + t.token,
    }, nil
}

func (t *tokenAuth) RequireTransportSecurity() bool {
    return true
}

// ReconnectManager 重连管理器
type ReconnectManager struct {
    client      *MasterCommunicator
    maxRetries  int
    baseDelay   time.Duration
    maxDelay    time.Duration
    jitter      float64
    stopCh      chan struct{}
    wg          sync.WaitGroup
}

// NewReconnectManager 创建重连管理器
func NewReconnectManager(client *MasterCommunicator, maxRetries int, baseDelay, maxDelay time.Duration) *ReconnectManager {
    return &ReconnectManager{
        client:     client,
        maxRetries: maxRetries,
        baseDelay:  baseDelay,
        maxDelay:   maxDelay,
        jitter:     0.3,
        stopCh:     make(chan struct{}),
    }
}

// Start 启动重连管理
func (m *ReconnectManager) Start() {
    m.wg.Add(1)
    go m.run()
}

// Stop 停止重连管理
func (m *ReconnectManager) Stop() {
    close(m.stopCh)
    m.wg.Wait()
}

func (m *ReconnectManager) run() {
    defer m.wg.Done()
    
    for {
        select {
        case <-m.stopCh:
            return
        default:
            // 检查连接状态
            if m.client.conn == nil || m.client.conn.GetState() != connectivity.Ready {
                m.reconnect()
            }
            time.Sleep(5 * time.Second)
        }
    }
}

func (m *ReconnectManager) reconnect() {
    var lastErr error
    
    for attempt := 0; attempt <= m.maxRetries; attempt++ {
        if attempt > 0 {
            delay := m.calculateDelay(attempt)
            log.Printf("Reconnecting to master (attempt %d/%d) after %v", attempt, m.maxRetries, delay)
            time.Sleep(delay)
        }
        
        ctx, cancel := context.WithTimeout(context.Background(), m.client.config.DialTimeout)
        err := m.client.Connect(ctx)
        cancel()
        
        if err != nil {
            lastErr = err
            continue
        }
        
        // 启动命令流
        ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
        err = m.client.StartStream(ctx)
        cancel()
        
        if err != nil {
            lastErr = err
            continue
        }
        
        log.Println("Reconnected to master successfully")
        return
    }
    
    log.Printf("Failed to reconnect after %d attempts: %v", m.maxRetries, lastErr)
}

func (m *ReconnectManager) calculateDelay(attempt int) time.Duration {
    delay := float64(m.baseDelay) * float64(attempt)
    if delay > float64(m.maxDelay) {
        delay = float64(m.maxDelay)
    }
    
    // 添加随机抖动
    jitter := delay * m.jitter
    delay += (jitter * 2 * float64(attempt%2) - jitter)
    
    return time.Duration(delay)
}

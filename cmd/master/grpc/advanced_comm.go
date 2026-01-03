package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/ai-cdn-tunnel/proto/master"
)

// MasterAgentClient 主控与被控通信客户端
type MasterAgentClient struct {
	config      *MasterAgentConfig
	connections map[string]*AgentConnection
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// AgentConfig 被控配置
type AgentConfig struct {
	// 被控ID
	AgentID string `json:"agent_id"`

	// 被控名称
	Name string `json:"name"`

	// 被控地址
	Addr string `json:"addr"`

	// 端口
	Port int `json:"port"`

	// 区域
	Region string `json:"region"`

	// 认证令牌
	Token string `json:"token"`

	// 启用状态
	Enabled bool `json:"enabled"`

	// 配置版本
	ConfigVersion int64 `json:"config_version"`

	// 最后同步时间
	LastSync time.Time `json:"last_sync"`
}

// AgentConnection 被控连接
type AgentConnection struct {
	AgentID   string
	Addr      string
	Port      int
	Conn      *grpc.ClientConn
	Client    pb.AgentServiceClient
	Stream    pb.AgentService_CommandStreamClient
	Status    string
	LastSeen  time.Time
	mu        sync.RWMutex
}

// MasterAgentConfig 主控通信配置
type MasterAgentConfig struct {
	// 监听地址
	ListenAddr string `json:"listen_addr"`

	// gRPC端口
	GRPCPort int `json:"grpc_port"`

	// 心跳间隔
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 最大重试次数
	MaxRetries int `json:"max_retries"`

	// 重试间隔
	RetryInterval time.Duration `json:"retry_interval"`

	// 启用TLS
	EnableTLS bool `json:"enable_tls"`

	// 证书配置
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

// SyncConfig 同步配置
type SyncConfig struct {
	// 同步间隔
	Interval time.Duration `json:"interval"`

	// 同步类型
	Types []string `json:"types"` // "security", "cache", "loadbalance", "port", "stats"

	// 增量同步
	Incremental bool `json:"incremental"`

	// 压缩传输
	Compress bool `json:"compress"`
}

// AdvancedSyncManager 高级同步管理器
type AdvancedSyncManager struct {
	config      *SyncConfig
	master      *MasterAgentClient
	agents      map[string]*AgentConfig
	pendingOps  map[string]*PendingOp
	syncStats   *SyncStats
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// PendingOp 待处理操作
type PendingOp struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	OpType    string    `json:"op_type"` // "sync", "restart", "upgrade"
	Config    []byte    `json:"config"`
	Status    string    `json:"status"` // "pending", "sent", "acknowledged", "failed"
	Retries   int       `json:"retries"`
	CreatedAt time.Time `json:"created_at"`
	SentAt    *time.Time `json:"sent_at"`
}

// SyncStats 同步统计
type SyncStats struct {
	TotalSyncs       int64            `json:"total_syncs"`
	SuccessfulSyncs  int64            `json:"successful_syncs"`
	FailedSyncs      int64            `json:"failed_syncs"`
	PendingSyncs     int64            `json:"pending_syncs"`
	AvgSyncTime      time.Duration    `json:"avg_sync_time"`
	ByAgent          map[string]*AgentSyncStats `json:"by_agent"`
	ByConfigType     map[string]int64 `json:"by_config_type"`
	mu               sync.RWMutex
}

// AgentSyncStats 节点同步统计
type AgentSyncStats struct {
	AgentID       string        `json:"agent_id"`
	Name          string        `json:"name"`
	TotalSyncs    int64         `json:"total_syncs"`
	SuccessCount  int64         `json:"success_count"`
	FailCount     int64         `json:"fail_count"`
	LastSync      time.Time     `json:"last_sync"`
	LastSuccess   time.Time     `json:"last_success"`
	LastFail      time.Time     `json:"last_fail"`
	AvgSyncTime   time.Duration `json:"avg_sync_time"`
}

// NewMasterAgentClient 创建主控通信客户端
func NewMasterAgentClient(cfg *MasterAgentConfig) *MasterAgentClient {
	ctx, cancel := context.WithCancel(context.Background())

	return &MasterAgentClient{
		config:      cfg,
		connections: make(map[string]*AgentConnection),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Connect 连接到被控
func (c *MasterAgentClient) Connect(agent *AgentConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", agent.Addr, agent.Port)

	// 创建gRPC连接（使用TLS）
	conn, err := grpc.Dial(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		})),
		grpc.WithUnaryInterceptor(c.authInterceptor(agent.Token)),
		grpc.WithStreamInterceptor(c.authStreamInterceptor(agent.Token)),
	)

	if err != nil {
		return fmt.Errorf("连接被控失败 %s: %v", agent.AgentID, err)
	}

	connection := &AgentConnection{
		AgentID: agent.AgentID,
		Addr:    agent.Addr,
		Port:    agent.Port,
		Conn:    conn,
		Client:  pb.NewAgentServiceClient(conn),
		Status:  "connected",
		LastSeen: time.Now(),
	}

	c.connections[agent.AgentID] = connection

	return nil
}

// authInterceptor 认证拦截器
func (c *MasterAgentClient) authInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// authStreamInterceptor 流认证拦截器
func (c *MasterAgentClient) authStreamInterceptor(token string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// Disconnect 断开连接
func (c *MasterAgentClient) Disconnect(agentID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, exists := c.connections[agentID]
	if !exists {
		return fmt.Errorf("连接不存在: %s", agentID)
	}

	conn.Conn.Close()
	delete(c.connections, agentID)

	return nil
}

// SendConfig 发送配置到被控
func (c *MasterAgentClient) SendConfig(agentID string, configType string, configData []byte) error {
	c.mu.RLock()
	conn, exists := c.connections[agentID]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("被控未连接: %s", agentID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := conn.Client.UpdateConfig(ctx, &pb.UpdateConfigRequest{
		AgentId:    agentID,
		ConfigType: configType,
		ConfigData: configData,
		Version:    time.Now().UnixNano(),
	})

	if err != nil {
		return fmt.Errorf("发送配置失败: %v", err)
	}

	return nil
}

// SendCommand 发送命令到被控
func (c *MasterAgentClient) SendCommand(agentID string, command string, params map[string]string) error {
	c.mu.RLock()
	conn, exists := c.connections[agentID]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("被控未连接: %s", agentID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := conn.Client.ExecuteCommand(ctx, &pb.CommandRequest{
		AgentId:  agentID,
		Command:  command,
		Params:   params,
	})

	if err != nil {
		return fmt.Errorf("发送命令失败: %v", err)
	}

	return nil
}

// GetAgentStatus 获取被控状态
func (c *MasterAgentClient) GetAgentStatus(agentID string) (*AgentStatus, error) {
	c.mu.RLock()
	conn, exists := c.connections[agentID]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("被控未连接: %s", agentID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := conn.Client.GetStatus(ctx, &pb.StatusRequest{
		AgentId: agentID,
	})

	if err != nil {
		return nil, fmt.Errorf("获取状态失败: %v", err)
	}

	return &AgentStatus{
		AgentID:      agentID,
		Status:       resp.Status,
		Uptime:       time.Duration(resp.Uptime),
		CPUUsage:     resp.CpuUsage,
		MemoryUsage:  resp.MemoryUsage,
		BandwidthIn:  resp.BandwidthIn,
		BandwidthOut: resp.BandwidthOut,
		QPS:          resp.Qps,
		Connections:  resp.Connections,
	}, nil
}

// BroadcastConfig 广播配置到所有被控
func (c *MasterAgentClient) BroadcastConfig(configType string, configData []byte) map[string]error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	results := make(map[string]error)

	for agentID, conn := range c.connections {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := conn.Client.UpdateConfig(ctx, &pb.UpdateConfigRequest{
			AgentId:    agentID,
			ConfigType: configType,
			ConfigData: configData,
			Version:    time.Now().UnixNano(),
		})
		cancel()

		if err != nil {
			results[agentID] = err
		} else {
			results[agentID] = nil
		}
	}

	return results
}

// GetConnectedAgents 获取已连接的被控列表
func (c *MasterAgentClient) GetConnectedAgents() []*AgentConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	agents := make([]*AgentConfig, 0)
	for agentID := range c.connections {
		agents = append(agents, &AgentConfig{
			AgentID: agentID,
		})
	}

	return agents
}

// AgentStatus 被控状态
type AgentStatus struct {
	AgentID      string    `json:"agent_id"`
	Status       string    `json:"status"`
	Uptime       time.Duration `json:"uptime"`
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  float64   `json:"memory_usage"`
	BandwidthIn  float64   `json:"bandwidth_in"`
	BandwidthOut float64   `json:"bandwidth_out"`
	QPS          float64   `json:"qps"`
	Connections  int64     `json:"connections"`
}

// NewAdvancedSyncManager 创建高级同步管理器
func NewAdvancedSyncManager(config *SyncConfig, master *MasterAgentClient) *AdvancedSyncManager {
	if config == nil {
		config = &SyncConfig{
			Interval:    60 * time.Second,
			Incremental: true,
			Compress:    true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AdvancedSyncManager{
		config:     config,
		master:     master,
		agents:     make(map[string]*AgentConfig),
		pendingOps: make(map[string]*PendingOp),
		syncStats: &SyncStats{
			ByAgent:    make(map[string]*AgentSyncStats),
			ByConfigType: make(map[string]int64),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动同步管理器
func (m *AdvancedSyncManager) Start() error {
	// 启动同步协程
	go m.runSync()

	// 启动清理协程
	go m.runCleanup()

	return nil
}

// runSync 运行同步
func (m *AdvancedSyncManager) runSync() {
	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.syncAll()
		}
	}
}

// syncAll 同步所有配置
func (m *AdvancedSyncManager) syncAll() {
	m.mu.RLock()
	agents := make([]*AgentConfig, 0)
	for _, agent := range m.agents {
		agents = append(agents, agent)
	}
	m.mu.RUnlock()

	for _, agent := range agents {
		if !agent.Enabled {
			continue
		}

		// 同步各种配置
		for _, configType := range m.config.Types {
			m.syncConfig(agent.AgentID, configType)
		}
	}
}

// syncConfig 同步配置
func (m *AdvancedSyncManager) syncConfig(agentID string, configType string) {
	// 创建待处理操作
	op := &PendingOp{
		ID:        fmt.Sprintf("op_%d", time.Now().UnixNano()),
		AgentID:   agentID,
		OpType:    "sync",
		Config:    []byte(fmt.Sprintf(`{"type":"%s","version":%d}`, configType, time.Now().UnixNano())),
		Status:    "pending",
		Retries:   0,
		CreatedAt: time.Now(),
	}

	m.mu.Lock()
	m.pendingOps[op.ID] = op
	m.mu.Unlock()

	// 发送配置
	err := m.master.SendConfig(agentID, configType, op.Config)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		op.Status = "failed"
		op.Retries++
		m.syncStats.FailedSyncs++
		m.syncStats.ByConfigType[configType]++

		// 重试
		if op.Retries < m.master.config.MaxRetries {
			op.Status = "pending"
		}
	} else {
		op.Status = "acknowledged"
		op.SentAt = new(time.Time)
		*op.SentAt = time.Now()
		m.syncStats.SuccessfulSyncs++
		m.syncStats.ByConfigType[configType]++

		// 更新节点统计
		if stats, ok := m.syncStats.ByAgent[agentID]; ok {
			stats.TotalSyncs++
			stats.SuccessCount++
			stats.LastSuccess = time.Now()
		}
	}
}

// runCleanup 运行清理
func (m *AdvancedSyncManager) runCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup 清理过期操作
func (m *AdvancedSyncManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, op := range m.pendingOps {
		// 清理超过1小时的操作
		if now.Sub(op.CreatedAt) > time.Hour {
			delete(m.pendingOps, id)
		}
	}
}

// GetSyncStats 获取同步统计
func (m *AdvancedSyncManager) GetSyncStats() *SyncStats {
	m.syncStats.mu.RLock()
	defer m.syncStats.mu.RUnlock()

	return m.syncStats
}

// GetPendingOps 获取待处理操作
func (m *AdvancedSyncManager) GetPendingOps() []*PendingOp {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ops := make([]*PendingOp, 0)
	for _, op := range m.pendingOps {
		ops = append(ops, op)
	}

	return ops
}

// RetryFailedOp 重试失败的操作
func (m *AdvancedSyncManager) RetryFailedOp(opID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	op, exists := m.pendingOps[opID]
	if !exists {
		return fmt.Errorf("操作不存在: %s", opID)
	}

	if op.Status != "failed" {
		return fmt.Errorf("只能重试失败的操作")
	}

	op.Status = "pending"
	op.Retries = 0

	return nil
}

// AddAgent 添加被控
func (m *AdvancedSyncManager) AddAgent(agent *AgentConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.agents[agent.AgentID]; exists {
		return fmt.Errorf("被控已存在: %s", agent.AgentID)
	}

	m.agents[agent.AgentID] = agent

	// 初始化同步统计
	m.syncStats.ByAgent[agent.AgentID] = &AgentSyncStats{
		AgentID: agent.AgentID,
		Name:    agent.Name,
	}

	return nil
}

// RemoveAgent 移除被控
func (m *AdvancedSyncManager) RemoveAgent(agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.agents[agentID]; !exists {
		return fmt.Errorf("被控不存在: %s", agentID)
	}

	delete(m.agents, agentID)
	delete(m.syncStats.ByAgent, agentID)

	return nil
}

// GetAgents 获取所有被控
func (m *AdvancedSyncManager) GetAgents() []*AgentConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agents := make([]*AgentConfig, 0)
	for _, agent := range m.agents {
		agents = append(agents, agent)
	}

	return agents
}

// UpdateAgentConfig 更新被控配置
func (m *AdvancedSyncManager) UpdateAgentConfig(agentID string, config *AgentConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	agent, exists := m.agents[agentID]
	if !exists {
		return fmt.Errorf("被控不存在: %s", agentID)
	}

	agent.Name = config.Name
	agent.Addr = config.Addr
	agent.Port = config.Port
	agent.Region = config.Region
	agent.Enabled = config.Enabled

	return nil
}

// ForceSync 强制同步
func (m *AdvancedSyncManager) ForceSync(agentID string, configType string) error {
	m.mu.RLock()
	_, exists := m.agents[agentID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("被控不存在: %s", agentID)
	}

	// 立即同步
	m.syncConfig(agentID, configType)

	return nil
}

// Stop 停止同步管理器
func (m *AdvancedSyncManager) Stop() {
	m.cancel()
}

package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/ai-cdn-tunnel/proto/agent"
)

// HealthChecker 健康检查器
type HealthChecker struct {
	config       *HealthConfig
	grpcPool     *GRPCConnectionPool
	nodeMgr      interface{ GetNode(id string) *Node }
	checkResults map[string]*CheckResult
	nodeStatus   map[string]*NodeStatusDetail
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// HealthConfig 健康检查配置
type HealthConfig struct {
	// 检查间隔
	CheckInterval time.Duration

	// 超时时间
	Timeout time.Duration

	// 不健康阈值
	UnhealthyThreshold int

	// 健康阈值
	HealthyThreshold int

	// 检查类型
	CheckTypes []CheckType

	// gRPC连接配置
	GRPCMaxConns int
	GRPCMaxIdle  time.Duration

	// TLS配置
	TLSCert      tls.Certificate
	CACertPool   *x509.CertPool
	SkipTLSCheck bool
}

// NodeStatusDetail 节点状态详情
type NodeStatusDetail struct {
	NodeID               string
	Status               string
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	LastCheck            time.Time
	TotalChecks          int
	TotalFailures        int
	TotalSuccesses       int
}

// CheckType 健康检查类型
type CheckType string

const (
	CheckTypeTCP   CheckType = "tcp"
	CheckTypeHTTP  CheckType = "http"
	CheckTypeGRPC  CheckType = "grpc"
	CheckTypeAgent CheckType = "agent"
)

// CheckResult 健康检查结果
type CheckResult struct {
	NodeID      string
	CheckType   CheckType
	Status      HealthStatus
	Latency     time.Duration
	Message     string
	LastChecked time.Time
	RetryCount  int
}

// HealthStatus 健康状态
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
	HealthStatusChecking  HealthStatus = "checking"
)

// Node 节点信息
type Node struct {
	ID        string
	Addr      string
	Port      int
	Region    string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DefaultConfig 默认配置
func DefaultConfig() *HealthConfig {
	return &HealthConfig{
		CheckInterval:     10 * time.Second,
		Timeout:           5 * time.Second,
		UnhealthyThreshold: 3,
		HealthyThreshold:  2,
		CheckTypes:        []CheckType{CheckTypeTCP, CheckTypeGRPC},
		GRPCMaxConns:      100,
		GRPCMaxIdle:       5 * time.Minute,
		SkipTLSCheck:      false,
	}
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker(cfg *HealthConfig, nodeMgr interface{ GetNode(id string) *Node }) *HealthChecker {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &HealthChecker{
		config:       cfg,
		grpcPool:     NewGRPCConnectionPool(cfg),
		nodeMgr:      nodeMgr,
		checkResults: make(map[string]*CheckResult),
		nodeStatus:   make(map[string]*NodeStatusDetail),
		stopCh:       make(chan struct{}),
	}
}

// GRPCConnectionPool gRPC连接池
type GRPCConnectionPool struct {
	config  *HealthConfig
	conns   map[string]*grpc.ClientConn
	mu      sync.RWMutex
	created map[string]time.Time
}

// NewGRPCConnectionPool 创建gRPC连接池
func NewGRPCConnectionPool(config *HealthConfig) *GRPCConnectionPool {
	return &GRPCConnectionPool{
		config:  config,
		conns:   make(map[string]*grpc.ClientConn),
		created: make(map[string]time.Time),
	}
}

// Get 获取连接
func (p *GRPCConnectionPool) Get(addr string) (*grpc.ClientConn, error) {
	p.mu.RLock()
	conn, ok := p.conns[addr]
	p.mu.RUnlock()

	if ok {
		return conn, nil
	}

	// 创建安全的gRPC连接
	var opts []grpc.DialOption

	// TLS配置
	if p.config.SkipTLSCheck {
		opts = append(opts, grpc.WithInsecure())
	} else if p.config.TLSCert.Certificate != nil {
		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{p.config.TLSCert},
			RootCAs:      p.config.CACertPool,
		})
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		// 默认使用安全连接
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(p.config.CACertPool, "")))
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 双重检查
	if existing, ok := p.conns[addr]; ok {
		conn.Close()
		return existing, nil
	}

	if len(p.conns) >= p.config.GRPCMaxConns {
		// 关闭最旧的连接
		p.cleanOldest()
	}

	p.conns[addr] = conn
	p.created[addr] = time.Now()

	return conn, nil
}

// cleanOldest 清理最旧的连接
func (p *GRPCConnectionPool) cleanOldest() {
	var oldestAddr string
	var oldestTime time.Time

	for addr, created := range p.created {
		if oldestTime.IsZero() || created.Before(oldestTime) {
			oldestAddr = addr
			oldestTime = created
		}
	}

	if oldestAddr != "" {
		if conn := p.conns[oldestAddr]; conn != nil {
			conn.Close()
		}
		delete(p.conns, oldestAddr)
		delete(p.created, oldestAddr)
	}
}

// Close 关闭所有连接
func (p *GRPCConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conn := range p.conns {
		conn.Close()
		delete(p.conns, addr)
		delete(p.created, addr)
	}
}

// Start 启动健康检查
func (h *HealthChecker) Start() {
	h.wg.Add(1)
	go h.runChecker()

	log.Printf("Health checker started with interval: %v", h.config.CheckInterval)
}

// Stop 停止健康检查
func (h *HealthChecker) Stop() {
	close(h.stopCh)
	h.wg.Wait()
	h.grpcPool.Close()

	log.Println("Health checker stopped")
}

// runChecker 运行检查器
func (h *HealthChecker) runChecker() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.checkAllNodes()
		}
	}
}

// checkAllNodes 检查所有节点
func (h *HealthChecker) checkAllNodes() {
	// 获取所有节点（从nodeMgr）
	nodes := h.getAllNodes()

	for _, node := range nodes {
		go h.checkNode(node)
	}
}

// getAllNodes 获取所有节点
func (h *HealthChecker) getAllNodes() []*Node {
	if h.nodeMgr != nil {
		// 使用反射获取节点列表
		if nodes, ok := h.nodeMgr.(interface{ GetAllNodes() []*Node }); ok {
			return nodes.GetAllNodes()
		}
	}
	return nil
}

// checkNode 检查单个节点
func (h *HealthChecker) checkNode(node *Node) {
	for _, checkType := range h.config.CheckTypes {
		result := h.performCheck(node, checkType)
		h.updateCheckResult(result)

		// 根据结果更新节点状态
		h.updateNodeStatus(node.ID, result)
	}
}

// performCheck 执行检查
func (h *HealthChecker) performCheck(node *Node, checkType CheckType) *CheckResult {
	result := &CheckResult{
		NodeID:      node.ID,
		CheckType:   checkType,
		Status:      HealthStatusUnknown,
		LastChecked: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
	defer cancel()

	switch checkType {
	case CheckTypeTCP:
		result = h.checkTCP(ctx, node, result)
	case CheckTypeGRPC:
		result = h.checkGRPC(ctx, node, result)
	case CheckTypeAgent:
		result = h.checkAgent(ctx, node, result)
	}

	return result
}

// checkTCP TCP检查
func (h *HealthChecker) checkTCP(ctx context.Context, node *Node, result *CheckResult) *CheckResult {
	start := time.Now()

	addr := node.Addr
	port := node.Port

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("TCP connection failed: %v", err)
	} else {
		conn.Close()
		result.Status = HealthStatusHealthy
		result.Message = "TCP connection successful"
	}

	result.Latency = time.Since(start)
	return result
}

// checkGRPC gRPC检查
func (h *HealthChecker) checkGRPC(ctx context.Context, node *Node, result *CheckResult) *CheckResult {
	start := time.Now()

	addr := fmt.Sprintf("%s:%d", node.Addr, node.Port)

	conn, err := h.grpcPool.Get(addr)
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("gRPC connection failed: %v", err)
		result.Latency = time.Since(start)
		return result
	}

	client := pb.NewAgentServiceClient(conn)

	// 发送健康检查请求
	resp, err := client.GetStatus(ctx, &pb.StatusRequest{
		AgentId: node.ID,
	})

	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("gRPC health check failed: %v", err)
		result.RetryCount++
	} else {
		result.Status = HealthStatusHealthy
		result.Message = fmt.Sprintf("gRPC health check successful, status: %s", resp.Status)
	}

	result.Latency = time.Since(start)
	return result
}

// checkAgent Agent状态检查
func (h *HealthChecker) checkAgent(ctx context.Context, node *Node, result *CheckResult) *CheckResult {
	start := time.Now()

	addr := fmt.Sprintf("%s:%d", node.Addr, node.Port)

	conn, err := h.grpcPool.Get(addr)
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("Agent connection failed: %v", err)
		result.Latency = time.Since(start)
		return result
	}

	client := pb.NewAgentServiceClient(conn)

	// 发送心跳请求检查Agent状态
	hbResp, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{
		NodeId:    node.ID,
		Timestamp: time.Now().Unix(),
		Status:    "checking",
	})

	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("Agent heartbeat failed: %v", err)
		result.RetryCount++
	} else {
		result.Status = HealthStatusHealthy
		result.Message = fmt.Sprintf("Agent heartbeat successful, status: %s", hbResp.Status)
	}

	result.Latency = time.Since(start)
	return result
}

// updateCheckResult 更新检查结果
func (h *HealthChecker) updateCheckResult(result *CheckResult) {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := fmt.Sprintf("%s:%s", result.NodeID, result.CheckType)
	h.checkResults[key] = result
}

// updateNodeStatus 更新节点状态
func (h *HealthChecker) updateNodeStatus(nodeID string, result *CheckResult) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 获取或创建节点状态详情
	statusDetail, exists := h.nodeStatus[nodeID]
	if !exists {
		statusDetail = &NodeStatusDetail{
			NodeID: nodeID,
			Status: "unknown",
		}
		h.nodeStatus[nodeID] = statusDetail
	}

	statusDetail.LastCheck = time.Now()
	statusDetail.TotalChecks++

	// 根据检查结果更新连续成功/失败计数
	if result.Status == HealthStatusHealthy {
		statusDetail.ConsecutiveSuccesses++
		statusDetail.ConsecutiveFailures = 0
		statusDetail.TotalSuccesses++
	} else {
		statusDetail.ConsecutiveFailures++
		statusDetail.ConsecutiveSuccesses = 0
		statusDetail.TotalFailures++
	}

	// 根据阈值判断节点状态
	if statusDetail.ConsecutiveFailures >= h.config.UnhealthyThreshold {
		statusDetail.Status = "offline"
		log.Printf("Node %s marked as offline (consecutive failures: %d)", nodeID, statusDetail.ConsecutiveFailures)
	} else if statusDetail.ConsecutiveSuccesses >= h.config.HealthyThreshold {
		statusDetail.Status = "online"
		if statusDetail.ConsecutiveSuccesses == h.config.HealthyThreshold {
			log.Printf("Node %s marked as online", nodeID)
		}
	}
}

// GetCheckResult 获取检查结果
func (h *HealthChecker) GetCheckResult(nodeID string) []*CheckResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var results []*CheckResult
	for _, result := range h.checkResults {
		if result.NodeID == nodeID {
			results = append(results, result)
		}
	}

	return results
}

// GetAllCheckResults 获取所有检查结果
func (h *HealthChecker) GetAllCheckResults() map[string]*CheckResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// 返回副本
	results := make(map[string]*CheckResult)
	for k, v := range h.checkResults {
		results[k] = v
	}
	return results
}

// GetNodeStatus 获取节点状态详情
func (h *HealthChecker) GetNodeStatus(nodeID string) *NodeStatusDetail {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.nodeStatus[nodeID]
}

// GetAllNodeStatus 获取所有节点状态
func (h *HealthChecker) GetAllNodeStatus() map[string]*NodeStatusDetail {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// 返回副本
	status := make(map[string]*NodeStatusDetail)
	for k, v := range h.nodeStatus {
		status[k] = v
	}
	return status
}

// IsNodeHealthy 判断节点是否健康
func (h *HealthChecker) IsNodeHealthy(nodeID string) bool {
	results := h.GetCheckResult(nodeID)

	healthyCount := 0
	unhealthyCount := 0

	for _, result := range results {
		if result.Status == HealthStatusHealthy {
			healthyCount++
		} else if result.Status == HealthStatusUnhealthy {
			unhealthyCount++
		}
	}

	// 根据阈值判断
	if unhealthyCount >= h.config.UnhealthyThreshold {
		return false
	}

	if healthyCount >= h.config.HealthyThreshold {
		return true
	}

	return false
}

// GetHealthyNodes 获取健康节点列表
func (h *HealthChecker) GetHealthyNodes() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var healthyNodes []string
	for nodeID, status := range h.nodeStatus {
		if status.Status == "online" {
			healthyNodes = append(healthyNodes, nodeID)
		}
	}

	return healthyNodes
}

// GetUnhealthyNodes 获取不健康节点列表
func (h *HealthChecker) GetUnhealthyNodes() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var unhealthyNodes []string
	for nodeID, status := range h.nodeStatus {
		if status.Status == "offline" {
			unhealthyNodes = append(unhealthyNodes, nodeID)
		}
	}

	return unhealthyNodes
}

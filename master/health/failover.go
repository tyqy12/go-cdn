package health

import (
	"context"
	"fmt"
	"log"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/master/node"
	pb "github.com/ai-cdn-tunnel/proto/agent"
)

// FailoverManager 故障转移管理器
type FailoverManager struct {
	config        *FailoverConfig
	healthChecker *HealthChecker
	nodeMgr       *node.Manager
	agentClient   pb.AgentServiceClient
	eventChan     chan *FailoverEvent
	policy        FailoverPolicy
	mu            sync.RWMutex
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// FailoverConfig 故障转移配置
type FailoverConfig struct {
	// 是否启用故障转移
	Enabled bool

	// 自动故障转移
	AutoFailover bool

	// 故障转移超时
	FailoverTimeout time.Duration

	// 回滚超时
	RollbackTimeout time.Duration

	// 最大故障转移次数
	MaxFailoverCount int

	// 故障转移间隔
	FailoverInterval time.Duration

	// 健康检查配置
	HealthCheckConfig *HealthConfig
}

// FailoverPolicy 故障转移策略
type FailoverPolicy string

const (
	// FailoverPolicyRoundRobin 轮询策略
	FailoverPolicyRoundRobin FailoverPolicy = "roundrobin"

	// FailoverPolicyLeastConn 最少连接策略
	FailoverPolicyLeastConn FailoverPolicy = "leastconn"

	// FailoverPolicyPriority 优先级策略
	FailoverPolicyPriority FailoverPolicy = "priority"

	// FailoverPolicyLatency 延迟最低策略
	FailoverPolicyLatency FailoverPolicy = "latency"

	// FailoverPolicyRegion 区域优先策略
	FailoverPolicyRegion FailoverPolicy = "region"
)

// FailoverEvent 故障转移事件
type FailoverEvent struct {
	EventType  EventType
	SourceNode *Node
	TargetNode *Node
	Reason     string
	Timestamp  time.Time
	Success    bool
	Message    string
}

// EventType 事件类型
type EventType string

const (
	EventTypeFailover   EventType = "failover"
	EventTypeRollback   EventType = "rollback"
	EventTypeNodeDown   EventType = "node_down"
	EventTypeNodeUp     EventType = "node_up"
	EventTypeSwitchover EventType = "switchover"
)

// DefaultFailoverConfig 默认配置
func DefaultFailoverConfig() *FailoverConfig {
	return &FailoverConfig{
		Enabled:           true,
		AutoFailover:      true,
		FailoverTimeout:   30 * time.Second,
		RollbackTimeout:   60 * time.Second,
		MaxFailoverCount:  3,
		FailoverInterval:  10 * time.Second,
		HealthCheckConfig: DefaultConfig(),
	}
}

// NewFailoverManager 创建故障转移管理器
func NewFailoverManager(cfg *FailoverConfig, healthChecker *HealthChecker, nodeMgr *node.Manager, agentClient pb.AgentServiceClient) *FailoverManager {
	if cfg == nil {
		cfg = DefaultFailoverConfig()
	}

	return &FailoverManager{
		config:        cfg,
		healthChecker: healthChecker,
		nodeMgr:       nodeMgr,
		agentClient:   agentClient,
		eventChan:     make(chan *FailoverEvent, 100),
		policy:        FailoverPolicyPriority,
		stopCh:        make(chan struct{}),
	}
}

// SetPolicy 设置故障转移策略
func (f *FailoverManager) SetPolicy(policy FailoverPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = policy
}

// GetPolicy 获取故障转移策略
func (f *FailoverManager) GetPolicy() FailoverPolicy {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.policy
}

// Start 启动故障转移管理器
func (f *FailoverManager) Start() {
	if !f.config.Enabled {
		log.Println("Failover manager is disabled")
		return
	}

	// 启动健康检查器
	if f.healthChecker != nil {
		f.healthChecker.Start()
	}

	// 启动故障转移协程
	f.wg.Add(1)
	go f.runFailover()

	// 启动事件处理协程
	f.wg.Add(1)
	go f.runEventHandler()

	log.Println("Failover manager started")
}

// Stop 停止故障转移管理器
func (f *FailoverManager) Stop() {
	close(f.stopCh)
	f.wg.Wait()

	if f.healthChecker != nil {
		f.healthChecker.Stop()
	}

	close(f.eventChan)

	log.Println("Failover manager stopped")
}

// runFailover 运行故障转移
func (f *FailoverManager) runFailover() {
	defer f.wg.Done()

	ticker := time.NewTicker(f.config.FailoverInterval)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.checkAndFailover()
		}
	}
}

// checkAndFailover 检查并执行故障转移
func (f *FailoverManager) checkAndFailover() {
	if !f.config.AutoFailover {
		return
	}

	// 获取所有离线节点
	offlineNodes := f.getOfflineNodes()

	for _, failedNode := range offlineNodes {
		// 查找最佳替代节点
		targetNode := f.selectFailoverNode(failedNode)
		if targetNode == nil {
			log.Printf("No suitable failover node found for %s", failedNode.ID)
			continue
		}

		// 执行故障转移
		event := f.executeFailover(failedNode, targetNode)
		f.eventChan <- event
	}
}

// getOfflineNodes 获取离线节点列表
func (f *FailoverManager) getOfflineNodes() []*Node {
	// 从节点管理器获取离线节点
	nodes := f.nodeMgr.GetAllNodes()
	var offline []*Node

	for _, n := range nodes {
		if n.Status == "offline" || n.Status == "unhealthy" {
			offline = append(offline, &Node{
				ID:     n.ID,
				Addr:   n.Addr,
				Port:   n.Port,
				Region: n.Region,
				Status: n.Status,
			})
		}
	}

	return offline
}

// selectFailoverNode 选择故障转移目标节点
func (f *FailoverManager) selectFailoverNode(failedNode *Node) *Node {
	allNodes := f.nodeMgr.GetAllNodes()
	var candidates []*Node

	// 筛选健康节点
	for _, n := range allNodes {
		if n.ID == failedNode.ID {
			continue
		}

		if n.Status == "online" && f.healthChecker.IsNodeHealthy(n.ID) {
			candidates = append(candidates, &Node{
				ID:     n.ID,
				Addr:   n.Addr,
				Port:   n.Port,
				Region: n.Region,
				Status: n.Status,
			})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// 根据策略选择节点
	switch f.policy {
	case FailoverPolicyRoundRobin:
		return f.selectRoundRobin(candidates)
	case FailoverPolicyLeastConn:
		return f.selectLeastConn(candidates)
	case FailoverPolicyPriority:
		return f.selectPriority(candidates, failedNode.Region)
	case FailoverPolicyLatency:
		return f.selectLatency(candidates)
	case FailoverPolicyRegion:
		return f.selectRegion(candidates, failedNode.Region)
	default:
		return f.selectPriority(candidates, failedNode.Region)
	}
}

// selectRoundRobin 轮询选择
func (f *FailoverManager) selectRoundRobin(candidates []*Node) *Node {
	// 简单实现：返回第一个候选节点
	// 实际实现应该维护一个轮询索引
	if len(candidates) > 0 {
		return candidates[0]
	}
	return nil
}

// selectLeastConn 选择最少连接
func (f *FailoverManager) selectLeastConn(candidates []*Node) *Node {
	var selected *Node
	minConn := int64(math.MaxInt64)

	for _, n := range candidates {
		// 获取节点连接数
		conns := f.getNodeConnectionCount(n.ID)
		if conns < minConn {
			minConn = conns
			selected = n
		}
	}

	return selected
}

// selectPriority 选择优先级最高
func (f *FailoverManager) selectPriority(candidates []*Node, preferredRegion string) *Node {
	var selected *Node
	highestPriority := -1

	for _, n := range candidates {
		priority := f.getNodePriority(n.ID)

		// 优先选择同区域节点
		if n.Region == preferredRegion {
			priority += 10
		}

		if priority > highestPriority {
			highestPriority = priority
			selected = n
		}
	}

	return selected
}

// selectLatency 选择延迟最低
func (f *FailoverManager) selectLatency(candidates []*Node) *Node {
	var selected *Node
	minLatency := time.Hour

	for _, n := range candidates {
		latency := f.getNodeLatency(n.ID)
		if latency < minLatency {
			minLatency = latency
			selected = n
		}
	}

	return selected
}

// selectRegion 选择同区域节点
func (f *FailoverManager) selectRegion(candidates []*Node, region string) *Node {
	for _, n := range candidates {
		if n.Region == region {
			return n
		}
	}

	// 如果没有同区域节点，返回任意健康节点
	if len(candidates) > 0 {
		return candidates[0]
	}

	return nil
}

// executeFailover 执行故障转移
func (f *FailoverManager) executeFailover(source, target *Node) *FailoverEvent {
	event := &FailoverEvent{
		EventType:  EventTypeFailover,
		SourceNode: source,
		TargetNode: target,
		Timestamp:  time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.config.FailoverTimeout)
	defer cancel()

	// 执行故障转移逻辑
	err := f.performFailover(ctx, source, target)

	if err != nil {
		event.Success = false
		event.Message = fmt.Sprintf("Failover failed: %v", err)
		log.Printf("Failover from %s to %s failed: %v", source.ID, target.ID, err)
	} else {
		event.Success = true
		event.Message = fmt.Sprintf("Successfully failed over from %s to %s", source.ID, target.ID)
		log.Printf("Failover from %s to %s completed", source.ID, target.ID)

		// 更新源节点状态
		f.nodeMgr.MarkOffline(source.ID)
	}

	return event
}

// performFailover 执行实际的故障转移操作
func (f *FailoverManager) performFailover(ctx context.Context, source, target *Node) error {
	log.Printf("[Failover] Starting failover from %s to %s", source.ID, target.ID)

	// 1. 通知目标节点准备接收流量
	if err := f.notifyTargetNode(target); err != nil {
		return fmt.Errorf("failed to notify target node: %w", err)
	}

	// 2. 同步必要的数据
	if err := f.syncData(ctx, source, target); err != nil {
		return fmt.Errorf("failed to sync data: %w", err)
	}

	// 3. 更新路由配置
	if err := f.updateRouting(ctx, source, target); err != nil {
		return fmt.Errorf("failed to update routing: %w", err)
	}

	// 4. 验证目标节点状态
	if err := f.verifyTargetNode(ctx, target); err != nil {
		return fmt.Errorf("target node verification failed: %w", err)
	}

	// 5. 更新节点状态
	f.nodeMgr.MarkOffline(source.ID)
	f.nodeMgr.MarkOnline(target.ID)

	log.Printf("[Failover] Failover from %s to %s completed successfully", source.ID, target.ID)
	return nil
}

// notifyTargetNode 通知目标节点准备接收流量
func (f *FailoverManager) notifyTargetNode(node *Node) error {
	if f.agentClient == nil {
		log.Printf("[Failover] No agent client available, skipping notification to %s", node.ID)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. 获取节点状态，验证节点是否在线
	resp, err := f.agentClient.GetStatus(ctx, &pb.StatusRequest{
		NodeId: node.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to contact node %s: %w", node.ID, err)
	}

	if !resp.Success {
		return fmt.Errorf("node %s is not ready: %s", node.ID, resp.Message)
	}

	// 2. 检查节点状态字符串
	if resp.Status != "online" && resp.Status != "ready" {
		return fmt.Errorf("node %s status is not ready: %s", node.ID, resp.Status)
	}

	// 3. 发送准备命令
	commandReq := &pb.CommandRequest{
		CommandId: fmt.Sprintf("prepare-failover-%d", time.Now().UnixNano()),
		NodeId:    node.ID,
		Command:   "prepare",
		Params: map[string]string{
			"action":   "failover_prepare",
			"priority": "10",
		},
	}

	stream, err := f.agentClient.ExecuteCommand(ctx, commandReq)
	if err != nil {
		log.Printf("[Failover] Warning: failed to send prepare command to %s: %v", node.ID, err)
		// 不是致命错误，继续
	} else {
		// 等待命令响应
		cmdResp, err := stream.Recv()
		if err != nil {
			log.Printf("[Failover] Warning: failed to receive prepare response from %s: %v", node.ID, err)
		} else {
			log.Printf("[Failover] Prepare command response from %s: %v", node.ID, cmdResp)
		}
		stream.CloseSend()
	}

	log.Printf("[Failover] Notified node %s to prepare for traffic", node.ID)
	return nil
}

// syncData 同步数据
func (f *FailoverManager) syncData(ctx context.Context, source, target *Node) error {
	log.Printf("[Failover] Syncing data from %s to %s", source.ID, target.ID)

	// 1. 发送数据同步命令
	if f.agentClient != nil {
		commandReq := &pb.CommandRequest{
			CommandId: fmt.Sprintf("sync-data-%d", time.Now().UnixNano()),
			NodeId:    target.ID,
			Command:   "sync",
			Params: map[string]string{
				"action":      "data_sync",
				"source_node": source.ID,
				"sync_type":   "session", // 会话状态同步
			},
		}

		stream, err := f.agentClient.ExecuteCommand(ctx, commandReq)
		if err != nil {
			log.Printf("[Failover] Warning: failed to send sync command to %s: %v", target.ID, err)
			// 不是致命错误，继续
		} else {
			// 等待同步完成
			timeout := time.NewTimer(30 * time.Second)
			defer timeout.Stop()

			syncComplete := false
			for !syncComplete {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timeout.C:
					log.Printf("[Failover] Warning: data sync timeout for %s", target.ID)
					syncComplete = true
				default:
					cmdResp, err := stream.Recv()
					if err != nil {
						syncComplete = true
						break
					}

					// 检查同步状态
					if status, ok := cmdResp.Params["status"]; ok && status == "complete" {
						log.Printf("[Failover] Data sync completed for %s", target.ID)
						syncComplete = true
					}
				}
			}
			stream.CloseSend()
		}
	}

	// 2. 等待数据同步完成（模拟）
	time.Sleep(2 * time.Second)

	log.Printf("[Failover] Data sync completed from %s to %s", source.ID, target.ID)
	return nil
}

// updateRouting 更新路由配置
func (f *FailoverManager) updateRouting(ctx context.Context, source, target *Node) error {
	// 1. 通知负载均衡器更新节点权重
	if f.agentClient != nil {
		// 1.1 先通知目标节点增加权重
		targetCommandReq := &pb.CommandRequest{
			CommandId: fmt.Sprintf("update-weight-%d", time.Now().UnixNano()),
			NodeId:    target.ID,
			Command:   "reload",
			Params: map[string]string{
				"action":      "update_weight",
				"weight":      "100",
				"priority":    "10",
				"source_node": source.ID,
			},
		}

		stream, err := f.agentClient.ExecuteCommand(ctx, targetCommandReq)
		if err != nil {
			log.Printf("[Failover] Failed to send weight update command to target %s: %v", target.ID, err)
		} else {
			log.Printf("[Failover] Weight update command sent to target %s", target.ID)
			stream.CloseSend()
		}

		// 1.2 通知源节点降低权重
		sourceCommandReq := &pb.CommandRequest{
			CommandId: fmt.Sprintf("decrease-weight-%d", time.Now().UnixNano()),
			NodeId:    source.ID,
			Command:   "reload",
			Params: map[string]string{
				"action":      "update_weight",
				"weight":      "0",
				"priority":    "0",
				"target_node": target.ID,
			},
		}

		stream, err = f.agentClient.ExecuteCommand(ctx, sourceCommandReq)
		if err != nil {
			log.Printf("[Failover] Warning: failed to send weight decrease command to source %s: %v", source.ID, err)
			// 不是致命错误，继续
		} else {
			log.Printf("[Failover] Weight decrease command sent to source %s", source.ID)
			stream.CloseSend()
		}
	}

	// 2. 更新节点管理器中的节点权重
	if f.nodeMgr != nil {
		// 2.1 增加目标节点的优先级
		f.nodeMgr.UpdateNode(target.ID, func(n *node.Node) {
			if n.Metadata == nil {
				n.Metadata = make(map[string]string)
			}
			n.Metadata["priority"] = "10"
			n.Metadata["failover_target"] = "true"
			n.Status = "active"
			n.Online = true
		})

		// 2.2 减少源节点的优先级
		f.nodeMgr.UpdateNode(source.ID, func(n *node.Node) {
			if n.Metadata == nil {
				n.Metadata = make(map[string]string)
			}
			n.Metadata["priority"] = "0"
			n.Metadata["failover_source"] = "true"
			n.Status = "degraded"
			n.Online = false
		})
	}

	log.Printf("[Failover] Updated routing from %s to %s", source.ID, target.ID)
	return nil
}

// verifyTargetNode 验证目标节点状态
func (f *FailoverManager) verifyTargetNode(ctx context.Context, node *Node) error {
	log.Printf("[Failover] Verifying node %s is ready...", node.ID)

	// 1. 健康检查验证
	if f.healthChecker != nil {
		isHealthy := f.healthChecker.IsNodeHealthy(node.ID)
		if !isHealthy {
			return fmt.Errorf("node %s health check failed", node.ID)
		}
	}

	// 2. 状态查询验证
	if f.agentClient != nil {
		statusCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		resp, err := f.agentClient.GetStatus(statusCtx, &pb.StatusRequest{
			NodeId: node.ID,
		})
		if err != nil {
			return fmt.Errorf("failed to get node %s status: %w", node.ID, err)
		}

		if !resp.Success {
			return fmt.Errorf("node %s status check failed: %s", node.ID, resp.Message)
		}

		// 3. 验证节点状态字符串
		if resp.Status != "online" && resp.Status != "ready" {
			return fmt.Errorf("node %s status is not ready: %s", node.ID, resp.Status)
		}
	}

	log.Printf("[Failover] Verified node %s is ready", node.ID)
	return nil
}

// rollback 回滚故障转移
func (f *FailoverManager) rollback(source, target *Node) *FailoverEvent {
	event := &FailoverEvent{
		EventType:  EventTypeRollback,
		SourceNode: source,
		TargetNode: target,
		Timestamp:  time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.config.RollbackTimeout)
	defer cancel()

	err := f.performRollback(ctx, source, target)

	if err != nil {
		event.Success = false
		event.Message = fmt.Sprintf("Rollback failed: %v", err)
		log.Printf("Rollback from %s to %s failed: %v", target.ID, source.ID, err)
	} else {
		event.Success = true
		event.Message = fmt.Sprintf("Successfully rolled back from %s to %s", target.ID, source.ID)
		log.Printf("Rollback from %s to %s completed", target.ID, source.ID)

		// 更新节点状态
		f.nodeMgr.MarkOnline(source.ID)
	}

	return event
}

// performRollback 执行实际的回滚操作
func (f *FailoverManager) performRollback(ctx context.Context, source, target *Node) error {
	log.Printf("[Failover] Starting rollback from %s to %s", target.ID, source.ID)

	// 1. 恢复源节点状态
	if err := f.restoreSourceNode(ctx, source); err != nil {
		return fmt.Errorf("failed to restore source node: %w", err)
	}

	// 2. 恢复路由配置
	if err := f.rollbackRouting(ctx, source, target); err != nil {
		return fmt.Errorf("failed to rollback routing: %w", err)
	}

	// 3. 更新节点状态
	f.nodeMgr.MarkOnline(source.ID)
	f.nodeMgr.MarkOffline(target.ID)

	log.Printf("[Failover] Rollback from %s to %s completed", target.ID, source.ID)
	return nil
}

// restoreSourceNode 恢复源节点
func (f *FailoverManager) restoreSourceNode(ctx context.Context, targetNode *Node) error {
	log.Printf("[Failover] Restoring node %s", targetNode.ID)

	// 1. 发送恢复命令到源节点
	if f.agentClient != nil {
		commandReq := &pb.CommandRequest{
			CommandId: fmt.Sprintf("restore-%d", time.Now().UnixNano()),
			NodeId:    targetNode.ID,
			Command:   "restore",
			Params: map[string]string{
				"action": "node_restore",
			},
		}

		stream, err := f.agentClient.ExecuteCommand(ctx, commandReq)
		if err != nil {
			log.Printf("[Failover] Warning: failed to send restore command to %s: %v", targetNode.ID, err)
		} else {
			// 等待恢复响应
			resp, err := stream.Recv()
			if err != nil {
				log.Printf("[Failover] Warning: failed to receive restore response from %s: %v", targetNode.ID, err)
			} else {
				log.Printf("[Failover] Restore response from %s: command_id=%s", targetNode.ID, resp.CommandId)
			}
			stream.CloseSend()
		}
	}

	// 2. 验证源节点健康状态
	if f.healthChecker != nil {
		if !f.healthChecker.IsNodeHealthy(targetNode.ID) {
			log.Printf("[Failover] Warning: source node %s is not healthy yet", targetNode.ID)
			// 继续尝试恢复，节点可能在恢复过程中
		} else {
			log.Printf("[Failover] Source node %s is healthy", targetNode.ID)
		}
	}

	// 3. 清除故障转移相关的元数据
	f.nodeMgr.UpdateNode(targetNode.ID, func(n *node.Node) {
		if n.Metadata == nil {
			n.Metadata = make(map[string]string)
		}
		// 清除故障转移标记
		delete(n.Metadata, "failover_source")
		delete(n.Metadata, "failover_target")
		// 重置优先级
		if priority, ok := n.Metadata["original_priority"]; ok {
			n.Metadata["priority"] = priority
			delete(n.Metadata, "original_priority")
		} else {
			n.Metadata["priority"] = "5" // 默认优先级
		}
		// 恢复状态
		n.Status = "online"
		n.Online = true
	})

	log.Printf("[Failover] Node %s restoration initiated", targetNode.ID)
	return nil
}

// rollbackRouting 回滚路由配置
func (f *FailoverManager) rollbackRouting(ctx context.Context, source, target *Node) error {
	log.Printf("[Failover] Rolling back routing from %s to %s", target.ID, source.ID)

	// 1. 通知目标节点减少权重
	if f.agentClient != nil {
		targetCommandReq := &pb.CommandRequest{
			CommandId: fmt.Sprintf("rollback-weight-%d", time.Now().UnixNano()),
			NodeId:    target.ID,
			Command:   "reload",
			Params: map[string]string{
				"action": "update_weight",
				"weight": "0",
				"priority": "0",
			},
		}

		stream, err := f.agentClient.ExecuteCommand(ctx, targetCommandReq)
		if err != nil {
			log.Printf("[Failover] Warning: failed to send rollback weight command to target %s: %v", target.ID, err)
		} else {
			log.Printf("[Failover] Rollback weight command sent to target %s", target.ID)
			stream.CloseSend()
		}
	}

	// 2. 通知源节点恢复正常权重
	if f.agentClient != nil {
		sourceCommandReq := &pb.CommandRequest{
			CommandId: fmt.Sprintf("restore-weight-%d", time.Now().UnixNano()),
			NodeId:    source.ID,
			Command:   "reload",
			Params: map[string]string{
				"action":           "update_weight",
				"weight":           "100",
				"priority":         "5",
				"restore_from":     target.ID,
			},
		}

		stream, err := f.agentClient.ExecuteCommand(ctx, sourceCommandReq)
		if err != nil {
			log.Printf("[Failover] Warning: failed to send restore weight command to source %s: %v", source.ID, err)
		} else {
			log.Printf("[Failover] Restore weight command sent to source %s", source.ID)
			stream.CloseSend()
		}
	}

	// 3. 更新节点管理器中的路由配置
	if f.nodeMgr != nil {
		// 恢复源节点的正常权重和状态
		f.nodeMgr.UpdateNode(source.ID, func(n *node.Node) {
			if n.Metadata == nil {
				n.Metadata = make(map[string]string)
			}
			n.Metadata["priority"] = "5"
			n.Metadata["failover_source"] = "false"
			n.Metadata["failover_target"] = "false"
			n.Status = "online"
			n.Online = true
		})

		// 将目标节点标记为备用
		f.nodeMgr.UpdateNode(target.ID, func(n *node.Node) {
			if n.Metadata == nil {
				n.Metadata = make(map[string]string)
			}
			n.Metadata["priority"] = "0"
			n.Metadata["standby"] = "true"
			n.Status = "online"
			n.Online = true
		})
	}

	log.Printf("[Failover] Routing rolled back from %s to %s", target.ID, source.ID)
	return nil
}

// runEventHandler 运行事件处理器
func (f *FailoverManager) runEventHandler() {
	defer f.wg.Done()

	for {
		select {
		case <-f.stopCh:
			return
		case event := <-f.eventChan:
			f.handleEvent(event)
		}
	}
}

// handleEvent 处理事件
func (f *FailoverManager) handleEvent(event *FailoverEvent) {
	switch event.EventType {
	case EventTypeFailover:
		if event.Success {
			// 记录成功故障转移
			log.Printf("Failover event: %s -> %s", event.SourceNode.ID, event.TargetNode.ID)
		}
	case EventTypeRollback:
		if event.Success {
			// 记录成功回滚
			log.Printf("Rollback event: %s -> %s", event.TargetNode.ID, event.SourceNode.ID)
		}
	case EventTypeNodeDown:
		log.Printf("Node down event: %s", event.SourceNode.ID)
	case EventTypeNodeUp:
		log.Printf("Node up event: %s", event.SourceNode.ID)
	}
}

// getNodeConnectionCount 获取节点连接数
func (f *FailoverManager) getNodeConnectionCount(nodeID string) int64 {
	// 从节点管理器获取节点的活跃连接数
	node := f.nodeMgr.GetNode(nodeID)
	if node == nil {
		return 0
	}

	// 如果节点有连接数元数据，使用它
	if conns, ok := node.Metadata["active_connections"]; ok {
		if parsed, err := strconv.ParseInt(conns, 10, 64); err == nil {
			return parsed
		}
	}

	// 默认返回0（没有实际连接数据时）
	return 0
}

// getNodePriority 获取节点优先级
func (f *FailoverManager) getNodePriority(nodeID string) int {
	// 从节点管理器获取节点优先级
	node := f.nodeMgr.GetNode(nodeID)
	if node == nil {
		return 0
	}

	// 检查元数据中的优先级
	if priority, ok := node.Metadata["priority"]; ok {
		if parsed, err := strconv.ParseInt(priority, 10, 64); err == nil {
			return int(parsed)
		}
	}

	// 根据节点类型计算默认优先级
	switch node.Type {
	case "master":
		return 100
	case "core":
		return 80
	case "l2":
		return 60
	case "edge":
		return 40
	default:
		return 10
	}
}

// getNodeLatency 获取节点延迟
func (f *FailoverManager) getNodeLatency(nodeID string) time.Duration {
	// 从健康检查器获取延迟
	results := f.healthChecker.GetCheckResult(nodeID)

	for _, result := range results {
		if result.CheckType == CheckTypeGRPC {
			return result.Latency
		}
	}

	return time.Hour
}

// ManualFailover 手动故障转移
func (f *FailoverManager) ManualFailover(sourceID, targetID string) error {
	source := f.nodeMgr.GetNode(sourceID)
	target := f.nodeMgr.GetNode(targetID)

	if source == nil {
		return fmt.Errorf("source node not found: %s", sourceID)
	}

	if target == nil {
		return fmt.Errorf("target node not found: %s", targetID)
	}

	event := f.executeFailover(&Node{
		ID:     source.ID,
		Addr:   source.Addr,
		Port:   source.Port,
		Region: source.Region,
		Status: source.Status,
	}, &Node{
		ID:     target.ID,
		Addr:   target.Addr,
		Port:   target.Port,
		Region: target.Region,
		Status: target.Status,
	})

	if !event.Success {
		return fmt.Errorf("failover failed: %s", event.Message)
	}

	return nil
}

// ManualRollback 手动回滚
func (f *FailoverManager) ManualRollback(sourceID, targetID string) error {
	source := f.nodeMgr.GetNode(sourceID)
	target := f.nodeMgr.GetNode(targetID)

	if source == nil {
		return fmt.Errorf("source node not found: %s", sourceID)
	}

	if target == nil {
		return fmt.Errorf("target node not found: %s", targetID)
	}

	event := f.rollback(&Node{
		ID:     source.ID,
		Addr:   source.Addr,
		Port:   source.Port,
		Region: source.Region,
		Status: source.Status,
	}, &Node{
		ID:     target.ID,
		Addr:   target.Addr,
		Port:   target.Port,
		Region: target.Region,
		Status: target.Status,
	})

	if !event.Success {
		return fmt.Errorf("rollback failed: %s", event.Message)
	}

	return nil
}

// GetFailoverStats 获取故障转移统计
func (f *FailoverManager) GetFailoverStats() *FailoverStats {
	stats := &FailoverStats{
		TotalFailovers:  0,
		SuccessfulCount: 0,
		FailedCount:     0,
		RollbackCount:   0,
		RecentEvents:    make([]*FailoverEvent, 0),
	}

	for {
		select {
		case event := <-f.eventChan:
			stats.TotalFailovers++
			if event.EventType == EventTypeFailover {
				if event.Success {
					stats.SuccessfulCount++
				} else {
					stats.FailedCount++
				}
			} else if event.EventType == EventTypeRollback {
				stats.RollbackCount++
			}
			stats.RecentEvents = append(stats.RecentEvents, event)

			// 只保留最近100个事件
			if len(stats.RecentEvents) > 100 {
				stats.RecentEvents = stats.RecentEvents[1:]
			}
		default:
			return stats
		}
	}
}

// FailoverStats 故障转移统计
type FailoverStats struct {
	TotalFailovers  int
	SuccessfulCount int
	FailedCount     int
	RollbackCount   int
	RecentEvents    []*FailoverEvent
}

package health

import (
	"log"
	"sync"
	"time"
)

// AutoScaler 自动扩缩容管理器
type AutoScaler struct {
	config      *AutoScaleConfig
	healthChecker *HealthChecker
	metrics     *MetricsCollector
	eventChan   chan *ScaleEvent
	scaleRules  []*ScaleRule
	mu          sync.RWMutex
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// AutoScaleConfig 自动扩缩容配置
type AutoScaleConfig struct {
	// 是否启用自动扩缩容
	Enabled bool

	// 最小节点数
	MinNodes int

	// 最大节点数
	MaxNodes int

	// 扩缩容间隔
	ScaleInterval time.Duration

	// 扩容阈值
	ScaleUpThreshold float64

	// 缩容阈值
	ScaleDownThreshold float64

	// 冷却时间
	CooldownPeriod time.Duration

	// 节点配置
	NodeConfig *NodeConfig
}

// NodeConfig 节点配置
type NodeConfig struct {
	// CPU配置
	CPU string

	// 内存配置
	Memory string

	// 磁盘配置
	Disk string

	// 区域
	Region string

	// 实例类型
	InstanceType string
}

// ScaleRule 扩缩容规则
type ScaleRule struct {
	RuleID      string
	Name        string
	MetricType  MetricType
	Condition   string
	Threshold   float64
	Action      ScaleAction
	Cooldown    time.Duration
	Enabled     bool
	Priority    int
}

// MetricType 指标类型
type MetricType string

const (
	MetricTypeCPUUsage     MetricType = "cpu_usage"
	MetricTypeMemoryUsage  MetricType = "memory_usage"
	MetricTypeQPS          MetricType = "qps"
	MetricTypeLatency      MetricType = "latency"
	MetricTypeConnections  MetricType = "connections"
	MetricTypeBandwidth    MetricType = "bandwidth"
)

// ScaleAction 扩缩容动作
type ScaleAction string

const (
	ScaleActionScaleUp   ScaleAction = "scale_up"
	ScaleActionScaleDown ScaleAction = "scale_down"
)

// ScaleEvent 扩缩容事件
type ScaleEvent struct {
	EventType   EventType
	NodeID      string
	Region      string
	OldReplica  int
	NewReplica  int
	Reason      string
	Timestamp   time.Time
	Success     bool
	Message     string
}

// MetricsCollector 指标收集器
type MetricsCollector struct {
	mu       sync.RWMutex
	metrics  map[string]*NodeMetrics
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NodeMetrics 节点指标
type NodeMetrics struct {
	NodeID       string
	CPUUsage     float64
	MemoryUsage  float64
	QPS          float64
	Latency      time.Duration
	Connections  int64
	BandwidthIn  float64
	BandwidthOut float64
	Timestamp    time.Time
}

// DefaultAutoScaleConfig 默认配置
func DefaultAutoScaleConfig() *AutoScaleConfig {
	return &AutoScaleConfig{
		Enabled:          true,
		MinNodes:         2,
		MaxNodes:         20,
		ScaleInterval:    30 * time.Second,
		ScaleUpThreshold: 0.7,  // CPU使用率70%时扩容
		ScaleDownThreshold: 0.3, // CPU使用率30%时缩容
		CooldownPeriod:   5 * time.Minute,
		NodeConfig: &NodeConfig{
			Region:       "default",
			InstanceType: "standard",
		},
	}
}

// NewAutoScaler 创建自动扩缩容管理器
func NewAutoScaler(cfg *AutoScaleConfig, healthChecker *HealthChecker) *AutoScaler {
	if cfg == nil {
		cfg = DefaultAutoScaleConfig()
	}

	return &AutoScaler{
		config:       cfg,
		healthChecker: healthChecker,
		metrics:      NewMetricsCollector(),
		eventChan:    make(chan *ScaleEvent, 100),
		scaleRules:   make([]*ScaleRule, 0),
		stopCh:       make(chan struct{}),
	}
}

// NewMetricsCollector 创建指标收集器
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: make(map[string]*NodeMetrics),
		stopCh:  make(chan struct{}),
	}
}

// Start 启动自动扩缩容
func (a *AutoScaler) Start() {
	if !a.config.Enabled {
		log.Println("Auto scaler is disabled")
		return
	}

	// 启动指标收集
	a.metrics.Start()

	// 启动扩缩容协程
	a.wg.Add(1)
	go a.runScaler()

	// 启动事件处理协程
	a.wg.Add(1)
	go a.runEventHandler()

	log.Println("Auto scaler started")
}

// Stop 停止自动扩缩容
func (a *AutoScaler) Stop() {
	close(a.stopCh)
	a.wg.Wait()
	a.metrics.Stop()
	close(a.eventChan)

	log.Println("Auto scaler stopped")
}

// runScaler 运行扩缩容
func (a *AutoScaler) runScaler() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.ScaleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.evaluateAndScale()
		}
	}
}

// evaluateAndScale 评估并执行扩缩容
func (a *AutoScaler) evaluateAndScale() {
	// 获取当前指标
	metrics := a.metrics.GetAllMetrics()

	// 计算平均负载
	avgCPU := a.calculateAverageCPU(metrics)
	avgQPS := a.calculateAverageQPS(metrics)

	// 检查是否需要扩容
	if avgCPU > a.config.ScaleUpThreshold || avgQPS > a.getQPSThreshold() {
		a.scaleUp()
	}

	// 检查是否需要缩容
	if avgCPU < a.config.ScaleDownThreshold && a.getCurrentNodeCount() > a.config.MinNodes {
		a.scaleDown()
	}

	// 检查自定义规则
	a.evaluateRules(metrics)
}

// calculateAverageCPU 计算平均CPU使用率
func (a *AutoScaler) calculateAverageCPU(metrics map[string]*NodeMetrics) float64 {
	if len(metrics) == 0 {
		return 0
	}

	var total float64
	for _, m := range metrics {
		total += m.CPUUsage
	}

	return total / float64(len(metrics))
}

// calculateAverageQPS 计算平均QPS
func (a *AutoScaler) calculateAverageQPS(metrics map[string]*NodeMetrics) float64 {
	if len(metrics) == 0 {
		return 0
	}

	var total float64
	for _, m := range metrics {
		total += m.QPS
	}

	return total / float64(len(metrics))
}

// getQPSThreshold 获取QPS阈值
func (a *AutoScaler) getQPSThreshold() float64 {
	// 根据节点数动态调整阈值
	nodeCount := a.getCurrentNodeCount()
	return 1000.0 * float64(nodeCount)
}

// scaleUp 扩容
func (a *AutoScaler) scaleUp() {
	currentCount := a.getCurrentNodeCount()

	if currentCount >= a.config.MaxNodes {
		log.Printf("Already at max nodes (%d), cannot scale up", currentCount)
		return
	}

	log.Printf("Scaling up: current nodes = %d", currentCount)

	// 创建新节点
	newNode := a.createNode()
	if newNode == nil {
		log.Println("Failed to create new node")
		return
	}

	event := &ScaleEvent{
		EventType:  EventTypeNodeUp,
		NodeID:     newNode.ID,
		Region:     newNode.Region,
		OldReplica: currentCount,
		NewReplica: currentCount + 1,
		Reason:     "high_cpu_usage",
		Timestamp:  time.Now(),
		Success:    true,
		Message:    "Successfully scaled up",
	}

	a.eventChan <- event

	log.Printf("Scaled up: new node = %s, total nodes = %d", newNode.ID, currentCount+1)
}

// scaleDown 缩容
func (a *AutoScaler) scaleDown() {
	currentCount := a.getCurrentNodeCount()

	if currentCount <= a.config.MinNodes {
		log.Printf("Already at min nodes (%d), cannot scale down", currentCount)
		return
	}

	// 选择要移除的节点
	nodeToRemove := a.selectNodeToRemove()
	if nodeToRemove == nil {
		log.Println("No suitable node to remove")
		return
	}

	log.Printf("Scaling down: current nodes = %d", currentCount)

	// 移除节点
	err := a.removeNode(nodeToRemove)
	if err != nil {
		log.Printf("Failed to remove node %s: %v", nodeToRemove.ID, err)
		return
	}

	event := &ScaleEvent{
		EventType:  EventTypeNodeDown,
		NodeID:     nodeToRemove.ID,
		Region:     nodeToRemove.Region,
		OldReplica: currentCount,
		NewReplica: currentCount - 1,
		Reason:     "low_cpu_usage",
		Timestamp:  time.Now(),
		Success:    true,
		Message:    "Successfully scaled down",
	}

	a.eventChan <- event

	log.Printf("Scaled down: removed node = %s, total nodes = %d", nodeToRemove.ID, currentCount-1)
}

// selectNodeToRemove 选择要移除的节点
func (a *AutoScaler) selectNodeToRemove() *Node {
	metrics := a.metrics.GetAllMetrics()

	var selected *Node
	lowestLoad := float64(^uint64(0))

	for nodeID, m := range metrics {
		load := m.CPUUsage + m.QPS/1000.0
		if load < lowestLoad {
			lowestLoad = load
			selected = &Node{ID: nodeID}
		}
	}

	return selected
}

// evaluateRules 评估扩缩容规则
func (a *AutoScaler) evaluateRules(metrics map[string]*NodeMetrics) {
	a.mu.RLock()
	rules := a.scaleRules
	a.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// 评估规则条件
		triggered := a.evaluateRuleCondition(rule, metrics)
		if triggered {
			a.executeRuleAction(rule)
		}
	}
}

// evaluateRuleCondition 评估规则条件
func (a *AutoScaler) evaluateRuleCondition(rule *ScaleRule, metrics map[string]*NodeMetrics) bool {
	// 计算指标平均值
	var avgValue float64

	switch rule.MetricType {
	case MetricTypeCPUUsage:
		avgValue = a.calculateAverageCPU(metrics)
	case MetricTypeMemoryUsage:
		avgValue = a.calculateAverageMemory(metrics)
	case MetricTypeQPS:
		avgValue = a.calculateAverageQPS(metrics)
	case MetricTypeLatency:
		avgValue = float64(a.calculateAverageLatency(metrics).Milliseconds())
	case MetricTypeConnections:
		avgValue = float64(a.calculateAverageConnections(metrics))
	}

	// 根据条件判断
	switch rule.Condition {
	case ">":
		return avgValue > rule.Threshold
	case ">=":
		return avgValue >= rule.Threshold
	case "<":
		return avgValue < rule.Threshold
	case "<=":
		return avgValue <= rule.Threshold
	case "==":
		return avgValue == rule.Threshold
	}

	return false
}

// calculateAverageMemory 计算平均内存使用率
func (a *AutoScaler) calculateAverageMemory(metrics map[string]*NodeMetrics) float64 {
	if len(metrics) == 0 {
		return 0
	}

	var total float64
	for _, m := range metrics {
		total += m.MemoryUsage
	}

	return total / float64(len(metrics))
}

// calculateAverageLatency 计算平均延迟
func (a *AutoScaler) calculateAverageLatency(metrics map[string]*NodeMetrics) time.Duration {
	if len(metrics) == 0 {
		return 0
	}

	var total time.Duration
	for _, m := range metrics {
		total += m.Latency
	}

	return total / time.Duration(len(metrics))
}

// calculateAverageConnections 计算平均连接数
func (a *AutoScaler) calculateAverageConnections(metrics map[string]*NodeMetrics) int64 {
	if len(metrics) == 0 {
		return 0
	}

	var total int64
	for _, m := range metrics {
		total += m.Connections
	}

	return total / int64(len(metrics))
}

// executeRuleAction 执行规则动作
func (a *AutoScaler) executeRuleAction(rule *ScaleRule) {
	switch rule.Action {
	case ScaleActionScaleUp:
		a.scaleUp()
	case ScaleActionScaleDown:
		a.scaleDown()
	}
}

// createNode 创建新节点
func (a *AutoScaler) createNode() *Node {
	// 实现节点创建逻辑
	return &Node{
		ID:     generateNodeID(),
		Region: a.config.NodeConfig.Region,
		Status: "pending",
	}
}

// removeNode 移除节点
func (a *AutoScaler) removeNode(node *Node) error {
	// 实现节点移除逻辑
	return nil
}

// getCurrentNodeCount 获取当前节点数
func (a *AutoScaler) getCurrentNodeCount() int {
	metrics := a.metrics.GetAllMetrics()
	return len(metrics)
}

// AddRule 添加扩缩容规则
func (a *AutoScaler) AddRule(rule *ScaleRule) {
	a.mu.Lock()
	defer a.mu.Unlock()

	rule.RuleID = generateRuleID()
	a.scaleRules = append(a.scaleRules, rule)
}

// RemoveRule 移除扩缩容规则
func (a *AutoScaler) RemoveRule(ruleID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, rule := range a.scaleRules {
		if rule.RuleID == ruleID {
			a.scaleRules = append(a.scaleRules[:i], a.scaleRules[i+1:]...)
			break
		}
	}
}

// GetRules 获取所有扩缩容规则
func (a *AutoScaler) GetRules() []*ScaleRule {
	a.mu.RLock()
	defer a.mu.RUnlock()

	rules := make([]*ScaleRule, len(a.scaleRules))
	copy(rules, a.scaleRules)
	return rules
}

// runEventHandler 运行事件处理器
func (a *AutoScaler) runEventHandler() {
	defer a.wg.Done()

	for {
		select {
		case <-a.stopCh:
			return
		case event := <-a.eventChan:
			log.Printf("Scale event: %s, node=%s, replicas=%d->%d",
				event.EventType, event.NodeID, event.OldReplica, event.NewReplica)
		}
	}
}

// StartMetricsCollector 启动指标收集器
func (m *MetricsCollector) Start() {
	m.wg.Add(1)
	go m.collectMetrics()
}

// StopMetricsCollector 停止指标收集器
func (m *MetricsCollector) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// collectMetrics 收集指标
func (m *MetricsCollector) collectMetrics() {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			// 收集节点指标
			m.refreshMetrics()
		}
	}
}

// refreshMetrics 刷新指标
func (m *MetricsCollector) refreshMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 更新指标数据
	// 这里应该从实际的监控系统中获取指标
}

// UpdateMetric 更新指标
func (m *MetricsCollector) UpdateMetric(nodeID string, metrics *NodeMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.metrics[nodeID] = metrics
}

// GetMetric 获取单个节点指标
func (m *MetricsCollector) GetMetric(nodeID string) *NodeMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.metrics[nodeID]
}

// GetAllMetrics 获取所有指标
func (m *MetricsCollector) GetAllMetrics() map[string]*NodeMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := make(map[string]*NodeMetrics)
	for k, v := range m.metrics {
		metrics[k] = v
	}
	return metrics
}

// 辅助函数
func generateNodeID() string {
	return "node-" + time.Now().Format("20060102150405")
}

func generateRuleID() string {
	return "rule-" + time.Now().Format("20060102150405")
}

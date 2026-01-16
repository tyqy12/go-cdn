package failover

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
)

// Manager 故障转移管理器
type Manager struct {
	mu           sync.RWMutex
	groups       map[string]*Group
	defaultGroup *Group
	logger       logger.Logger
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// Group 故障转移组
type Group struct {
	name         string
	primary      *Node
	secondaries  []*Node
	strategy     FailoverStrategy
	interval     time.Duration
	timeout      time.Duration
	current      atomic.Value // 当前活跃节点
	switches     atomic.Int64
	lastSwitch   time.Time
	logger       logger.Logger
	mu           sync.RWMutex
}

// Node 节点
type Node struct {
	Addr     string
	Port     int
	Weight   int
	Priority int
	Healthy  bool
	Name     string
}

// FailoverStrategy 故障转移策略
type FailoverStrategy string

const (
	// StrategyPrimary 主备
	StrategyPrimary FailoverStrategy = "primary"
	// StrategyActiveActive 主动主动
	StrategyActiveActive FailoverStrategy = "active_active"
	// StrategyActiveStandby 主动备份
	StrategyActiveStandby FailoverStrategy = "active_standby"
	// StrategyWeighted 加权
	StrategyWeighted FailoverStrategy = "weighted"
)

// FailoverConfig 故障转移配置
type FailoverConfig struct {
	Strategy   FailoverStrategy
	Interval   time.Duration
	Timeout    time.Duration
	MaxRetries int
}

// SwitchEvent 切换事件
type SwitchEvent struct {
	Group     string
	FromNode  string
	ToNode    string
	Reason    string
	Timestamp time.Time
}

// NewManager 创建故障转移管理器
func NewManager(opts ...Option) *Manager {
	m := &Manager{
		groups: make(map[string]*Group),
		logger: logger.Default(),
		stopCh: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Option 选项
type Option func(*Manager)

// WithFOMLogger 设置日志
func WithFOMLogger(l logger.Logger) Option {
	return func(m *Manager) {
		m.logger = l
	}
}

// CreateGroup 创建故障转移组
func (m *Manager) CreateGroup(name string, cfg *FailoverConfig) (*Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.groups[name]; exists {
		return nil, ErrGroupAlreadyExists
	}

	g := &Group{
		name:     name,
		strategy: cfg.Strategy,
		interval: cfg.Interval,
		timeout:  cfg.Timeout,
		logger:   m.logger,
	}

	m.groups[name] = g
	return g, nil
}

// GetGroup 获取故障转移组
func (m *Manager) GetGroup(name string) (*Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	g, ok := m.groups[name]
	if !ok {
		return nil, ErrGroupNotFound
	}

	return g, nil
}

// RemoveGroup 移除故障转移组
func (m *Manager) RemoveGroup(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.groups[name]; !ok {
		return ErrGroupNotFound
	}

	delete(m.groups, name)
	return nil
}

// SetPrimary 设置主节点
func (g *Group) SetPrimary(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.primary = node
	g.current.Store(node)

	g.logger.Infof("primary node set: %s:%d", node.Addr, node.Port)
}

// AddSecondary 添加备用节点
func (g *Group) AddSecondary(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.secondaries = append(g.secondaries, node)

	g.logger.Infof("secondary node added: %s:%d", node.Addr, node.Port)
}

// RemoveSecondary 移除备用节点
func (g *Group) RemoveSecondary(addr string, port int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for i, n := range g.secondaries {
		if n.Addr == addr && n.Port == port {
			g.secondaries = append(g.secondaries[:i], g.secondaries[i+1:]...)
			break
		}
	}
}

// GetCurrent 获取当前活跃节点
func (g *Group) GetCurrent() *Node {
	return g.current.Load().(*Node)
}

// SwitchTo 手动切换到指定节点
func (g *Group) SwitchTo(node *Node, reason string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	oldNode := g.current.Load().(*Node)

	if oldNode != nil && oldNode.Addr == node.Addr && oldNode.Port == node.Port {
		return ErrSameNode
	}

	g.current.Store(node)
	g.lastSwitch = time.Now()
	g.switches.Add(1)

	g.logger.Infof("failover: %s -> %s (%s)", oldNode.String(), node.String(), reason)
	return nil
}

// ShouldSwitch 判断是否应该切换
func (g *Group) ShouldSwitch() (bool, string) {
	current := g.current.Load().(*Node)
	if current == nil {
		return true, "no active node"
	}

	if !current.Healthy {
		return true, "current node unhealthy"
	}

	return false, ""
}

// PerformFailover 执行故障转移
func (g *Group) PerformFailover() (*Node, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	current := g.current.Load().(*Node)
	if current != nil && current.Healthy {
		return current, nil
	}

	var target *Node

	switch g.strategy {
	case StrategyPrimary:
		target = g.selectPrimary()
	case StrategyActiveStandby:
		target = g.selectActiveStandby()
	case StrategyActiveActive:
		target = g.selectActiveActive()
	case StrategyWeighted:
		target = g.selectWeighted()
	default:
		target = g.selectPrimary()
	}

	if target == nil {
		return nil, ErrNoAvailableNode
	}

	if current != nil {
		g.logger.Warnf("failover triggered: %s -> %s", current.String(), target.String())
	} else {
		g.logger.Infof("initial node selection: %s", target.String())
	}

	g.current.Store(target)
	g.lastSwitch = time.Now()
	g.switches.Add(1)

	return target, nil
}

// selectPrimary 选择主节点
func (g *Group) selectPrimary() *Node {
	if g.primary != nil && g.primary.Healthy {
		return g.primary
	}

	for _, n := range g.secondaries {
		if n.Healthy {
			return n
		}
	}

	return nil
}

// selectActiveStandby 选择活动备份节点
func (g *Group) selectActiveStandby() *Node {
	// 按优先级选择
	for _, n := range g.secondaries {
		if n.Healthy && n.Priority > 0 {
			return n
		}
	}

	return g.selectPrimary()
}

// selectActiveActive 选择活动活动节点
func (g *Group) selectActiveActive() *Node {
	// 选择权重最高的健康节点
	var maxWeight int
	var selected *Node

	if g.primary != nil && g.primary.Healthy {
		selected = g.primary
		maxWeight = g.primary.Weight
	}

	for _, n := range g.secondaries {
		if n.Healthy && n.Weight > maxWeight {
			selected = n
			maxWeight = n.Weight
		}
	}

	return selected
}

// selectWeighted 选择加权节点
func (g *Group) selectWeighted() *Node {
	totalWeight := 0
	healthyNodes := make([]*Node, 0)

	if g.primary != nil && g.primary.Healthy {
		totalWeight += g.primary.Weight
		healthyNodes = append(healthyNodes, g.primary)
	}

	for _, n := range g.secondaries {
		if n.Healthy {
			totalWeight += n.Weight
			healthyNodes = append(healthyNodes, n)
		}
	}

	if totalWeight == 0 || len(healthyNodes) == 0 {
		return nil
	}

	// 加权随机选择
	randWeight := rand.Intn(totalWeight)
	curWeight := 0
	for _, n := range healthyNodes {
		curWeight += n.Weight
		if randWeight < curWeight {
			return n
		}
	}

	return healthyNodes[0]
}

// StartMonitoring 启动监控
func (g *Group) StartMonitoring(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(g.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.checkAndSwitch()
			}
		}
	}()
}

// checkAndSwitch 检查并切换
func (g *Group) checkAndSwitch() {
	shouldSwitch, reason := g.ShouldSwitch()
	if shouldSwitch {
		g.logger.Infof("auto failover triggered: %s", reason)
		g.PerformFailover()
	}
}

// GetStats 获取统计信息
func (g *Group) GetStats() FailoverStats {
	current := g.current.Load().(*Node)

	stats := FailoverStats{
		Group:       g.name,
		Strategy:    string(g.strategy),
		Switches:    g.switches.Load(),
		LastSwitch:  g.lastSwitch,
	}

	if current != nil {
		stats.CurrentNode = current.String()
		stats.CurrentHealthy = current.Healthy
	}

	stats.SecondaryCount = len(g.secondaries)
	stats.HealthySecondaries = g.countHealthySecondaries()

	return stats
}

// countHealthySecondaries 统计健康备用节点数
func (g *Group) countHealthySecondaries() int {
	count := 0
	for _, n := range g.secondaries {
		if n.Healthy {
			count++
		}
	}
	return count
}

// FailoverStats 故障转移统计
type FailoverStats struct {
	Group              string
	CurrentNode        string
	CurrentHealthy     bool
	Strategy           string
	SecondaryCount     int
	HealthySecondaries int
	Switches           int64
	LastSwitch         time.Time
}

// String 返回节点字符串表示
func (n *Node) String() string {
	return n.Addr + ":" + itoa(n.Port)
}

// itoa 整数转字符串
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	result := ""
	for i > 0 {
		result = string(rune('0'+i%10)) + result
		i /= 10
	}
	return result
}

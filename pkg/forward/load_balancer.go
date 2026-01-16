package forward

import (
	"context"
	"hash/fnv"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
)

// LoadBalancer 负载均衡器
type LoadBalancer struct {
	mu       sync.RWMutex
	clusters map[string]*Cluster
	logger   logger.Logger
}

// Cluster 后端服务器集群
type Cluster struct {
	mu           sync.RWMutex
	name         string
	backends     []*Backend
	strategy     LBStrategy
	healthCheck  HealthCheckFunc
	stickyConfig StickyConfig
	logger       logger.Logger
}

// Backend 后端服务器
type Backend struct {
	addr     string
	port     int
	weight   int
	healthy  atomic.Bool
	active   atomic.Int64
	latency  float64 // 使用 float64 替代 atomic.Float64
	failures atomic.Int64
}

// LBStrategy 负载均衡策略
type LBStrategy string

const (
	// LBStrategyRoundRobin 轮询
	LBStrategyRoundRobin LBStrategy = "round_robin"
	// LBStrategyWeighted 加权轮询
	LBStrategyWeighted LBStrategy = "weighted"
	// LBStrategyLeastConn 最少连接
	LBStrategyLeastConn LBStrategy = "least_conn"
	// LBStrategyIPHash IP哈希
	LBStrategyIPHash LBStrategy = "ip_hash"
	// LBStrategyURLHash URL哈希
	LBStrategyURLHash LBStrategy = "url_hash"
	// LBStrategyRandom 随机
	LBStrategyRandom LBStrategy = "random"
	// LBStrategyConsistentHash 一致性哈希
	LBStrategyConsistentHash LBStrategy = "consistent_hash"
	// LBStrategyLatencyBased 延迟最低
	LBStrategyLatencyBased LBStrategy = "latency"
)

// StickyConfig 会话粘性配置
type StickyConfig struct {
	Enabled    bool
	Method     string // cookie, ip_hash, header
	CookieName string
	HeaderName string
	Timeout    int // 秒
}

// HealthCheckFunc 健康检查函数
type HealthCheckFunc func(ctx context.Context, addr string) error

// NewLoadBalancer 创建负载均衡器
func NewLoadBalancer(opts ...LBOption) *LoadBalancer {
	lb := &LoadBalancer{
		clusters: make(map[string]*Cluster),
		logger:   logger.Default(),
	}

	for _, opt := range opts {
		opt(lb)
	}

	return lb
}

// LBOption 选项
type LBOption func(*LoadBalancer)

// WithLBLogger 设置日志
func WithLBLogger(l logger.Logger) LBOption {
	return func(lb *LoadBalancer) {
		lb.logger = l
	}
}

// CreateCluster 创建集群
func (lb *LoadBalancer) CreateCluster(name string, opts ...ClusterOption) (*Cluster, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if _, exists := lb.clusters[name]; exists {
		return nil, ErrClusterAlreadyExists
	}

	c := &Cluster{
		name:     name,
		backends: make([]*Backend, 0),
		strategy: LBStrategyRoundRobin,
		logger:   lb.logger,
	}

	for _, opt := range opts {
		opt(c)
	}

	lb.clusters[name] = c
	return c, nil
}

// GetCluster 获取集群
func (lb *LoadBalancer) GetCluster(name string) (*Cluster, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	c, ok := lb.clusters[name]
	if !ok {
		return nil, ErrClusterNotFound
	}

	return c, nil
}

// RemoveCluster 移除集群
func (lb *LoadBalancer) RemoveCluster(name string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if _, ok := lb.clusters[name]; !ok {
		return ErrClusterNotFound
	}

	delete(lb.clusters, name)
	return nil
}

// ClusterOption 集群选项
type ClusterOption func(*Cluster)

// WithLBStrategy 设置负载均衡策略
func WithLBStrategy(s LBStrategy) ClusterOption {
	return func(c *Cluster) {
		c.strategy = s
	}
}

// WithLBHealthChecker 设置健康检查器
func WithLBHealthChecker(hc HealthCheckFunc) ClusterOption {
	return func(c *Cluster) {
		c.healthCheck = hc
	}
}

// WithLBStickyConfig 设置会话粘性
func WithLBStickyConfig(cfg StickyConfig) ClusterOption {
	return func(c *Cluster) {
		c.stickyConfig = cfg
	}
}

// AddBackend 添加后端
func (c *Cluster) AddBackend(addr string, port int, weight int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	b := &Backend{
		addr:   addr,
		port:   port,
		weight: weight,
	}
	b.healthy.Store(true)

	c.backends = append(c.backends, b)
}

// RemoveBackend 移除后端
func (c *Cluster) RemoveBackend(addr string, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, b := range c.backends {
		if b.addr == addr && b.port == port {
			c.backends = append(c.backends[:i], c.backends[i+1:]...)
			break
		}
	}
}

// SetBackendWeight 设置后端权重
func (c *Cluster) SetBackendWeight(addr string, port int, weight int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, b := range c.backends {
		if b.addr == addr && b.port == port {
			b.weight = weight
			break
		}
	}
}

// SetBackendHealthy 设置后端健康状态
func (c *Cluster) SetBackendHealthy(addr string, port int, healthy bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, b := range c.backends {
		if b.addr == addr && b.port == port {
			b.healthy.Store(healthy)
			break
		}
	}
}

// GetBackends 获取所有后端
func (c *Cluster) GetBackends() []*Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()

	backends := make([]*Backend, len(c.backends))
	copy(backends, c.backends)
	return backends
}

// SetStrategy 设置负载均衡策略
func (c *Cluster) SetStrategy(s LBStrategy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.strategy = s
}

// SetStickyConfig 设置会话粘性配置
func (c *Cluster) SetStickyConfig(cfg StickyConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stickyConfig = cfg
}

// Select 选择后端
func (c *Cluster) Select(ctx context.Context, req *Request) (*Backend, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.backends) == 0 {
		return nil, ErrNoBackends
	}

	// 过滤健康的后端
	healthyBackends := c.filterHealthyBackends()
	if len(healthyBackends) == 0 {
		return nil, ErrNoHealthyBackends
	}

	// 根据策略选择
	switch c.strategy {
	case LBStrategyRoundRobin:
		return c.selectRoundRobin(healthyBackends)
	case LBStrategyWeighted:
		return c.selectWeighted(healthyBackends)
	case LBStrategyLeastConn:
		return c.selectLeastConn(healthyBackends)
	case LBStrategyIPHash:
		return c.selectIPHash(req, healthyBackends)
	case LBStrategyURLHash:
		return c.selectURLHash(req, healthyBackends)
	case LBStrategyRandom:
		return c.selectRandom(healthyBackends)
	case LBStrategyConsistentHash:
		return c.selectConsistentHash(req, healthyBackends)
	case LBStrategyLatencyBased:
		return c.selectLatencyBased(healthyBackends)
	default:
		return c.selectRoundRobin(healthyBackends)
	}
}

// Request 请求信息
type Request struct {
	IP        net.IP
	URL       string
	Method    string
	Header    map[string]string
	Cookie    map[string]string
	UserAgent string
}

// filterHealthyBackends 过滤健康的后端
func (c *Cluster) filterHealthyBackends() []*Backend {
	backends := make([]*Backend, 0, len(c.backends))
	for _, b := range c.backends {
		if b.healthy.Load() {
			backends = append(backends, b)
		}
	}
	return backends
}

// selectRoundRobin 轮询选择
func (c *Cluster) selectRoundRobin(backends []*Backend) (*Backend, error) {
	idx := rand.Intn(len(backends))
	return backends[idx], nil
}

// selectWeighted 加权轮询
func (c *Cluster) selectWeighted(backends []*Backend) (*Backend, error) {
	totalWeight := 0
	for _, b := range backends {
		totalWeight += b.weight
	}

	if totalWeight == 0 {
		return backends[0], nil
	}

	randWeight := rand.Intn(totalWeight)
	curWeight := 0
	for _, b := range backends {
		curWeight += b.weight
		if randWeight < curWeight {
			return b, nil
		}
	}

	return backends[0], nil
}

// selectLeastConn 最少连接选择
func (c *Cluster) selectLeastConn(backends []*Backend) (*Backend, error) {
	minConn := int64(math.MaxInt64)
	var selected *Backend

	for _, b := range backends {
		conn := b.active.Load()
		if conn < minConn {
			minConn = conn
			selected = b
		}
	}

	return selected, nil
}

// selectIPHash IP哈希选择
func (c *Cluster) selectIPHash(req *Request, backends []*Backend) (*Backend, error) {
	ip := req.IP
	if ip == nil {
		ip = net.ParseIP("127.0.0.1")
	}

	hash := hashIP(ip)
	return backends[int(hash)%len(backends)], nil
}

// selectURLHash URL哈希选择
func (c *Cluster) selectURLHash(req *Request, backends []*Backend) (*Backend, error) {
	hash := hashString(req.URL)
	return backends[int(hash)%len(backends)], nil
}

// selectRandom 随机选择
func (c *Cluster) selectRandom(backends []*Backend) (*Backend, error) {
	return backends[rand.Intn(len(backends))], nil
}

// selectConsistentHash 一致性哈希选择
func (c *Cluster) selectConsistentHash(req *Request, backends []*Backend) (*Backend, error) {
	key := req.URL
	if key == "" {
		key = req.IP.String()
	}

	hash := hashString(key)
	// 简单实现：取模
	return backends[int(hash)%len(backends)], nil
}

// selectLatencyBased 延迟最低选择
func (c *Cluster) selectLatencyBased(backends []*Backend) (*Backend, error) {
	minLatency := float64(math.MaxFloat64)
	var selected *Backend

	for _, b := range backends {
		latency := b.latency
		if latency < minLatency && latency > 0 {
			minLatency = latency
			selected = b
		}
	}

	if selected == nil {
		return backends[0], nil
	}

	return selected, nil
}

// UpdateBackendLatency 更新后端延迟
func (c *Cluster) UpdateBackendLatency(addr string, port int, latency time.Duration) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, b := range c.backends {
		if b.addr == addr && b.port == port {
			b.latency = latency.Seconds()
			break
		}
	}
}

// UpdateBackendConns 更新后端连接数
func (c *Cluster) UpdateBackendConns(addr string, port int, delta int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, b := range c.backends {
		if b.addr == addr && b.port == port {
			b.active.Add(delta)
			break
		}
	}
}

// GetStats 获取集群统计
func (c *Cluster) GetStats() ClusterStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := ClusterStats{
		Name:    c.name,
		Backends: make([]BackendStats, 0, len(c.backends)),
	}

	totalWeight := 0
	totalActive := int64(0)
	for _, b := range c.backends {
		totalWeight += b.weight
		totalActive += b.active.Load()

		stats.Backends = append(stats.Backends, BackendStats{
			Addr:    b.addr,
			Port:    b.port,
			Weight:  b.weight,
			Healthy: b.healthy.Load(),
			Active:  b.active.Load(),
			Latency: b.latency,
		})
	}

	stats.TotalBackends = len(c.backends)
	stats.TotalWeight = totalWeight
	stats.TotalActive = totalActive

	return stats
}

// ClusterStats 集群统计
type ClusterStats struct {
	Name           string
	TotalBackends  int
	TotalWeight    int
	TotalActive    int64
	Backends       []BackendStats
}

// BackendStats 后端统计
type BackendStats struct {
	Addr    string
	Port    int
	Weight  int
	Healthy bool
	Active  int64
	Latency float64
}

// Addr 返回后端地址
func (b *Backend) Addr() string {
	return net.JoinHostPort(b.addr, itoa(b.port))
}

// hashIP IP地址哈希
func hashIP(ip net.IP) uint32 {
	h := fnv.New32a()
	h.Write(ip)
	return h.Sum32()
}

// hashString 字符串哈希
func hashString(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
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

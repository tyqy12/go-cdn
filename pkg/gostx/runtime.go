package gostx

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
)

// Runtime gost 嵌入式运行时
type Runtime struct {
	mu       sync.RWMutex
	handlers map[string]handler.Handler
	listeners map[string]listener.Listener
	logger    logger.Logger
	metrics   *MetricsAdapter
	options   RuntimeOptions
	closed    chan struct{}
	wg        sync.WaitGroup
	stats     runtimeStats
}

// runtimeStats 运行时统计
type runtimeStats struct {
	requestsTotal   float64
	requestsActive  int64
	errorsTotal     float64
	bytesIn         float64
	bytesOut        float64
	lastActivity    time.Time
	mu              sync.RWMutex
}

// RuntimeOptions 运行时选项
type RuntimeOptions struct {
	Logger        logger.Logger
	Metrics       *MetricsAdapter
	HandlerPrefix string
	AutoRegister  bool
}

// RuntimeOption 运行时配置选项
type RuntimeOption func(*RuntimeOptions)

// WithGOSTLogger 设置日志
func WithGOSTLogger(l logger.Logger) RuntimeOption {
	return func(o *RuntimeOptions) {
		o.Logger = l
	}
}

// WithGOSTMetrics 设置指标适配器
func WithGOSTMetrics(m *MetricsAdapter) RuntimeOption {
	return func(o *RuntimeOptions) {
		o.Metrics = m
	}
}

// WithHandlerPrefix 设置 handler 前缀
func WithHandlerPrefix(prefix string) RuntimeOption {
	return func(o *RuntimeOptions) {
		o.HandlerPrefix = prefix
	}
}

// WithAutoRegister 自动注册默认处理器
func WithAutoRegister(b bool) RuntimeOption {
	return func(o *RuntimeOptions) {
		o.AutoRegister = b
	}
}

// NewRuntime 创建运行时
func NewRuntime(opts ...RuntimeOption) *Runtime {
	options := RuntimeOptions{
		HandlerPrefix: "cdn",
		AutoRegister:  true,
	}

	for _, opt := range opts {
		opt(&options)
	}

	if options.Logger == nil {
		options.Logger = NewCDNLoggerAdapter()
	}

	if options.Metrics == nil {
		options.Metrics = NewMetricsAdapter()
	}

	r := &Runtime{
		handlers:  make(map[string]handler.Handler),
		listeners: make(map[string]listener.Listener),
		logger:    options.Logger,
		metrics:   options.Metrics,
		options:   options,
		closed:    make(chan struct{}),
	}

	return r
}

// RegisterHandler 注册处理器
func (r *Runtime) RegisterHandler(name string, h handler.Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[name] = h
	r.logger.Debugf("gostx: handler registered: %s", name)
}

// GetHandler 获取处理器
func (r *Runtime) GetHandler(name string) (handler.Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[name]
	return h, ok
}

// RegisterListener 注册监听器
func (r *Runtime) RegisterListener(name string, l listener.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners[name] = l
	r.logger.Debugf("gostx: listener registered: %s", name)
}

// GetListener 获取监听器
func (r *Runtime) GetListener(name string) (listener.Listener, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.listeners[name]
	return l, ok
}

// Start 启动运行时
func (r *Runtime) Start(ctx context.Context) error {
	r.logger.Info("gostx: runtime starting")
	r.wg.Add(1)
	go r.gc(ctx)
	r.logger.Info("gostx: runtime started")
	return nil
}

// Stop 停止运行时
func (r *Runtime) Stop() {
	r.logger.Info("gostx: runtime stopping")
	close(r.closed)
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.listeners {
		l.Close()
	}
	r.listeners = make(map[string]listener.Listener)
	r.logger.Info("gostx: runtime stopped")
}

// gc 垃圾回收
func (r *Runtime) gc(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.closed:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.cleanupIdleHandlers()
		}
	}
}

func (r *Runtime) cleanupIdleHandlers() {
	r.logger.Debug("gostx: cleanup idle handlers")
}

// GetStats 获取运行时统计
func (r *Runtime) GetStats() RuntimeStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.stats.mu.RLock()
	defer r.stats.mu.RUnlock()

	return RuntimeStats{
		HandlerCount:   len(r.handlers),
		ListenerCount:  len(r.listeners),
		RequestsTotal:  r.stats.requestsTotal,
		RequestsActive: atomic.LoadInt64(&r.stats.requestsActive),
		ErrorsTotal:    r.stats.errorsTotal,
		BytesIn:        r.stats.bytesIn,
		BytesOut:       r.stats.bytesOut,
	}
}

// recordRequest 记录请求
func (r *Runtime) recordRequest(success bool, bytesIn, bytesOut int64) {
	r.stats.mu.Lock()
	defer r.stats.mu.Unlock()

	r.stats.requestsTotal++
	if !success {
		r.stats.errorsTotal++
	}
	atomic.AddInt64(&r.stats.requestsActive, 1)
	r.stats.bytesIn += float64(bytesIn)
	r.stats.bytesOut += float64(bytesOut)
	r.stats.lastActivity = time.Now()

	// 更新指标
	r.metrics.Counter("requests_total", nil).Inc()
	if !success {
		r.metrics.Counter("errors_total", nil).Inc()
	}
	r.metrics.Gauge("requests_active", nil).Set(float64(atomic.LoadInt64(&r.stats.requestsActive)))
}

// RuntimeStats 运行时统计
type RuntimeStats struct {
	HandlerCount   int
	ListenerCount  int
	RequestsTotal  float64
	RequestsActive int64
	ErrorsTotal    float64
	BytesIn        float64
	BytesOut       float64
}

// ConnManager 连接管理器 - 桥接 gost 和 CDN 连接池
type ConnManager struct {
	pool        interface {
		Get(ctx context.Context, network, addr string) (net.Conn, error)
		Put(conn net.Conn)
	}
	activeConns int64
	logger      logger.Logger
	metrics     *MetricsAdapter
	options     ConnManagerOptions
}

// ConnManagerOptions 连接管理器选项
type ConnManagerOptions struct {
	MaxIdleConns    int
	MaxConnsPerAddr int
	IdleTimeout     int
}

// ConnManagerOption 连接管理器配置选项
type ConnManagerOption func(*ConnManagerOptions)

func WithMaxIdleConns(n int) ConnManagerOption {
	return func(o *ConnManagerOptions) {
		o.MaxIdleConns = n
	}
}

func WithMaxConnsPerAddr(n int) ConnManagerOption {
	return func(o *ConnManagerOptions) {
		o.MaxConnsPerAddr = n
	}
}

func WithIdleTimeout(seconds int) ConnManagerOption {
	return func(o *ConnManagerOptions) {
		o.IdleTimeout = seconds
	}
}

// NewConnManager 创建连接管理器
func NewConnManager(opts ...ConnManagerOption) *ConnManager {
	options := ConnManagerOptions{
		MaxIdleConns:    100,
		MaxConnsPerAddr: 1000,
		IdleTimeout:     90,
	}
	for _, opt := range opts {
		opt(&options)
	}
	return &ConnManager{
		logger:  NewCDNLoggerAdapter(),
		metrics: NewMetricsAdapter(),
		options: options,
	}
}

// SetPool 设置 CDN 连接池
func (cm *ConnManager) SetPool(pool interface {
	Get(ctx context.Context, network, addr string) (net.Conn, error)
	Put(conn net.Conn)
}) {
	cm.pool = pool
}

// SetLogger 设置日志
func (cm *ConnManager) SetLogger(l logger.Logger) {
	cm.logger = l
}

// SetMetrics 设置指标
func (cm *ConnManager) SetMetrics(m *MetricsAdapter) {
	cm.metrics = m
}

// Dial 拨号
func (cm *ConnManager) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	atomic.AddInt64(&cm.activeConns, 1)
	cm.metrics.Gauge("connections_active", nil).Inc()

	if cm.pool != nil {
		conn, err := cm.pool.Get(ctx, network, addr)
		if err == nil {
			return &connWrapper{Conn: conn, cm: cm, closed: false}, nil
		}
	}
	conn, err := net.Dial(network, addr)
	if err != nil {
		atomic.AddInt64(&cm.activeConns, -1)
		cm.metrics.Gauge("connections_active", nil).Dec()
		return nil, err
	}
	return &connWrapper{Conn: conn, cm: cm, closed: false}, nil
}

// GetStats 获取连接统计
func (cm *ConnManager) GetStats() ConnStats {
	return ConnStats{
		ActiveConns: atomic.LoadInt64(&cm.activeConns),
	}
}

// ConnStats 连接统计
type ConnStats struct {
	ActiveConns int64
}

// connWrapper 连接包装器
type connWrapper struct {
	net.Conn
	cm     *ConnManager
	closed bool
	mu     sync.Mutex
}

func (c *connWrapper) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	atomic.AddInt64(&c.cm.activeConns, -1)
	c.cm.metrics.Gauge("connections_active", nil).Dec()
	if c.cm.pool != nil {
		c.cm.pool.Put(c.Conn)
		return nil
	}
	return c.Conn.Close()
}

// LoadBalancer 简化的负载均衡器
type LoadBalancer struct {
	mu       sync.RWMutex
	nodes    []*Node
	strategy LBStrategy
	metrics  *MetricsAdapter
}

type LBStrategy string

const (
	StrategyRoundRobin LBStrategy = "round_robin"
	StrategyLeastConn  LBStrategy = "least_conn"
	StrategyIPHash     LBStrategy = "ip_hash"
)

type Node struct {
	Addr     string
	Port     int
	Weight   int
	Active   int64
	Healthy  bool
}

func NewLoadBalancer(strategy LBStrategy) *LoadBalancer {
	return &LoadBalancer{
		nodes:    make([]*Node, 0),
		strategy: strategy,
		metrics:  NewMetricsAdapter(),
	}
}

func (lb *LoadBalancer) AddNode(node *Node) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.nodes = append(lb.nodes, node)
}

func (lb *LoadBalancer) Select(clientIP net.IP) (*Node, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	if len(lb.nodes) == 0 {
		return nil, ErrNoNodes
	}
	healthyNodes := make([]*Node, 0)
	for _, n := range lb.nodes {
		if n.Healthy {
			healthyNodes = append(healthyNodes, n)
		}
	}
	if len(healthyNodes) == 0 {
		return lb.nodes[0], nil
	}
	var selected *Node
	switch lb.strategy {
	case StrategyRoundRobin:
		selected = healthyNodes[0]
	case StrategyLeastConn:
		minConn := healthyNodes[0]
		for _, n := range healthyNodes {
			if n.Active < minConn.Active {
				minConn = n
			}
		}
		selected = minConn
	case StrategyIPHash:
		if clientIP == nil {
			selected = healthyNodes[0]
		} else {
			selected = healthyNodes[int(clientIP[len(clientIP)-1])%len(healthyNodes)]
		}
	default:
		selected = healthyNodes[0]
	}
	if selected != nil {
		lb.metrics.Counter("node_selected", map[string]string{"node": selected.Addr}).Inc()
	}
	return selected, nil
}

var ErrNoNodes = &nodesError{msg: "no available nodes"}

type nodesError struct {
	msg string
}

func (e *nodesError) Error() string {
	return e.msg
}

// SimpleHandler 简单处理器实现
type SimpleHandler struct {
	logger  logger.Logger
	metrics *MetricsAdapter
}

func NewSimpleHandler() *SimpleHandler {
	return &SimpleHandler{
		logger:  NewCDNLoggerAdapter(),
		metrics: NewMetricsAdapter(),
	}
}

func (h *SimpleHandler) Init(md metadata.Metadata) error {
	return nil
}

func (h *SimpleHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	h.logger.Debugf("gostx: handling connection from %s", conn.RemoteAddr().String())
	h.metrics.Counter("handler_calls_total", nil).Inc()
	return nil
}

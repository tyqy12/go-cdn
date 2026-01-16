package health

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
)

// Checker 健康检查器
type Checker struct {
	mu            sync.RWMutex
	targets       map[string]*Target
	checkers      []HealthCheckerFunc
	interval      time.Duration
	timeout       time.Duration
	unhealthy     int
	healthyThresh int
	logger        logger.Logger
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// Target 健康检查目标
type Target struct {
	Addr        string
	Port        int
	Name        string
	Protocol    string
	Healthy     atomic.Bool
	LastCheck   time.Time
	LastSuccess time.Time
	LastFailure time.Time
	FailCount   int
	Latency     float64
	Metadata    map[string]interface{}
}

// HealthStatus 健康状态
type HealthStatus string

const (
	StatusUnknown   HealthStatus = "unknown"
	StatusHealthy   HealthStatus = "healthy"
	StatusUnhealthy HealthStatus = "unhealthy"
	StatusDegraded  HealthStatus = "degraded"
)

// CheckResult 检查结果
type CheckResult struct {
	Target    string
	Status    HealthStatus
	Latency   time.Duration
	Error     error
	Timestamp time.Time
}

// CheckerConfig 检查器配置
type CheckerConfig struct {
	Interval       time.Duration
	Timeout        time.Duration
	Unhealthy      int
	HealthyThresh  int
}

// HealthCheckerFunc 健康检查函数
type HealthCheckerFunc func(ctx context.Context, addr string) error

// NewChecker 创建健康检查器
func NewChecker(opts ...Option) *Checker {
	c := &Checker{
		targets:       make(map[string]*Target),
		checkers:      make([]HealthCheckerFunc, 0),
		interval:      10 * time.Second,
		timeout:       5 * time.Second,
		unhealthy:     3,
		healthyThresh: 2,
		logger:        logger.Default(),
		stopCh:        make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	// 默认添加 TCP 检查器
	c.checkers = append(c.checkers, TCPCheck)

	return c
}

// Option 选项
type Option func(*Checker)

// WithHCInterval 设置检查间隔
func WithHCInterval(d time.Duration) Option {
	return func(c *Checker) {
		c.interval = d
	}
}

// WithHCTimeout 设置超时时间
func WithHCTimeout(d time.Duration) Option {
	return func(c *Checker) {
		c.timeout = d
	}
}

// WithHCUnhealthyThreshold 设置不健康阈值
func WithHCUnhealthyThreshold(n int) Option {
	return func(c *Checker) {
		c.unhealthy = n
	}
}

// WithHCHealthyThreshold 设置健康阈值
func WithHCHealthyThreshold(n int) Option {
	return func(c *Checker) {
		c.healthyThresh = n
	}
}

// WithHCLogger 设置日志
func WithHCLogger(l logger.Logger) Option {
	return func(c *Checker) {
		c.logger = l
	}
}

// AddChecker 添加检查函数
func (c *Checker) AddChecker(checker HealthCheckerFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkers = append(c.checkers, checker)
}

// AddTarget 添加检查目标
func (c *Checker) AddTarget(name, addr string, port int, protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := generateTargetKey(addr, port)
	c.targets[key] = &Target{
		Addr:     addr,
		Port:     port,
		Name:     name,
		Protocol: protocol,
		Metadata: make(map[string]interface{}),
	}

	c.logger.Infof("health check target added: %s (%s:%d)", name, addr, port)
}

// RemoveTarget 移除检查目标
func (c *Checker) RemoveTarget(addr string, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := generateTargetKey(addr, port)
	delete(c.targets, key)

	c.logger.Infof("health check target removed: %s:%d", addr, port)
}

// Start 启动健康检查
func (c *Checker) Start(ctx context.Context) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run(ctx)
	}()

	c.logger.Info("health checker started")
}

// Stop 停止健康检查
func (c *Checker) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	c.logger.Info("health checker stopped")
}

// run 运行健康检查循环
func (c *Checker) run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkAll()
		}
	}
}

// checkAll 检查所有目标
func (c *Checker) checkAll() {
	c.mu.RLock()
	targets := make([]*Target, 0, len(c.targets))
	for _, t := range c.targets {
		targets = append(targets, t)
	}
	c.mu.RUnlock()

	for _, t := range targets {
		c.checkTarget(t)
	}
}

// checkTarget 检查单个目标
func (c *Checker) checkTarget(t *Target) {
	start := time.Now()

	addr := t.Addr + ":" + itoa(t.Port)
	var err error
	for _, checker := range c.checkers {
		err = checker(context.Background(), addr)
		if err == nil {
			break
		}
	}

	latency := time.Since(start)
	t.Latency = latency.Seconds()
	t.LastCheck = time.Now()

	if err != nil {
		t.LastFailure = time.Now()
		t.FailCount++
		t.Healthy.Store(false)

		c.logger.Warnf("health check failed for %s: %v (latency: %v)", addr, err, latency)
	} else {
		t.LastSuccess = time.Now()
		t.FailCount = 0
		t.Healthy.Store(true)

		c.logger.Debugf("health check passed for %s (latency: %v)", addr, latency)
	}
}

// GetStatus 获取目标状态
func (c *Checker) GetStatus(addr string, port int) (*CheckResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := generateTargetKey(addr, port)
	t, ok := c.targets[key]
	if !ok {
		return nil, ErrTargetNotFound
	}

	status := StatusHealthy
	if !t.Healthy.Load() {
		if t.FailCount >= c.unhealthy {
			status = StatusUnhealthy
		} else {
			status = StatusDegraded
		}
	}

	return &CheckResult{
		Target:    addr + ":" + itoa(port),
		Status:    status,
		Latency:   time.Duration(t.Latency * float64(time.Second)),
		Timestamp: t.LastCheck,
	}, nil
}

// GetAllStatus 获取所有目标状态
func (c *Checker) GetAllStatus() []*CheckResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	results := make([]*CheckResult, 0, len(c.targets))
	for _, t := range c.targets {
		addr := t.Addr + ":" + itoa(t.Port)
		status := StatusHealthy
		if !t.Healthy.Load() {
			if t.FailCount >= c.unhealthy {
				status = StatusUnhealthy
			} else {
				status = StatusDegraded
			}
		}

		results = append(results, &CheckResult{
			Target:    addr,
			Status:    status,
			Latency:   time.Duration(t.Latency * float64(time.Second)),
			Timestamp: t.LastCheck,
		})
	}

	return results
}

// IsHealthy 检查目标是否健康
func (c *Checker) IsHealthy(addr string, port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := generateTargetKey(addr, port)
	t, ok := c.targets[key]
	if !ok {
		return false
	}

	return t.Healthy.Load()
}

// generateTargetKey 生成目标键
func generateTargetKey(addr string, port int) string {
	return addr + ":" + itoa(port)
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

// TCPCheck TCP 健康检查
func TCPCheck(ctx context.Context, addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// HTTPCheck HTTP 健康检查
type HTTPCheck struct {
	path     string
	method   string
	headers  map[string]string
	statusOK []int
}

// NewHTTPCheck 创建 HTTP 检查器
func NewHTTPCheck(path string, opts ...HCOption) *HTTPCheck {
	h := &HTTPCheck{
		path:     path,
		method:   "GET",
		headers:  make(map[string]string),
		statusOK: []int{200},
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// HCOption HTTP 检查器选项
type HCOption func(*HTTPCheck)

// WithHTTPCheckTimeout 设置超时
func WithHTTPCheckTimeout(d time.Duration) HCOption {
	return func(h *HTTPCheck) {
		// 预留接口
	}
}

// WithHCMethod 设置方法
func WithHCMethod(m string) HCOption {
	return func(h *HTTPCheck) {
		h.method = m
	}
}

// WithHCHeaders 设置头
func WithHCHeaders(headers map[string]string) HCOption {
	return func(h *HTTPCheck) {
		h.headers = headers
	}
}

// WithHCStatus 设置期望状态码
func WithHCStatus(status []int) HCOption {
	return func(h *HTTPCheck) {
		h.statusOK = status
	}
}

// Check 执行 HTTP 检查
func (c *HTTPCheck) Check(ctx context.Context, addr string) error {
	url := "http://" + addr + c.path

	req, err := http.NewRequestWithContext(ctx, c.method, url, nil)
	if err != nil {
		return err
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for _, status := range c.statusOK {
		if resp.StatusCode == status {
			return nil
		}
	}

	return &HTTPStatusError{StatusCode: resp.StatusCode}
}

// HTTPStatusError HTTP 状态错误
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return "unexpected status code: " + itoa(e.StatusCode)
}

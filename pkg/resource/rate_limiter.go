package resource

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// RateLimiter 限流器
type RateLimiter struct {
	config      *RateLimitConfig
	limits      map[string]*UserLimit
	globalLimit *GlobalLimit
	mu          sync.RWMutex
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// 是否启用限流
	Enabled bool

	// 全局限流配置
	GlobalConfig *GlobalLimitConfig

	// 用户限流配置
	UserConfig *UserLimitConfig

	// 限流算法
	Algorithm RateLimitAlgorithm
}

// GlobalLimitConfig 全局限流配置
type GlobalLimitConfig struct {
	// 最大请求数/秒
	MaxRequestsPerSecond int64

	// 最大并发连接数
	MaxConcurrentConnections int64

	// 最大带宽（字节/秒）
	MaxBandwidth int64
}

// UserLimitConfig 用户限流配置
type UserLimitConfig struct {
	// 默认最大请求数/秒
	DefaultMaxRequestsPerSecond int64

	// 默认最大并发连接数
	DefaultMaxConcurrentConnections int64

	// 桶大小
	BucketSize int64

	// 补充速率
	RefillRate int64

	// 白名单用户
	Whitelist []string
}

// UserLimit 用户限流状态
type UserLimit struct {
	UserID        string
	Bucket        *TokenBucket
	ConnCount     int64
	LastUpdated   time.Time
	IsWhitelisted bool
	mu            sync.Mutex
}

// TokenBucket 令牌桶
type TokenBucket struct {
	capacity   int64
	tokens     int64
	refillRate int64
	lastRefill time.Time
	mu         sync.Mutex
}

// GlobalLimit 全局限流状态
type GlobalLimit struct {
	RequestCounter *SlidingWindow
	ConnCounter    int64
	BandwidthMeter *BandwidthMeter
	mu             sync.RWMutex
}

// SlidingWindow 滑动窗口
type SlidingWindow struct {
	windowSize  time.Duration
	granularity time.Duration
	buckets     map[int64]*WindowBucket
	mu          sync.RWMutex
}

// WindowBucket 窗口桶
type WindowBucket struct {
	Count     int64
	StartTime time.Time
}

// BandwidthMeter 带宽计量器
type BandwidthMeter struct {
	bytesIn  int64
	bytesOut int64
	window   time.Duration
	mu       sync.Mutex
}

// RateLimitAlgorithm 限流算法
type RateLimitAlgorithm string

const (
	RateLimitAlgorithmTokenBucket   RateLimitAlgorithm = "token_bucket"
	RateLimitAlgorithmSlidingWindow RateLimitAlgorithm = "sliding_window"
	RateLimitAlgorithmLeakyBucket   RateLimitAlgorithm = "leaky_bucket"
)

// RateLimitResult 限流结果
type RateLimitResult struct {
	Allowed   bool
	Reason    string
	Remaining int64
	ResetAt   time.Time
	Metadata  map[string]interface{}
}

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	config       *CircuitBreakerConfig
	state        CircuitState
	failCount    int64
	successCount int64
	lastFailTime time.Time
	lastSuccess  time.Time
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// CircuitBreakerConfig 熔断器配置
type CircuitBreakerConfig struct {
	// 名称
	Name string

	// 失败阈值
	FailureThreshold int64

	// 成功阈值
	SuccessThreshold int64

	// 失败百分比阈值
	FailureRateThreshold float64

	// 半开状态最大尝试次数
	MaxHalfOpenRequests int64

	// 超时时间
	Timeout time.Duration

	// 滑动窗口大小
	WindowSize time.Duration

	// 最小请求数
	MinRequests int64
}

// CircuitState 熔断状态
type CircuitState string

const (
	CircuitStateClosed   CircuitState = "closed"
	CircuitStateOpen     CircuitState = "open"
	CircuitStateHalfOpen CircuitState = "half_open"
)

// CircuitBreakerResult 熔断器结果
type CircuitBreakerResult struct {
	Allowed    bool
	State      CircuitState
	Reason     string
	RetryAfter time.Duration
}

// DefaultRateLimitConfig 默认限流配置
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled: true,
		GlobalConfig: &GlobalLimitConfig{
			MaxRequestsPerSecond:     100000,
			MaxConcurrentConnections: 100000,
			MaxBandwidth:             10 * 1024 * 1024 * 1024, // 10Gbps
		},
		UserConfig: &UserLimitConfig{
			DefaultMaxRequestsPerSecond:     1000,
			DefaultMaxConcurrentConnections: 100,
			BucketSize:                      1000,
			RefillRate:                      100,
			Whitelist:                       []string{},
		},
		Algorithm: RateLimitAlgorithmTokenBucket,
	}
}

// DefaultCircuitBreakerConfig 默认熔断器配置
func DefaultCircuitBreakerConfig(name string) *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		Name:                 name,
		FailureThreshold:     10,
		SuccessThreshold:     5,
		FailureRateThreshold: 0.5,
		MaxHalfOpenRequests:  3,
		Timeout:              30 * time.Second,
		WindowSize:           60 * time.Second,
		MinRequests:          10,
	}
}

// NewRateLimiter 创建限流器
func NewRateLimiter(cfg *RateLimitConfig) *RateLimiter {
	if cfg == nil {
		cfg = DefaultRateLimitConfig()
	}

	return &RateLimiter{
		config:      cfg,
		limits:      make(map[string]*UserLimit),
		globalLimit: NewGlobalLimit(cfg.GlobalConfig),
		stopCh:      make(chan struct{}),
	}
}

// NewGlobalLimit 创建全局限流状态
func NewGlobalLimit(cfg *GlobalLimitConfig) *GlobalLimit {
	return &GlobalLimit{
		RequestCounter: NewSlidingWindow(1*time.Second, 100*time.Millisecond),
		ConnCounter:    0,
		BandwidthMeter: NewBandwidthMeter(1 * time.Second),
	}
}

// NewSlidingWindow 创建滑动窗口
func NewSlidingWindow(windowSize, granularity time.Duration) *SlidingWindow {
	return &SlidingWindow{
		windowSize:  windowSize,
		granularity: granularity,
		buckets:     make(map[int64]*WindowBucket),
	}
}

// NewBandwidthMeter 创建带宽计量器
func NewBandwidthMeter(window time.Duration) *BandwidthMeter {
	return &BandwidthMeter{
		bytesIn:  0,
		bytesOut: 0,
		window:   window,
	}
}

// NewTokenBucket 创建令牌桶
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Start 启动限流器
func (l *RateLimiter) Start() {
	if !l.config.Enabled {
		log.Println("Rate limiter is disabled")
		return
	}

	// 启动全局计数器重置协程
	l.wg.Add(1)
	go l.runGlobalReset()

	log.Println("Rate limiter started")
}

// Stop 停止限流器
func (l *RateLimiter) Stop() {
	close(l.stopCh)
	l.wg.Wait()

	log.Println("Rate limiter stopped")
}

// runGlobalReset 运行全局重置
func (l *RateLimiter) runGlobalReset() {
	defer l.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.globalLimit.RequestCounter.ResetOldBuckets()
		}
	}
}

// Allow 检查是否允许请求
func (l *RateLimiter) Allow(userID string, tokens int64) *RateLimitResult {
	// 检查白名单
	if l.isWhitelisted(userID) {
		return &RateLimitResult{
			Allowed:   true,
			Reason:    "白名单用户",
			Remaining: -1,
		}
	}

	// 检查全局限流
	globalResult := l.checkGlobalLimit()
	if !globalResult.Allowed {
		return globalResult
	}

	// 检查用户限流
	return l.checkUserLimit(userID, tokens)
}

// checkGlobalLimit 检查全局限流
func (l *RateLimiter) checkGlobalLimit() *RateLimitResult {
	l.globalLimit.mu.RLock()
	defer l.globalLimit.mu.RUnlock()

	// 检查请求率
	count := l.globalLimit.RequestCounter.Increment()
	if count > l.config.GlobalConfig.MaxRequestsPerSecond {
		return &RateLimitResult{
			Allowed:   false,
			Reason:    "全局请求率超过限制",
			Remaining: l.config.GlobalConfig.MaxRequestsPerSecond - count,
		}
	}

	// 检查并发连接数
	if l.globalLimit.ConnCounter >= l.config.GlobalConfig.MaxConcurrentConnections {
		return &RateLimitResult{
			Allowed:   false,
			Reason:    "全局连接数超过限制",
			Remaining: l.config.GlobalConfig.MaxConcurrentConnections - l.globalLimit.ConnCounter,
		}
	}

	return &RateLimitResult{
		Allowed:   true,
		Remaining: l.config.GlobalConfig.MaxRequestsPerSecond - count,
	}
}

// checkUserLimit 检查用户限流
func (l *RateLimiter) checkUserLimit(userID string, tokens int64) *RateLimitResult {
	l.mu.RLock()
	limit := l.limits[userID]
	l.mu.RUnlock()

	if limit == nil {
		limit = l.createUserLimit(userID)
	}

	// 检查连接数
	if limit.ConnCount >= l.config.UserConfig.DefaultMaxConcurrentConnections {
		return &RateLimitResult{
			Allowed:   false,
			Reason:    "用户并发连接数超过限制",
			Remaining: l.config.UserConfig.DefaultMaxConcurrentConnections - limit.ConnCount,
		}
	}

	// 检查令牌桶
	if !limit.Bucket.TryConsume(tokens) {
		return &RateLimitResult{
			Allowed:   false,
			Reason:    "令牌桶已空",
			Remaining: limit.Bucket.Tokens(),
		}
	}

	return &RateLimitResult{
		Allowed:   true,
		Remaining: limit.Bucket.Tokens(),
	}
}

// isWhitelisted 检查是否在白名单
func (l *RateLimiter) isWhitelisted(userID string) bool {
	for _, whitelisted := range l.config.UserConfig.Whitelist {
		if userID == whitelisted {
			return true
		}
	}
	return false
}

// createUserLimit 创建用户限流状态
func (l *RateLimiter) createUserLimit(userID string) *UserLimit {
	limit := &UserLimit{
		UserID:        userID,
		Bucket:        NewTokenBucket(l.config.UserConfig.BucketSize, l.config.UserConfig.RefillRate),
		ConnCount:     0,
		IsWhitelisted: false,
	}

	l.mu.Lock()
	l.limits[userID] = limit
	l.mu.Unlock()

	return limit
}

// AddConnection 增加连接数
func (l *RateLimiter) AddConnection(userID string) bool {
	l.mu.RLock()
	limit := l.limits[userID]
	l.mu.RUnlock()

	if limit == nil {
		limit = l.createUserLimit(userID)
	}

	limit.mu.Lock()
	defer limit.mu.Unlock()

	if limit.ConnCount >= l.config.UserConfig.DefaultMaxConcurrentConnections {
		return false
	}

	limit.ConnCount++
	l.globalLimit.mu.Lock()
	l.globalLimit.ConnCounter++
	l.globalLimit.mu.Unlock()

	return true
}

// RemoveConnection 减少连接数
func (l *RateLimiter) RemoveConnection(userID string) {
	l.mu.RLock()
	limit := l.limits[userID]
	l.mu.RUnlock()

	if limit != nil {
		limit.mu.Lock()
		if limit.ConnCount > 0 {
			limit.ConnCount--
		}
		limit.mu.Unlock()

		l.globalLimit.mu.Lock()
		if l.globalLimit.ConnCounter > 0 {
			l.globalLimit.ConnCounter--
		}
		l.globalLimit.mu.Unlock()
	}
}

// NewCircuitBreaker 创建熔断器
func NewCircuitBreaker(cfg *CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config:       cfg,
		state:        CircuitStateClosed,
		failCount:    0,
		successCount: 0,
		lastFailTime: time.Now(),
		lastSuccess:  time.Now(),
		stopCh:       make(chan struct{}),
	}
}

// Start 启动熔断器
func (c *CircuitBreaker) Start() {
	c.wg.Add(1)
	go c.runStateManager()

	log.Printf("Circuit breaker %s started", c.config.Name)
}

// Stop 停止熔断器
func (c *CircuitBreaker) Stop() {
	close(c.stopCh)
	c.wg.Wait()

	log.Printf("Circuit breaker %s stopped", c.config.Name)
}

// runStateManager 运行状态管理器
func (c *CircuitBreaker) runStateManager() {
	defer c.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.updateState()
		}
	}
}

// updateState 更新状态
func (c *CircuitBreaker) updateState() {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case CircuitStateOpen:
		// 检查是否超时
		if time.Since(c.lastFailTime) > c.config.Timeout {
			c.state = CircuitStateHalfOpen
			c.failCount = 0
			c.successCount = 0
		}
	case CircuitStateHalfOpen:
		// 允许少量请求通过
		// 状态转换逻辑在RecordResult中处理
	}
}

// Execute 执行请求
func (c *CircuitBreaker) Execute(req func() error) *CircuitBreakerResult {
	// 检查状态
	state := c.getState()
	if state == CircuitStateOpen {
		return &CircuitBreakerResult{
			Allowed:    false,
			State:      CircuitStateOpen,
			Reason:     "熔断器已开启",
			RetryAfter: c.getRetryAfter(),
		}
	}

	// 执行请求
	err := req()

	// 记录结果
	c.recordResult(err)

	// 返回结果
	if err != nil {
		return &CircuitBreakerResult{
			Allowed: false,
			State:   c.getState(),
			Reason:  fmt.Sprintf("请求失败: %v", err),
		}
	}

	return &CircuitBreakerResult{
		Allowed: true,
		State:   c.getState(),
		Reason:  "请求成功",
	}
}

// getState 获取当前状态
func (c *CircuitBreaker) getState() CircuitState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// recordResult 记录结果
func (c *CircuitBreaker) recordResult(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		c.failCount++
		c.lastFailTime = time.Now()

		// 检查是否需要开启熔断
		if c.shouldOpen() {
			c.state = CircuitStateOpen
		}
	} else {
		c.successCount++
		c.lastSuccess = time.Now()

		// 半开状态下成功，检查是否需要关闭熔断
		if c.state == CircuitStateHalfOpen {
			if c.successCount >= c.config.SuccessThreshold {
				c.state = CircuitStateClosed
				c.failCount = 0
				c.successCount = 0
			}
		}
	}
}

// shouldOpen 判断是否应该开启熔断
func (c *CircuitBreaker) shouldOpen() bool {
	// 检查失败次数
	if c.failCount >= c.config.FailureThreshold {
		return true
	}

	return false
}

// getRetryAfter 获取重试等待时间
func (c *CircuitBreaker) getRetryAfter() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.config.Timeout - time.Since(c.lastFailTime)
}

// GetState 获取熔断器状态
func (c *CircuitBreaker) GetState() *CircuitBreakerStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return &CircuitBreakerStatus{
		Name:         c.config.Name,
		State:        c.state,
		FailCount:    c.failCount,
		SuccessCount: c.successCount,
		LastFailTime: c.lastFailTime,
		LastSuccess:  c.lastSuccess,
	}
}

// CircuitBreakerStatus 熔断器状态
type CircuitBreakerStatus struct {
	Name         string
	State        CircuitState
	FailCount    int64
	SuccessCount int64
	LastFailTime time.Time
	LastSuccess  time.Time
}

// TokenBucket methods

// TryConsume 尝试消费令牌
func (b *TokenBucket) TryConsume(tokens int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 补充令牌
	b.refill()

	if b.tokens >= tokens {
		b.tokens -= tokens
		return true
	}

	return false
}

// Tokens 获取当前令牌数
func (b *TokenBucket) Tokens() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()
	return b.tokens
}

// refill 补充令牌
func (b *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill)

	if elapsed > 0 {
		toAdd := int64(elapsed.Seconds()) * b.refillRate
		if toAdd > 0 {
			b.tokens += toAdd
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
		}
		b.lastRefill = now
	}
}

// SlidingWindow methods

// Increment 增加计数
func (w *SlidingWindow) Increment() int64 {
	now := time.Now()
	bucketIndex := w.getBucketIndex(now)

	w.mu.Lock()
	defer w.mu.Unlock()

	// 创建新桶
	if w.buckets[bucketIndex] == nil {
		w.buckets[bucketIndex] = &WindowBucket{
			Count:     0,
			StartTime: now,
		}
	}

	w.buckets[bucketIndex].Count++
	return w.getTotalCount()
}

// getBucketIndex 获取桶索引
func (w *SlidingWindow) getBucketIndex(t time.Time) int64 {
	return t.UnixNano() / int64(w.granularity)
}

// getTotalCount 获取总计数
func (w *SlidingWindow) getTotalCount() int64 {
	now := time.Now()
	cutoff := now.Add(-w.windowSize)

	total := int64(0)
	for _, bucket := range w.buckets {
		if bucket.StartTime.After(cutoff) {
			total += bucket.Count
		}
	}

	return total
}

// ResetOldBuckets 重置旧桶
func (w *SlidingWindow) ResetOldBuckets() {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-w.windowSize)

	for index, bucket := range w.buckets {
		if bucket.StartTime.Before(cutoff) {
			delete(w.buckets, index)
		}
	}
}

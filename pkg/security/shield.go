package security

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// FiveSecondShield 5秒盾 - 访问频率限制
type FiveSecondShield struct {
	config     *ShieldConfig
	visitorMap map[string]*VisitorInfo
	whiteList  map[string]bool
	blackList  map[string]bool
	mu         sync.RWMutex
	stats      *ShieldStats
	ctx        context.Context
	cancel     context.CancelFunc
	running    bool
	runningMu  sync.Mutex
}

// ShieldConfig 5秒盾配置
type ShieldConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 限制时间窗口
	WindowSize time.Duration `yaml:"window_size"` // 默认5秒

	// 窗口内最大请求数
	MaxRequests int `yaml:"max_requests"` // 默认10

	// 触发限制后的封锁时间
	BlockDuration time.Duration `yaml:"block_duration"` // 默认60秒

	// 限流算法
	Algorithm string `yaml:"algorithm"` // "token_bucket", "sliding_window"

	// 白名单
	WhiteList []string `yaml:"white_list"`

	// 黑名单
	BlackList []string `yaml:"black_list"`

	// 验证方式
	VerificationType string `yaml:"verification_type"` // "cookie", "captcha", "js"

	// 严格模式（更严格的限制）
	StrictMode bool `yaml:"strict_mode"`
}

// VisitorInfo 访客信息
type VisitorInfo struct {
	IP           string    `json:"ip"`
	RequestCount int       `json:"request_count"`
	FirstRequest time.Time `json:"first_request"`
	LastRequest  time.Time `json:"last_request"`
	Blocked      bool      `json:"blocked"`
	BlockExpiry  time.Time `json:"block_expiry"`
	UserAgent    string    `json:"user_agent"`
	Referer      string    `json:"referer"`
}

// ShieldStats 防护统计
type ShieldStats struct {
	TotalRequests       int64 `json:"total_requests"`
	AllowedRequests     int64 `json:"allowed_requests"`
	BlockedRequests     int64 `json:"blocked_requests"`
	WhiteListedRequests int64 `json:"white_listed_requests"`
	CurrentBlocked      int64 `json:"current_blocked"`
	TotalBlockedIPs     int64 `json:"total_blocked_ips"`
	mu                  sync.RWMutex
}

// NewFiveSecondShield 创建5秒盾
func NewFiveSecondShield(config *ShieldConfig) *FiveSecondShield {
	if config == nil {
		config = &ShieldConfig{
			Enabled:       true,
			WindowSize:    5 * time.Second,
			MaxRequests:   10,
			BlockDuration: 60 * time.Second,
			Algorithm:     "sliding_window",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	shield := &FiveSecondShield{
		config:     config,
		visitorMap: make(map[string]*VisitorInfo),
		whiteList:  make(map[string]bool),
		blackList:  make(map[string]bool),
		stats:      &ShieldStats{},
		ctx:        ctx,
		cancel:     cancel,
		running:    false,
	}

	// 加载白名单和黑名单
	for _, ip := range config.WhiteList {
		shield.whiteList[ip] = true
	}
	for _, ip := range config.BlackList {
		shield.blackList[ip] = true
	}

	// 启动清理过期数据协程
	shield.Start()

	return shield
}

// Start 启动后台清理任务
func (s *FiveSecondShield) Start() {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()

	if s.running {
		return
	}

	s.running = true
	go s.cleanupExpired()
}

// Stop 停止后台清理任务
func (s *FiveSecondShield) Stop() {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	s.cancel()
}

// CheckRequest 检查请求是否允许
func (s *FiveSecondShield) CheckRequest(ip, userAgent, referer string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 使用 atomic 更新总请求数
	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// 检查白名单
	if s.whiteList[ip] {
		atomic.AddInt64(&s.stats.WhiteListedRequests, 1)
		return true, ""
	}

	// 检查黑名单
	if s.blackList[ip] {
		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		return false, "IP在黑名单中"
	}

	// 检查是否被封锁
	visitor, exists := s.visitorMap[ip]
	if exists {
		if visitor.Blocked && time.Now().Before(visitor.BlockExpiry) {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			atomic.AddInt64(&s.stats.CurrentBlocked, 1)
			return false, "请求过于频繁，请稍后再试"
		}

		// 解除封锁
		if visitor.Blocked && time.Now().After(visitor.BlockExpiry) {
			visitor.Blocked = false
			visitor.RequestCount = 0
		}
	}

	// 更新访客信息
	if !exists {
		visitor = &VisitorInfo{
			IP:           ip,
			RequestCount: 0,
			FirstRequest: time.Now(),
			UserAgent:    userAgent,
			Referer:      referer,
		}
		s.visitorMap[ip] = visitor
	}

	visitor.LastRequest = time.Now()
	visitor.RequestCount++

	// 检查是否超出限制
	windowStart := time.Now().Add(-s.config.WindowSize)

	switch s.config.Algorithm {
	case "token_bucket":
		return s.checkTokenBucket(visitor, windowStart)
	case "sliding_window":
		return s.checkSlidingWindow(visitor, windowStart)
	default:
		return s.checkSlidingWindow(visitor, windowStart)
	}
}

// checkTokenBucket Token Bucket算法
func (s *FiveSecondShield) checkTokenBucket(visitor *VisitorInfo, windowStart time.Time) (bool, string) {
	// 简单实现：检查窗口内的请求数
	if visitor.RequestCount > s.config.MaxRequests {
		s.blockVisitor(visitor)
		return false, "请求过于频繁"
	}
	return true, ""
}

// checkSlidingWindow 滑动窗口算法
func (s *FiveSecondShield) checkSlidingWindow(visitor *VisitorInfo, windowStart time.Time) (bool, string) {
	// 如果首次请求在窗口外，重置计数
	if visitor.FirstRequest.Before(windowStart) {
		visitor.RequestCount = 1
		visitor.FirstRequest = time.Now()
		return true, ""
	}

	if visitor.RequestCount > s.config.MaxRequests {
		s.blockVisitor(visitor)
		return false, "请求过于频繁，请5秒后再试"
	}

	// 使用 atomic 更新允许请求数
	atomic.AddInt64(&s.stats.AllowedRequests, 1)

	return true, ""
}

// blockVisitor 封锁访客
func (s *FiveSecondShield) blockVisitor(visitor *VisitorInfo) {
	visitor.Blocked = true
	visitor.BlockExpiry = time.Now().Add(s.config.BlockDuration)

	// 使用 atomic 更新统计
	atomic.AddInt64(&s.stats.BlockedRequests, 1)
	atomic.AddInt64(&s.stats.CurrentBlocked, 1)
	atomic.AddInt64(&s.stats.TotalBlockedIPs, 1)
}

// cleanupExpired 清理过期数据
func (s *FiveSecondShield) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// 执行最后一次清理
			s.doCleanup()
			return
		case <-ticker.C:
			s.doCleanup()
		}
	}
}

// doCleanup 执行实际的清理操作
func (s *FiveSecondShield) doCleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for ip, visitor := range s.visitorMap {
		// 清理超过24小时无活动的访客
		if now.Sub(visitor.LastRequest) > 24*time.Hour {
			delete(s.visitorMap, ip)
		}

		// 清理已过期的封锁
		if visitor.Blocked && now.After(visitor.BlockExpiry) {
			visitor.Blocked = false
			visitor.RequestCount = 0
		}
	}
}

// GetStats 获取统计信息
func (s *FiveSecondShield) GetStats() *ShieldStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return s.stats
}

// AddToWhiteList 添加到白名单
func (s *FiveSecondShield) AddToWhiteList(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.whiteList[ip] = true
	delete(s.visitorMap, ip)
}

// AddToBlackList 添加到黑名单
func (s *FiveSecondShield) AddToBlackList(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blackList[ip] = true
}

// GetBlockedIPs 获取被封锁的IP列表
func (s *FiveSecondShield) GetBlockedIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blocked := make([]string, 0)
	for ip, visitor := range s.visitorMap {
		if visitor.Blocked {
			blocked = append(blocked, ip)
		}
	}
	return blocked
}

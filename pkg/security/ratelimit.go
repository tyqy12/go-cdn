package security

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter 限流器
type RateLimiter struct {
	mu          sync.RWMutex
	rules       map[string]*RateRule
	windows     map[string]*SlidingWindow
	stats       RateLimiterStats
	logger      Logger
}

// RateRule 限流规则
type RateRule struct {
	Name            string
	Pattern         string // 匹配模式: ip, path, header:User-Agent
	Threshold       int64  // 阈值
	Window          time.Duration // 窗口时间
	Action          RateAction    // 触发动作
	Burst           int64          // 突发容量
	Enabled         bool
	CreatedAt       time.Time
}

// SlidingWindow 滑动窗口
type SlidingWindow struct {
	requests    []time.Time
	windowSize  time.Duration
	mu          sync.Mutex
}

// RateAction 限流动作
type RateAction string

const (
	RateActionBlock    RateAction = "block"     // 阻止
	RateActionRateLimit RateAction = "rate_limit" // 限速
	RateActionChallenge RateAction = "challenge" // 挑战验证
	RateActionLog      RateAction = "log"       // 仅记录
)

// RateLimiterStats 限流统计
type RateLimiterStats struct {
	TotalRequests   int64
	TotalBlocked    int64
	TotalLimited    int64
	TotalChallenged int64
	ActiveRules     int
	mu              sync.RWMutex
}

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// NewRateLimiter 创建限流器
func NewRateLimiter(opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		rules:   make(map[string]*RateRule),
		windows: make(map[string]*SlidingWindow),
		logger:  &DefaultLogger{},
	}

	for _, opt := range opts {
		opt(rl)
	}

	return rl
}

// RateLimiterOption 限流器选项
type RateLimiterOption func(*RateLimiter)

// WithRateLimiterLogger 设置日志
func WithRateLimiterLogger(l Logger) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.logger = l
	}
}

// AddRule 添加规则
func (rl *RateLimiter) AddRule(rule *RateRule) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rule.CreatedAt = time.Now()
	rl.rules[rule.Name] = rule
	rl.stats.ActiveRules = len(rl.rules)
}

// RemoveRule 移除规则
func (rl *RateLimiter) RemoveRule(name string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.rules, name)
	delete(rl.windows, name)
	rl.stats.ActiveRules = len(rl.rules)
}

// Check 检查请求是否被限流
func (rl *RateLimiter) Check(ctx context.Context, key string) (bool, RateAction) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	atomic.AddInt64(&rl.stats.TotalRequests, 1)

	for _, rule := range rl.rules {
		if !rule.Enabled {
			continue
		}

		if rl.matchRule(key, rule) {
			count := rl.countRequests(key, rule)
			if count >= rule.Threshold {
				// 触发限流
				rl.updateStats(rule.Action)
				rl.logger.Warnf("rate_limit: key=%s rule=%s count=%d threshold=%d action=%s",
					key, rule.Name, count, rule.Threshold, rule.Action)
				return true, rule.Action
			}
		}
	}

	return false, ""
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(key string) bool {
	blocked, _ := rl.Check(context.Background(), key)
	return !blocked
}

// Increment 递增计数器
func (rl *RateLimiter) Increment(key string, rule *RateRule) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	windowKey := key + ":" + rule.Name

	window, ok := rl.windows[windowKey]
	if !ok {
		window = &SlidingWindow{
			windowSize: rule.Window,
		}
		rl.windows[windowKey] = window
	}

	window.mu.Lock()
	defer window.mu.Unlock()

	now := time.Now()
	window.requests = append(window.requests, now)
}

// matchRule 匹配规则
func (rl *RateLimiter) matchRule(key string, rule *RateRule) bool {
	switch rule.Pattern {
	case "ip":
		return true // IP 匹配由调用者保证
	case "path":
		return true // Path 匹配由调用者保证
	default:
		return key == rule.Pattern
	}
}

// countRequests 统计请求数
func (rl *RateLimiter) countRequests(key string, rule *RateRule) int64 {
	windowKey := key + ":" + rule.Name

	rl.mu.Lock()
	defer rl.mu.Unlock()

	window, ok := rl.windows[windowKey]
	if !ok {
		return 0
	}

	window.mu.Lock()
	defer window.mu.Unlock()

	// 清理过期请求
	cutoff := time.Now().Add(-rule.Window)
	valid := make([]time.Time, 0, len(window.requests))
	for _, t := range window.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	window.requests = valid

	return int64(len(window.requests))
}

// updateStats 更新统计
func (rl *RateLimiter) updateStats(action RateAction) {
	rl.stats.mu.Lock()
	defer rl.stats.mu.Unlock()

	switch action {
	case RateActionBlock:
		rl.stats.TotalBlocked++
	case RateActionRateLimit:
		rl.stats.TotalLimited++
	case RateActionChallenge:
		rl.stats.TotalChallenged++
	}
}

// GetStats 获取统计
func (rl *RateLimiter) GetStats() RateLimiterStats {
	rl.stats.mu.RLock()
	defer rl.stats.mu.RUnlock()

	return RateLimiterStats{
		TotalRequests:   atomic.LoadInt64(&rl.stats.TotalRequests),
		TotalBlocked:    atomic.LoadInt64(&rl.stats.TotalBlocked),
		TotalLimited:    atomic.LoadInt64(&rl.stats.TotalLimited),
		TotalChallenged: atomic.LoadInt64(&rl.stats.TotalChallenged),
		ActiveRules:     rl.stats.ActiveRules,
	}
}

// GetRules 获取所有规则
func (rl *RateLimiter) GetRules() []*RateRule {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	rules := make([]*RateRule, 0, len(rl.rules))
	for _, rule := range rl.rules {
		rules = append(rules, rule)
	}
	return rules
}

// Reset 重置限流器
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.rules = make(map[string]*RateRule)
	rl.windows = make(map[string]*SlidingWindow)
	rl.stats = RateLimiterStats{}
}

// ConnectionLimiter 连接限流器
type ConnectionLimiter struct {
	mu           sync.RWMutex
	connections  map[string]int64
	maxPerIP     int64
	maxTotal     int64
	totalConns   int64
	logger       Logger
}

// NewConnectionLimiter 创建连接限流器
func NewConnectionLimiter(maxPerIP, maxTotal int64) *ConnectionLimiter {
	return &ConnectionLimiter{
		connections: make(map[string]int64),
		maxPerIP:    maxPerIP,
		maxTotal:    maxTotal,
		logger:      &DefaultLogger{},
	}
}

// Allow 检查是否允许新连接
func (cl *ConnectionLimiter) Allow(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// 检查总连接数
	if cl.totalConns >= cl.maxTotal {
		cl.logger.Warnf("connection_limit: total connections reached limit %d", cl.maxTotal)
		return false
	}

	// 检查单 IP 连接数
	current := cl.connections[ip]
	if current >= cl.maxPerIP {
		cl.logger.Warnf("connection_limit: IP %s reached limit %d", ip, cl.maxPerIP)
		return false
	}

	// 增加连接数
	cl.connections[ip] = current + 1
	cl.totalConns++

	return true
}

// Release 释放连接
func (cl *ConnectionLimiter) Release(ip string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	current := cl.connections[ip]
	if current > 0 {
		cl.connections[ip] = current - 1
		cl.totalConns--
	}
}

// GetIPCount 获取 IP 连接数
func (cl *ConnectionLimiter) GetIPCount(ip string) int64 {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.connections[ip]
}

// GetTotalCount 获取总连接数
func (cl *ConnectionLimiter) GetTotalCount() int64 {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.totalConns
}

// Reset 重置连接计数
func (cl *ConnectionLimiter) Reset() {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	cl.connections = make(map[string]int64)
	cl.totalConns = 0
}

// DefaultLogger 默认日志实现
type DefaultLogger struct{}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {}
func (l *DefaultLogger) Infof(format string, args ...interface{})  {}
func (l *DefaultLogger) Warnf(format string, args ...interface{})  {}
func (l *DefaultLogger) Errorf(format string, args ...interface{}) {}

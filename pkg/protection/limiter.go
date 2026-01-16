package protection

import (
	"sync"
	"time"
)

// RateLimiter 令牌桶限流器
type RateLimiter struct {
	maxTokens  int
	tokens     int
	mu         sync.Mutex
	refillRate time.Duration
	lastRefill time.Time
}

// NewRateLimiter 创建限流器
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		maxTokens:  rate,
		tokens:     rate,
		refillRate: window / time.Duration(rate),
		lastRefill: time.Now(),
	}
}

// Allow 检查是否允许通过
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	if elapsed >= rl.refillRate {
		tokensToAdd := int(elapsed / rl.refillRate)
		rl.tokens += tokensToAdd
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// Reset 重置限流器
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.tokens = rl.maxTokens
	rl.lastRefill = time.Now()
}

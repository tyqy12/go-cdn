package security

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/pkg/config"
)

// OriginProtector 源站保护器
type OriginProtector struct {
	config *config.OriginProtectionConfig
	rules  []*OriginProtectionRule
	mu     sync.RWMutex
	cache  *OriginAccessCache
	logger Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// OriginProtectionRule 源站保护规则
type OriginProtectionRule struct {
	ID          string
	Type        string
	IPRange     *net.IPNet
	Action      string
	Priority    int
	Enabled     bool
	CreatedAt   time.Time
	LastUpdated time.Time
}

// OriginAccessCache 访问缓存
type OriginAccessCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Allowed     bool
	ExpiresAt   time.Time
	Reason      string
	HitCount    int64
	LastHitTime time.Time
}

// OriginAccessDecision 源站访问决策
type OriginAccessDecision struct {
	Allowed  bool
	Reason   string
	RuleID   string
	Action   string
	CacheHit bool
	Duration time.Duration
}

// NewOriginProtector 创建源站保护器
func NewOriginProtector(cfg *config.OriginProtectionConfig, opts ...OriginProtectorOption) (*OriginProtector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("源站保护配置不能为空")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("源站保护配置验证失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	op := &OriginProtector{
		config: cfg,
		rules:  make([]*OriginProtectionRule, 0),
		cache: &OriginAccessCache{
			entries: make(map[string]*CacheEntry),
			ttl:     5 * time.Minute,
		},
		logger: &DefaultLogger{},
		ctx:    ctx,
		cancel: cancel,
	}

	for _, opt := range opts {
		opt(op)
	}

	// 初始化规则
	if err := op.initRules(); err != nil {
		cancel()
		return nil, fmt.Errorf("初始化规则失败: %w", err)
	}

	// 启动缓存清理
	go op.cacheCleanupLoop()

	return op, nil
}

// OriginProtectorOption 源站保护器选项
type OriginProtectorOption func(*OriginProtector)

// WithOriginLogger 设置日志
func WithOriginLogger(l Logger) OriginProtectorOption {
	return func(op *OriginProtector) {
		op.logger = l
	}
}

// initRules 初始化规则
func (op *OriginProtector) initRules() error {
	op.mu.Lock()
	defer op.mu.Unlock()

	ruleID := 0

	// 白名单规则
	for _, ipRange := range op.config.AllowOnlyFrom {
		_, cidr, err := net.ParseCIDR(ipRange.CIDR)
		if err != nil {
			op.logger.Warnf("解析CIDR失败: %s, %v", ipRange.CIDR, err)
			continue
		}

		rule := &OriginProtectionRule{
			ID:          fmt.Sprintf("allow_%d", ruleID),
			Type:        "allow",
			IPRange:     cidr,
			Action:      "allow",
			Priority:    100,
			Enabled:     true,
			CreatedAt:   time.Now(),
			LastUpdated: time.Now(),
		}
		op.rules = append(op.rules, rule)
		ruleID++
	}

	// 黑名单规则
	for _, ipRange := range op.config.BlockFrom {
		_, cidr, err := net.ParseCIDR(ipRange.CIDR)
		if err != nil {
			op.logger.Warnf("解析CIDR失败: %s, %v", ipRange.CIDR, err)
			continue
		}

		rule := &OriginProtectionRule{
			ID:          fmt.Sprintf("block_%d", ruleID),
			Type:        "block",
			IPRange:     cidr,
			Action:      "deny",
			Priority:    200,
			Enabled:     true,
			CreatedAt:   time.Now(),
			LastUpdated: time.Now(),
		}
		op.rules = append(op.rules, rule)
		ruleID++
	}

	op.logger.Infof("源站保护规则初始化完成: %d条规则", len(op.rules))
	return nil
}

// Start 启动源站保护器
func (op *OriginProtector) Start() error {
	if !op.config.Enabled {
		op.logger.Infof("源站保护未启用")
		return nil
	}

	op.logger.Infof("启动源站保护器，模式: %s", op.config.Mode)
	return nil
}

// Stop 停止源站保护器
func (op *OriginProtector) Stop() {
	op.logger.Infof("停止源站保护器")
	if op.cancel != nil {
		op.cancel()
	}
}

// CheckAccess 检查源站访问权限
func (op *OriginProtector) CheckAccess(ctx context.Context, ip string, port int, protocol string) (*OriginAccessDecision, error) {
	startTime := time.Now()

	// 检查缓存
	cacheKey := fmt.Sprintf("%s:%d:%s", ip, port, protocol)
	if entry, hit := op.cache.Get(cacheKey); hit {
		if time.Now().Before(entry.ExpiresAt) {
			entry.HitCount++
			entry.LastHitTime = time.Now()

			return &OriginAccessDecision{
				Allowed:  entry.Allowed,
				Reason:   entry.Reason,
				CacheHit: true,
				Duration: time.Since(startTime),
			}, nil
		}
	}

	// 执行访问控制检查
	decision := op.checkAccessRules(ip, port, protocol)

	// 更新缓存
	op.cache.Set(cacheKey, &CacheEntry{
		Allowed:     decision.Allowed,
		ExpiresAt:   time.Now().Add(op.cache.ttl),
		Reason:      decision.Reason,
		HitCount:    1,
		LastHitTime: time.Now(),
	})

	decision.Duration = time.Since(startTime)
	return decision, nil
}

// checkAccessRules 检查访问规则
func (op *OriginProtector) checkAccessRules(ip string, port int, protocol string) *OriginAccessDecision {
	op.mu.RLock()
	defer op.mu.RUnlock()

	decision := &OriginAccessDecision{
		Allowed: false,
		Reason:  "denied by default",
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		decision.Reason = "invalid IP address"
		return decision
	}

	// 检查模式
	switch op.config.Mode {
	case "whitelist":
		return op.checkWhitelist(parsedIP, port, protocol)
	case "blacklist":
		return op.checkBlacklist(parsedIP, port, protocol)
	case "hybrid":
		return op.checkHybrid(parsedIP, port, protocol)
	default:
		decision.Reason = fmt.Sprintf("unknown mode: %s", op.config.Mode)
		return decision
	}
}

// checkWhitelist 检查白名单
func (op *OriginProtector) checkWhitelist(ip net.IP, port int, protocol string) *OriginAccessDecision {
	decision := &OriginAccessDecision{
		Allowed: false,
		Reason:  "not in whitelist",
	}

	// 检查白名单规则
	for _, rule := range op.rules {
		if !rule.Enabled || rule.Type != "allow" {
			continue
		}

		if rule.IPRange.Contains(ip) {
			decision.Allowed = true
			decision.Reason = "in whitelist"
			decision.RuleID = rule.ID
			return decision
		}
	}

	return decision
}

// checkBlacklist 检查黑名单
func (op *OriginProtector) checkBlacklist(ip net.IP, port int, protocol string) *OriginAccessDecision {
	decision := &OriginAccessDecision{
		Allowed: true,
		Reason:  "not in blacklist",
	}

	// 检查黑名单规则
	for _, rule := range op.rules {
		if !rule.Enabled || rule.Type != "block" {
			continue
		}

		if rule.IPRange.Contains(ip) {
			decision.Allowed = false
			decision.Reason = "in blacklist"
			decision.RuleID = rule.ID
			return decision
		}
	}

	// 检查端口限制
	if op.config.PortRestrictions != nil {
		for _, blockedPort := range op.config.PortRestrictions.BlockedPorts {
			if port == blockedPort {
				decision.Allowed = false
				decision.Reason = fmt.Sprintf("port %d is blocked", port)
				return decision
			}
		}

		if len(op.config.PortRestrictions.AllowedPorts) > 0 {
			allowed := false
			for _, allowedPort := range op.config.PortRestrictions.AllowedPorts {
				if port == allowedPort {
					allowed = true
					break
				}
			}
			if !allowed {
				decision.Allowed = false
				decision.Reason = fmt.Sprintf("port %d not in allowed list", port)
				return decision
			}
		}
	}

	return decision
}

// checkHybrid 检查混合模式
func (op *OriginProtector) checkHybrid(ip net.IP, port int, protocol string) *OriginAccessDecision {
	// 先检查黑名单
	blacklistDecision := op.checkBlacklist(ip, port, protocol)
	if !blacklistDecision.Allowed {
		return blacklistDecision
	}

	// 再检查白名单
	whitelistDecision := op.checkWhitelist(ip, port, protocol)
	if whitelistDecision.Allowed {
		return whitelistDecision
	}

	// 检查ACL规则
	aclDecision := op.checkACLRules(ip, port, protocol)
	if aclDecision != nil {
		return aclDecision
	}

	return &OriginAccessDecision{
		Allowed: true,
		Reason:  "allowed by hybrid mode (no restrictions matched)",
	}
}

// checkACLRules 检查ACL规则
func (op *OriginProtector) checkACLRules(ip net.IP, port int, protocol string) *OriginAccessDecision {
	if op.config.ACLs == nil || len(op.config.ACLs) == 0 {
		return nil
	}

	ipStr := ip.String()

	for _, acl := range op.config.ACLs {
		if !acl.Enabled {
			continue
		}

		// 检查源IP
		if acl.Match.SourceIP != "" {
			_, cidr, err := net.ParseCIDR(acl.Match.SourceIP)
			if err == nil {
				if !cidr.Contains(ip) {
					continue
				}
			} else if acl.Match.SourceIP != ipStr {
				continue
			}
		}

		// 检查协议
		if acl.Match.Protocol != "" && acl.Match.Protocol != protocol {
			continue
		}

		// 检查端口
		if acl.Match.Port != 0 && acl.Match.Port != port {
			continue
		}

		// 匹配到ACL规则
		allowed := acl.Action == "allow"
		return &OriginAccessDecision{
			Allowed: allowed,
			Reason:  fmt.Sprintf("matched ACL rule: %s, action: %s", acl.ID, acl.Action),
			RuleID:  acl.ID,
			Action:  acl.Action,
		}
	}

	return nil
}

// Get 获取缓存条目
func (c *OriginAccessCache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	return entry, ok
}

// Set 设置缓存条目
func (c *OriginAccessCache) Set(key string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = entry
}

// cacheCleanupLoop 缓存清理循环
func (op *OriginProtector) cacheCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-op.ctx.Done():
			return
		case <-ticker.C:
			op.cleanupCache()
		}
	}
}

// cleanupCache 清理过期缓存
func (op *OriginProtector) cleanupCache() {
	now := time.Now()
	op.cache.mu.Lock()
	defer op.cache.mu.Unlock()

	for key, entry := range op.cache.entries {
		if now.After(entry.ExpiresAt) {
			delete(op.cache.entries, key)
		}
	}
}

// GetStats 获取统计信息
func (op *OriginProtector) GetStats() *OriginProtectionStats {
	op.mu.RLock()
	defer op.mu.RUnlock()

	op.cache.mu.RLock()
	defer op.cache.mu.RUnlock()

	stats := &OriginProtectionStats{
		TotalRules:   len(op.rules),
		EnabledRules: 0,
		CacheEntries: len(op.cache.entries),
		AllowedCount: 0,
		BlockedCount: 0,
	}

	for _, rule := range op.rules {
		if rule.Enabled {
			stats.EnabledRules++
		}
	}

	for _, entry := range op.cache.entries {
		if entry.Allowed {
			stats.AllowedCount++
		} else {
			stats.BlockedCount++
		}
	}

	return stats
}

// OriginProtectionStats 源站保护统计
type OriginProtectionStats struct {
	TotalRules   int
	EnabledRules int
	CacheEntries int
	AllowedCount int64
	BlockedCount int64
}

// Clear 清空缓存
func (c *OriginAccessCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
}

// AddRule 动态添加规则
func (op *OriginProtector) AddRule(cidr, ruleType, action string, priority int) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("解析CIDR失败: %w", err)
	}

	op.mu.Lock()
	defer op.mu.Unlock()

	rule := &OriginProtectionRule{
		ID:          fmt.Sprintf("rule_%d", time.Now().UnixNano()),
		Type:        ruleType,
		IPRange:     ipNet,
		Action:      action,
		Priority:    priority,
		Enabled:     true,
		CreatedAt:   time.Now(),
		LastUpdated: time.Now(),
	}

	op.rules = append(op.rules, rule)
	op.cache.Clear()
	op.logger.Infof("添加源站保护规则: %s (%s)", rule.ID, cidr)

	return nil
}

// RemoveRule 删除规则
func (op *OriginProtector) RemoveRule(ruleID string) error {
	op.mu.Lock()
	defer op.mu.Unlock()

	for i, rule := range op.rules {
		if rule.ID == ruleID {
			op.rules = append(op.rules[:i], op.rules[i+1:]...)
			op.cache.Clear()
			op.logger.Infof("删除源站保护规则: %s", ruleID)
			return nil
		}
	}

	return fmt.Errorf("规则不存在: %s", ruleID)
}

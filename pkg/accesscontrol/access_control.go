package accesscontrol

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AccessControl 访问控制管理器
type AccessControl struct {
	config      *AccessConfig
	rules       []*AccessRule
	ruleGroups  map[string]*RuleGroup
	ipCache     *IPCache
	domainCache *DomainCache
	mu          sync.RWMutex
	stats       *AccessStats
	ctx         context.Context
	cancel      context.CancelFunc
}

// AccessConfig 访问控制配置
type AccessConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 默认策略
	DefaultAction string `yaml:"default_action"` // "allow", "block"

	// 规则匹配模式
	MatchMode string `yaml:"match_mode"` // "all", "any"

	// 规则组
	RuleGroups []RuleGroupConfig `yaml:"rule_groups"`

	// IP配置
	IPConfig *IPAccessConfig `yaml:"ip_config"`

	// 域名配置
	DomainConfig *DomainAccessConfig `yaml:"domain_config"`

	// User-Agent配置
	UAConfig *UAAccessConfig `yaml:"ua_config"`

	// URL配置
	URLConfig *URLAccessConfig `yaml:"url_config"`

	// 响应配置
	Response *AccessResponseConfig `yaml:"response"`

	// 日志配置
	Logging *AccessLoggingConfig `yaml:"logging"`
}

// RuleGroupConfig 规则组配置
type RuleGroupConfig struct {
	ID          string       `yaml:"id"`
	Name        string       `yaml:"name"`
	Priority    int          `yaml:"priority"`
	Description string       `yaml:"description"`
	Rules       []RuleConfig `yaml:"rules"`
}

// RuleConfig 单个规则配置
type RuleConfig struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`      // "ip", "domain", "ua", "url"
	Condition   string `yaml:"condition"` // "eq", "ne", "contains", "regex", "prefix", "suffix"
	Value       string `yaml:"value"`
	Action      string `yaml:"action"` // "allow", "block", "challenge"
	Priority    int    `yaml:"priority"`
	Enabled     bool   `yaml:"enabled"`
	Description string `yaml:"description"`
}

// AccessRule 访问规则
type AccessRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"` // "ip", "domain", "ua", "url"
	Condition   string         `json:"condition"`
	Value       string         `json:"value"`
	ValueRegex  *regexp.Regexp `json:"-"`
	Action      string         `json:"action"`
	Priority    int            `json:"priority"`
	GroupID     string         `json:"group_id"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Stats       *RuleStats     `json:"stats"`
}

// RuleGroup 规则组
type RuleGroup struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Priority    int           `json:"priority"`
	Description string        `json:"description"`
	Rules       []*AccessRule `json:"rules"`
	Action      string        `json:"action"` // "allow", "block"
	Enabled     bool          `json:"enabled"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Stats       *GroupStats   `json:"stats"`
}

// IPAccessConfig IP访问配置
type IPAccessConfig struct {
	// 启用IP规则
	Enabled bool `yaml:"enabled"`

	// IP黑名单
	BlackList []string `yaml:"black_list"`

	// IP白名单
	WhiteList []string `yaml:"white_list"`

	// IP范围
	IPRanges []IPRangeConfig `yaml:"ip_ranges"`

	// 最大连接数
	MaxConnections int `yaml:"max_connections"`

	// 连接超时
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`

	// 地理位置限制
	GeoConfig *GeoAccessConfig `yaml:"geo_config"`
}

// IPRangeConfig IP范围配置
type IPRangeConfig struct {
	CIDR    string `yaml:"cidr"`
	StartIP string `yaml:"start_ip"`
	EndIP   string `yaml:"end_ip"`
	Action  string `yaml:"action"`
}

// GeoAccessConfig 地理位置访问配置
type GeoAccessConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 允许的国家/地区
	AllowedCountries []string `yaml:"allowed_countries"`

	// 禁止的国家/地区
	BlockedCountries []string `yaml:"blocked_countries"`

	// 允许的区域
	AllowedRegions []string `yaml:"allowed_regions"`

	// 禁止的区域
	BlockedRegions []string `yaml:"blocked_regions"`
}

// DomainAccessConfig 域名访问配置
type DomainAccessConfig struct {
	// 启用域名规则
	Enabled bool `yaml:"enabled"`

	// 允许的域名
	AllowedDomains []string `yaml:"allowed_domains"`

	// 禁止的域名
	BlockedDomains []string `yaml:"blocked_domains"`

	// 域名正则
	DomainRegexes []DomainRegexConfig `yaml:"domain_regexes"`

	// 泛域名配置
	WildcardConfig *WildcardDomainConfig `yaml:"wildcard_config"`
}

// DomainRegexConfig 域名正则配置
type DomainRegexConfig struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
}

// WildcardDomainConfig 泛域名配置
type WildcardDomainConfig struct {
	// 启用泛域名
	Enabled bool `yaml:"enabled"`

	// 泛域名列表
	Wildcards []string `yaml:"wildcards"`

	// 泛域名规则
	Rules []WildcardRuleConfig `yaml:"rules"`
}

// WildcardRuleConfig 泛域名规则
type WildcardRuleConfig struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
}

// UAAccessConfig User-Agent访问配置
type UAAccessConfig struct {
	// 启用UA规则
	Enabled bool `yaml:"enabled"`

	// 允许的User-Agent
	AllowedUA []string `yaml:"allowed_ua"`

	// 禁止的User-Agent
	BlockedUA []string `yaml:"blocked_ua"`

	// UA正则
	UARegexes []UARegexConfig `yaml:"ua_regexes"`

	// 机器人检测
	BotConfig *BotDetectionConfig `yaml:"bot_config"`
}

// UARegexConfig UA正则配置
type UARegexConfig struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
}

// BotDetectionConfig 机器人检测配置
type BotDetectionConfig struct {
	// 启用机器人检测
	Enabled bool `yaml:"enabled"`

	// 已知机器人UA
	KnownBots []string `yaml:"known_bots"`

	// 疑似机器人
	SuspiciousBots []string `yaml:"suspicious_bots"`

	// 机器人动作为
	BotAction string `yaml:"bot_action"` // "allow", "block", "challenge"
}

// URLAccessConfig URL访问配置
type URLAccessConfig struct {
	// 启用URL规则
	Enabled bool `yaml:"enabled"`

	// 允许的URL
	AllowedURLs []string `yaml:"allowed_urls"`

	// 禁止的URL
	BlockedURLs []string `yaml:"blocked_urls"`

	// URL正则
	URLRegexes []URLRegexConfig `yaml:"url_regexes"`

	// 路径配置
	PathConfig *PathAccessConfig `yaml:"path_config"`

	// 方法配置
	MethodConfig *MethodAccessConfig `yaml:"method_config"`
}

// URLRegexConfig URL正则配置
type URLRegexConfig struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
}

// PathAccessConfig 路径访问配置
type PathAccessConfig struct {
	// 允许的路径
	AllowedPaths []string `yaml:"allowed_paths"`

	// 禁止的路径
	BlockedPaths []string `yaml:"blocked_paths"`

	// 路径前缀
	PathPrefixes []PathPrefixConfig `yaml:"path_prefixes"`
}

// PathPrefixConfig 路径前缀配置
type PathPrefixConfig struct {
	Prefix string `yaml:"prefix"`
	Action string `yaml:"action"`
}

// MethodAccessConfig 方法访问配置
type MethodAccessConfig struct {
	// 允许的方法
	AllowedMethods []string `yaml:"allowed_methods"`

	// 禁止的方法
	BlockedMethods []string `yaml:"blocked_methods"`
}

// AccessResponseConfig 访问响应配置
type AccessResponseConfig struct {
	// 阻断时的状态码
	BlockStatusCode int `yaml:"block_status_code"`

	// 阻断响应内容
	BlockResponse string `yaml:"block_response"`

	// 阻断响应Content-Type
	BlockContentType string `yaml:"block_content_type"`

	// 是否记录请求头
	RecordHeaders bool `yaml:"record_headers"`

	// 重定向URL
	RedirectURL string `yaml:"redirect_url"`

	// 挑战配置
	ChallengeConfig *ChallengeResponseConfig `yaml:"challenge_config"`
}

// ChallengeResponseConfig 挑战响应配置
type ChallengeResponseConfig struct {
	// 启用挑战
	Enabled bool `yaml:"enabled"`

	// 挑战类型
	Type string `yaml:"type"` // "js", "captcha", "slider"

	// 挑战有效期
	ValidDuration time.Duration `yaml:"valid_duration"`

	// 挑战页面
	ChallengePage string `yaml:"challenge_page"`
}

// AccessLoggingConfig 访问日志配置
type AccessLoggingConfig struct {
	// 启用日志
	Enabled bool `yaml:"enabled"`

	// 日志级别
	Level string `yaml:"level"` // "debug", "info", "warn", "error"

	// 日志格式
	Format string `yaml:"format"` // "json", "text"

	// 包含的字段
	IncludeFields []string `yaml:"include_fields"`

	// 排除的字段
	ExcludeFields []string `yaml:"exclude_fields"`
}

// AccessStats 访问统计
type AccessStats struct {
	TotalRequests       int64            `json:"total_requests"`
	AllowedRequests     int64            `json:"allowed_requests"`
	BlockedRequests     int64            `json:"blocked_requests"`
	ChallengedRequests  int64            `json:"challenged_requests"`
	WhiteListedRequests int64            `json:"white_listed_requests"`
	ByRuleType          map[string]int64 `json:"by_rule_type"`
	TopBlockedIPs       []BlockedIPInfo  `json:"top_blocked_ips"`
	TopBlockedURLs      []BlockedURLInfo `json:"top_blocked_urls"`
	CurrentBlocked      int64            `json:"current_blocked"`
	mu                  sync.RWMutex
}

// RuleStats 规则统计
type RuleStats struct {
	MatchCount  int64            `json:"match_count"`
	ActionCount map[string]int64 `json:"action_count"`
	LastMatched time.Time        `json:"last_matched"`
	mu          sync.RWMutex
}

// GroupStats 组统计
type GroupStats struct {
	TotalMatches int64            `json:"total_matches"`
	AllowedCount int64            `json:"allowed_count"`
	BlockedCount int64            `json:"blocked_count"`
	ActionCount  map[string]int64 `json:"action_count"`
	LastMatched  time.Time        `json:"last_matched"`
	mu           sync.RWMutex
}

// BlockedIPInfo 被阻断IP信息
type BlockedIPInfo struct {
	IP        string    `json:"ip"`
	Count     int64     `json:"count"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// BlockedURLInfo 被阻断URL信息
type BlockedURLInfo struct {
	URL   string `json:"url"`
	Count int64  `json:"count"`
	Rule  string `json:"rule"`
}

// AccessRequest 访问请求信息
type AccessRequest struct {
	// 源IP
	SourceIP string `json:"source_ip"`

	// 域名
	Host string `json:"host"`

	// User-Agent
	UserAgent string `json:"user_agent"`

	// URL
	URL string `json:"url"`

	// 请求方法
	Method string `json:"method"`

	// 请求头
	Headers map[string]string `json:"headers"`

	// 地理位置
	Geo *GeoInfo `json:"geo"`

	// 请求时间
	Timestamp time.Time `json:"timestamp"`
}

// GeoInfo 地理位置信息
type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// AccessResult 访问控制结果
type AccessResult struct {
	// 是否允许
	Allowed bool `json:"allowed"`

	// 执行的动作
	Action string `json:"action"`

	// 匹配的规则ID
	MatchedRuleID string `json:"matched_rule_id"`

	// 匹配的规则组ID
	MatchedGroupID string `json:"matched_group_id"`

	// 原因
	Reason string `json:"reason"`

	// 挑战信息
	Challenge *ChallengeInfo `json:"challenge,omitempty"`

	// 处理时间
	ProcessingTime time.Duration `json:"processing_time"`
}

// ChallengeInfo 挑战信息
type ChallengeInfo struct {
	// 挑战类型
	Type string `json:"type"`

	// 挑战令牌
	Token string `json:"token"`

	// 过期时间
	Expiry time.Time `json:"expiry"`

	// 挑战页面URL
	ChallengeURL string `json:"challenge_url"`
}

// IPCache IP缓存
type IPCache struct {
	cache map[string]*IPCacheEntry
	mu    sync.RWMutex
}

// IPCacheEntry IP缓存条目
type IPCacheEntry struct {
	IP           string    `json:"ip"`
	Action       string    `json:"action"`
	MatchRuleID  string    `json:"match_rule_id"`
	MatchGroupID string    `json:"match_group_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// DomainCache 域名缓存
type DomainCache struct {
	cache map[string]*DomainCacheEntry
	mu    sync.RWMutex
}

// DomainCacheEntry 域名缓存条目
type DomainCacheEntry struct {
	Domain      string    `json:"domain"`
	Action      string    `json:"action"`
	MatchRuleID string    `json:"match_rule_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// NewAccessControl 创建访问控制管理器
func NewAccessControl(config *AccessConfig) *AccessControl {
	if config == nil {
		config = &AccessConfig{
			Enabled:       true,
			DefaultAction: "allow",
			MatchMode:     "all",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	ac := &AccessControl{
		config:      config,
		rules:       make([]*AccessRule, 0),
		ruleGroups:  make(map[string]*RuleGroup),
		ipCache:     &IPCache{cache: make(map[string]*IPCacheEntry)},
		domainCache: &DomainCache{cache: make(map[string]*DomainCacheEntry)},
		stats:       &AccessStats{ByRuleType: make(map[string]int64)},
		ctx:         ctx,
		cancel:      cancel,
	}

	// 初始化规则
	ac.initRules()

	// 启动清理协程
	go ac.cleanupExpiredCache()

	return ac
}

// initRules 初始化规则
func (ac *AccessControl) initRules() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 从配置加载规则
	for _, groupConfig := range ac.config.RuleGroups {
		group := &RuleGroup{
			ID:          groupConfig.ID,
			Name:        groupConfig.Name,
			Priority:    groupConfig.Priority,
			Description: groupConfig.Description,
			Rules:       make([]*AccessRule, 0),
			Action:      "block",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Stats:       &GroupStats{ActionCount: make(map[string]int64)},
		}

		for _, ruleConfig := range groupConfig.Rules {
			rule := ac.createRule(ruleConfig, group.ID)
			if rule != nil {
				group.Rules = append(group.Rules, rule)
				ac.rules = append(ac.rules, rule)
			}
		}

		ac.ruleGroups[group.ID] = group
	}
}

// createRule 创建规则
func (ac *AccessControl) createRule(config RuleConfig, groupID string) *AccessRule {
	if !config.Enabled {
		return nil
	}

	rule := &AccessRule{
		ID:          config.ID,
		Name:        config.Name,
		Type:        config.Type,
		Condition:   config.Condition,
		Value:       config.Value,
		Action:      config.Action,
		Priority:    config.Priority,
		GroupID:     groupID,
		Description: config.Description,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Stats:       &RuleStats{ActionCount: make(map[string]int64)},
	}

	// 编译正则表达式
	if config.Condition == "regex" && config.Value != "" {
		re, err := regexp.Compile(config.Value)
		if err == nil {
			rule.ValueRegex = re
		}
	}

	return rule
}

// CheckRequest 检查请求
func (ac *AccessControl) CheckRequest(req *AccessRequest) *AccessResult {
	startTime := time.Now()

	ac.mu.RLock()
	defer ac.mu.RUnlock()

	result := &AccessResult{
		Allowed: ac.config.DefaultAction == "allow",
		Action:  ac.config.DefaultAction,
	}

	// 1. 检查IP缓存
	if cached := ac.ipCache.get(req.SourceIP); cached != nil {
		result.Allowed = cached.Action == "allow"
		result.Action = cached.Action
		result.MatchedRuleID = cached.MatchRuleID
		result.MatchedGroupID = cached.MatchGroupID
		result.ProcessingTime = time.Since(startTime)

		// 缓存命中也需要更新统计
		ac.updateStats(result.Action, result.MatchedRuleID, result.MatchedGroupID)

		return result
	}

	// 2. 检查规则组
	for _, group := range ac.getSortedGroups() {
		if !group.Enabled {
			continue
		}

		groupResult := ac.checkGroup(group, req)
		if groupResult != nil {
			result.MatchedRuleID = groupResult.MatchedRuleID
			result.MatchedGroupID = group.ID

			if groupResult.Action != "allow" {
				result.Allowed = false
				result.Action = groupResult.Action
				result.Reason = groupResult.Reason

				// 更新统计
				ac.updateStats(groupResult.Action, groupResult.MatchedRuleID, group.ID)

				// 缓存结果
				ac.cacheResult(req.SourceIP, groupResult)

				break
			}
		}
	}

	result.ProcessingTime = time.Since(startTime)

	// 更新统计（无论是否被阻止）
	ac.updateStats(result.Action, result.MatchedRuleID, result.MatchedGroupID)

	// 如果允许且无匹配规则，也缓存结果
	if result.Allowed && result.MatchedRuleID == "" {
		ac.cacheResult(req.SourceIP, result)
	}

	return result
}

// checkGroup 检查规则组
func (ac *AccessControl) checkGroup(group *RuleGroup, req *AccessRequest) *AccessResult {
	for _, rule := range group.Rules {
		if !rule.Enabled {
			continue
		}

		matched := ac.checkRule(rule, req)
		if matched {
			// 更新规则统计
			rule.Stats.mu.Lock()
			rule.Stats.MatchCount++
			rule.Stats.ActionCount[rule.Action]++
			rule.Stats.LastMatched = time.Now()
			rule.Stats.mu.Unlock()

			return &AccessResult{
				Allowed:       rule.Action == "allow",
				Action:        rule.Action,
				MatchedRuleID: rule.ID,
				Reason:        fmt.Sprintf("规则匹配: %s", rule.Name),
			}
		}
	}

	return nil
}

// checkRule 检查单个规则
func (ac *AccessControl) checkRule(rule *AccessRule, req *AccessRequest) bool {
	switch rule.Type {
	case "ip":
		return ac.checkIPRule(rule, req)
	case "domain":
		return ac.checkDomainRule(rule, req)
	case "ua":
		return ac.checkUARule(rule, req)
	case "url":
		return ac.checkURLRule(rule, req)
	}
	return false
}

// checkIPRule 检查IP规则
func (ac *AccessControl) checkIPRule(rule *AccessRule, req *AccessRequest) bool {
	switch rule.Condition {
	case "eq":
		return req.SourceIP == rule.Value
	case "ne":
		return req.SourceIP != rule.Value
	case "contains":
		return strings.Contains(req.SourceIP, rule.Value)
	case "regex":
		if rule.ValueRegex != nil {
			return rule.ValueRegex.MatchString(req.SourceIP)
		}
	case "prefix":
		return strings.HasPrefix(req.SourceIP, rule.Value)
	case "cidr":
		return ac.checkCIDRRule(rule, req)
	}
	return false
}

// checkCIDRRule 检查CIDR规则
func (ac *AccessControl) checkCIDRRule(rule *AccessRule, req *AccessRequest) bool {
	ip := net.ParseIP(req.SourceIP)
	if ip == nil {
		return false
	}

	_, cidr, err := net.ParseCIDR(rule.Value)
	if err != nil {
		return false
	}

	return cidr.Contains(ip)
}

// checkDomainRule 检查域名规则
func (ac *AccessControl) checkDomainRule(rule *AccessRule, req *AccessRequest) bool {
	host := strings.ToLower(req.Host)

	switch rule.Condition {
	case "eq":
		return host == strings.ToLower(rule.Value)
	case "ne":
		return host != strings.ToLower(rule.Value)
	case "contains":
		return strings.Contains(host, strings.ToLower(rule.Value))
	case "regex":
		if rule.ValueRegex != nil {
			return rule.ValueRegex.MatchString(host)
		}
	case "suffix":
		return strings.HasSuffix(host, strings.ToLower(rule.Value))
	case "wildcard":
		return ac.matchWildcard(strings.ToLower(rule.Value), host)
	}
	return false
}

// matchWildcard 通配符匹配
// 支持 * 匹配任意多个字符，? 匹配单个字符
func (ac *AccessControl) matchWildcard(pattern, text string) bool {
	// 将通配符模式转换为正则表达式进行匹配
	regexPattern := convertWildcardToRegex(pattern)
	if regexPattern == "" {
		return false
	}

	re, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return false
	}

	return re.MatchString(text)
}

// convertWildcardToRegex 将通配符模式转换为正则表达式
func convertWildcardToRegex(pattern string) string {
	if pattern == "" {
		return ""
	}

	var result strings.Builder
	result.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			// * 匹配任意字符（包括空字符）
			result.WriteString(".*")
		case '?':
			// ? 匹配任意单个字符
			result.WriteString(".")
		case '.', '+', '^', '$', '[', ']', '{', '}', '(', ')', '|', '\\':
			// 转义正则表达式特殊字符
			result.WriteString("\\" + string(pattern[i]))
		default:
			result.WriteByte(pattern[i])
		}
	}

	result.WriteString("$")
	return result.String()
}

// checkUARule 检查User-Agent规则
func (ac *AccessControl) checkUARule(rule *AccessRule, req *AccessRequest) bool {
	ua := strings.ToLower(req.UserAgent)

	switch rule.Condition {
	case "eq":
		return ua == strings.ToLower(rule.Value)
	case "ne":
		return ua != strings.ToLower(rule.Value)
	case "contains":
		return strings.Contains(ua, strings.ToLower(rule.Value))
	case "regex":
		if rule.ValueRegex != nil {
			return rule.ValueRegex.MatchString(ua)
		}
	case "prefix":
		return strings.HasPrefix(ua, strings.ToLower(rule.Value))
	}
	return false
}

// checkURLRule 检查URL规则
func (ac *AccessControl) checkURLRule(rule *AccessRule, req *AccessRequest) bool {
	url := strings.ToLower(req.URL)

	switch rule.Condition {
	case "eq":
		return url == strings.ToLower(rule.Value)
	case "ne":
		return url != strings.ToLower(rule.Value)
	case "contains":
		return strings.Contains(url, strings.ToLower(rule.Value))
	case "regex":
		if rule.ValueRegex != nil {
			return rule.ValueRegex.MatchString(url)
		}
	case "prefix":
		return strings.HasPrefix(url, strings.ToLower(rule.Value))
	case "suffix":
		return strings.HasSuffix(url, strings.ToLower(rule.Value))
	}
	return false
}

// getSortedGroups 获取排序后的规则组
func (ac *AccessControl) getSortedGroups() []*RuleGroup {
	groups := make([]*RuleGroup, 0)
	for _, group := range ac.ruleGroups {
		groups = append(groups, group)
	}

	// 按优先级排序
	for i := 0; i < len(groups); i++ {
		for j := i + 1; j < len(groups); j++ {
			if groups[j].Priority > groups[i].Priority {
				groups[i], groups[j] = groups[j], groups[i]
			}
		}
	}

	return groups
}

// updateStats 更新统计
func (ac *AccessControl) updateStats(action, ruleID, groupID string) {
	ac.stats.mu.Lock()
	defer ac.stats.mu.Unlock()

	ac.stats.TotalRequests++

	switch action {
	case "allow":
		ac.stats.AllowedRequests++
	case "block":
		ac.stats.BlockedRequests++
	case "challenge":
		ac.stats.ChallengedRequests++
	}
}

// cacheResult 缓存结果
func (ac *AccessControl) cacheResult(ip string, result *AccessResult) {
	entry := &IPCacheEntry{
		IP:           ip,
		Action:       result.Action,
		MatchRuleID:  result.MatchedRuleID,
		MatchGroupID: result.MatchedGroupID,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	ac.ipCache.set(ip, entry)
}

// cleanupExpiredCache 清理过期缓存
func (ac *AccessControl) cleanupExpiredCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ac.ctx.Done():
			return
		case <-ticker.C:
			ac.ipCache.cleanup()
			ac.domainCache.cleanup()
		}
	}
}

// GetStats 获取统计
func (ac *AccessControl) GetStats() *AccessStats {
	ac.stats.mu.RLock()
	defer ac.stats.mu.RUnlock()

	return ac.stats
}

// AddRule 添加规则
func (ac *AccessControl) AddRule(rule *AccessRule) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.Stats = &RuleStats{ActionCount: make(map[string]int64)}

	// 编译正则
	if rule.Condition == "regex" && rule.Value != "" {
		re, err := regexp.Compile(rule.Value)
		if err != nil {
			return fmt.Errorf("正则表达式编译失败: %v", err)
		}
		rule.ValueRegex = re
	}

	ac.rules = append(ac.rules, rule)

	// 如果有规则组，添加到规则组
	if rule.GroupID != "" {
		if group, ok := ac.ruleGroups[rule.GroupID]; ok {
			group.Rules = append(group.Rules, rule)
		}
	}

	return nil
}

// RemoveRule 移除规则
func (ac *AccessControl) RemoveRule(ruleID string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	for i, rule := range ac.rules {
		if rule.ID == ruleID {
			ac.rules = append(ac.rules[:i], ac.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("规则不存在: %s", ruleID)
}

// GetRules 获取所有规则
func (ac *AccessControl) GetRules() []*AccessRule {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	return ac.rules
}

// GetRuleGroups 获取所有规则组
func (ac *AccessControl) GetRuleGroups() []*RuleGroup {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	groups := make([]*RuleGroup, 0)
	for _, group := range ac.ruleGroups {
		groups = append(groups, group)
	}

	return groups
}

// IPCache methods
func (c *IPCache) get(ip string) *IPCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[ip]
	if !ok {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(c.cache, ip)
		return nil
	}

	return entry
}

func (c *IPCache) set(ip string, entry *IPCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[ip] = entry
}

func (c *IPCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for ip, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, ip)
		}
	}
}

// DomainCache methods
func (c *DomainCache) get(domain string) *DomainCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[domain]
	if !ok {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(c.cache, domain)
		return nil
	}

	return entry
}

func (c *DomainCache) set(domain string, entry *DomainCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[domain] = entry
}

func (c *DomainCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for domain, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, domain)
		}
	}
}

// BlockIP 封锁IP
func (ac *AccessControl) BlockIP(ip, reason string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry := &IPCacheEntry{
		IP:        ip,
		Action:    "block",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	ac.ipCache.set(ip, entry)

	// 更新统计
	ac.stats.mu.Lock()
	ac.stats.BlockedRequests++
	ac.stats.TopBlockedIPs = append(ac.stats.TopBlockedIPs, BlockedIPInfo{
		IP:        ip,
		Count:     1,
		Reason:    reason,
		Timestamp: time.Now(),
	})
	ac.stats.mu.Unlock()
}

// AllowIP 允许IP
func (ac *AccessControl) AllowIP(ip string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry := &IPCacheEntry{
		IP:        ip,
		Action:    "allow",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	ac.ipCache.set(ip, entry)
}

// IsBlocked 检查IP是否被封锁
func (ac *AccessControl) IsBlocked(ip string) bool {
	if cached := ac.ipCache.get(ip); cached != nil {
		return cached.Action == "block"
	}
	return false
}

// AddToWhiteList 添加到白名单
func (ac *AccessControl) AddToWhiteList(ip string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry := &IPCacheEntry{
		IP:        ip,
		Action:    "allow",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	ac.ipCache.set(ip, entry)
}

// AddToBlackList 添加到黑名单
func (ac *AccessControl) AddToBlackList(ip string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry := &IPCacheEntry{
		IP:        ip,
		Action:    "block",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	ac.ipCache.set(ip, entry)
}

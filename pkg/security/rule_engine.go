package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RuleEngine 规则引擎
type RuleEngine struct {
	mu          sync.RWMutex
	blacklist   *RuleList
	whitelist   *RuleList
	rules       []*Rule
	logger      Logger
	stats       RuleEngineStats
}

// RuleList 规则列表
type RuleList struct {
	IPs      map[string]*ListEntry
	IPRanges []*IPRange
	CIDRs    []*net.IPNet
	UserAgents map[string]*ListEntry
	Paths    map[string]*ListEntry
	Headers  map[string]map[string]*ListEntry
	domains  map[string]*ListEntry
}

// IPRange IP范围
type IPRange struct {
	Start net.IP
	End   net.IP
}

// ListEntry 列表条目
type ListEntry struct {
	Value     string
	Reason    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Enabled   bool
}

// Rule 规则
type Rule struct {
	ID          string
	Name        string
	Type        RuleType
	Action      RuleAction
	Match       RuleMatch
	Priority    int
	Enabled     bool
	TTL         time.Duration
	RateLimit   *RuleRateLimitConfig
	CreatedAt   time.Time
	HitCount    int64
	LastHitAt   time.Time
}

// RuleType 规则类型
type RuleType string

const (
	RuleTypeBlacklist RuleType = "blacklist"
	RuleTypeWhitelist RuleType = "whitelist"
	RuleTypeCustom    RuleType = "custom"
)

// RuleAction 规则动作
type RuleAction string

const (
	RuleActionAllow  RuleAction = "allow"
	RuleActionBlock  RuleAction = "block"
	RuleActionLog    RuleAction = "log"
	RuleActionRateLimit RuleAction = "rate_limit"
	RuleActionChallenge RuleAction = "challenge"
)

// RuleMatch 规则匹配条件
type RuleMatch struct {
	IP        string // exact IP or CIDR
	IPRange   string // e.g., "192.168.1.0-192.168.1.255"
	Path      string // exact path or prefix
	PathRegex string // regex pattern
	Method    string // HTTP method
	UserAgent string // user agent substring
	Header    map[string]string // header key-value pairs
	Domain    string // domain
	Country   string // country code
}

// RuleRateLimitConfig 规则速率限制配置
type RuleRateLimitConfig struct {
	Requests int64
	Window   time.Duration
}

// RuleEngineStats 规则引擎统计
type RuleEngineStats struct {
	TotalRules      int
	ActiveRules     int
	TotalChecked    int64
	BlacklistHits   int64
	WhitelistHits   int64
	CustomRuleHits  int64
	BlockedTotal    int64
	AllowedTotal    int64
	mu              sync.RWMutex
}

// NewRuleEngine 创建规则引擎
func NewRuleEngine(opts ...RuleEngineOption) *RuleEngine {
	re := &RuleEngine{
		blacklist: &RuleList{
			IPs:        make(map[string]*ListEntry),
			UserAgents: make(map[string]*ListEntry),
			Paths:      make(map[string]*ListEntry),
			Headers:    make(map[string]map[string]*ListEntry),
			domains:    make(map[string]*ListEntry),
		},
		whitelist: &RuleList{
			IPs:        make(map[string]*ListEntry),
			UserAgents: make(map[string]*ListEntry),
			Paths:      make(map[string]*ListEntry),
			Headers:    make(map[string]map[string]*ListEntry),
			domains:    make(map[string]*ListEntry),
		},
		rules:  make([]*Rule, 0),
		logger: &DefaultLogger{},
	}

	for _, opt := range opts {
		opt(re)
	}

	return re
}

// RuleEngineOption 规则引擎选项
type RuleEngineOption func(*RuleEngine)

// WithRuleEngineLogger 设置日志
func WithRuleEngineLogger(l Logger) RuleEngineOption {
	return func(re *RuleEngine) {
		re.logger = l
	}
}

// AddToBlacklist 添加到黑名单
func (re *RuleEngine) AddToBlacklist(entry *BlacklistEntry) {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.addToList(re.blacklist, entry)
}

// BlacklistEntry 黑名单条目
type BlacklistEntry struct {
	Type      BlacklistType
	Value     string
	Reason    string
	TTL       time.Duration
}

// BlacklistType 黑名单类型
type BlacklistType string

const (
	BlacklistTypeIP        BlacklistType = "ip"
	BlacklistTypeIPRange   BlacklistType = "ip_range"
	BlacklistTypeCIDR      BlacklistType = "cidr"
	BlacklistTypeUserAgent BlacklistType = "user_agent"
	BlacklistTypePath      BlacklistType = "path"
	BlacklistTypeDomain    BlacklistType = "domain"
	BlacklistTypeHeader    BlacklistType = "header"
)

func (re *RuleEngine) addToList(list *RuleList, entry *BlacklistEntry) {
	var ttl time.Duration
	if entry.TTL > 0 {
		ttl = entry.TTL
	}

	listEntry := &ListEntry{
		Value:     entry.Value,
		Reason:    entry.Reason,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		Enabled:   true,
	}

	switch entry.Type {
	case BlacklistTypeIP:
		list.IPs[entry.Value] = listEntry
	case BlacklistTypeIPRange:
		re.parseIPRange(entry.Value, list)
	case BlacklistTypeCIDR:
		re.parseCIDR(entry.Value, list)
	case BlacklistTypeUserAgent:
		list.UserAgents[entry.Value] = listEntry
	case BlacklistTypePath:
		list.Paths[entry.Value] = listEntry
	case BlacklistTypeDomain:
		list.domains[entry.Value] = listEntry
	case BlacklistTypeHeader:
		parts := strings.SplitN(entry.Value, ":", 2)
		if len(parts) == 2 {
			if list.Headers[parts[0]] == nil {
				list.Headers[parts[0]] = make(map[string]*ListEntry)
			}
			list.Headers[parts[0]][parts[1]] = listEntry
		}
	}
}

func (re *RuleEngine) parseIPRange(rangeStr string, list *RuleList) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) == 2 {
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start != nil && end != nil {
			list.IPRanges = append(list.IPRanges, &IPRange{Start: start, End: end})
		}
	}
}

func (re *RuleEngine) parseCIDR(cidrStr string, list *RuleList) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err == nil {
		list.CIDRs = append(list.CIDRs, ipNet)
	}
}

// RemoveFromBlacklist 从黑名单移除
func (re *RuleEngine) RemoveFromBlacklist(entryType BlacklistType, value string) {
	re.mu.Lock()
	defer re.mu.Unlock()

	switch entryType {
	case BlacklistTypeIP:
		delete(re.blacklist.IPs, value)
	case BlacklistTypeUserAgent:
		delete(re.blacklist.UserAgents, value)
	case BlacklistTypePath:
		delete(re.blacklist.Paths, value)
	case BlacklistTypeDomain:
		delete(re.blacklist.domains, value)
	}
}

// AddToWhitelist 添加到白名单
func (re *RuleEngine) AddToWhitelist(entry *BlacklistEntry) {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.addToList(re.whitelist, entry)
}

// RemoveFromWhitelist 从白名单移除
func (re *RuleEngine) RemoveFromWhitelist(entryType BlacklistType, value string) {
	re.mu.Lock()
	defer re.mu.Unlock()

	switch entryType {
	case BlacklistTypeIP:
		delete(re.whitelist.IPs, value)
	case BlacklistTypeUserAgent:
		delete(re.whitelist.UserAgents, value)
	case BlacklistTypePath:
		delete(re.whitelist.Paths, value)
	case BlacklistTypeDomain:
		delete(re.whitelist.domains, value)
	}
}

// IsWhitelisted 检查是否在白名单
func (re *RuleEngine) IsWhitelisted(req *http.Request) bool {
	re.mu.RLock()
	defer re.mu.RUnlock()

	clientIP := getClientIP(req)
	ua := req.UserAgent()
	path := req.URL.Path

	// 检查 IP 白名单
	if re.isIPInList(clientIP, re.whitelist) {
		return true
	}

	// 检查 UA 白名单
	if _, ok := re.whitelist.UserAgents[ua]; ok {
		return true
	}

	// 检查路径白名单
	if _, ok := re.whitelist.Paths[path]; ok {
		return true
	}

	return false
}

// IsBlacklisted 检查是否在黑名单
func (re *RuleEngine) IsBlacklisted(req *http.Request) (*ListEntry, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	clientIP := getClientIP(req)
	ua := req.UserAgent()
	path := req.URL.Path

	// 检查 IP 黑名单
	if entry, ok := re.isIPBlacklisted(clientIP); ok {
		return entry, true
	}

	// 检查 UA 黑名单
	if entry, ok := re.blacklist.UserAgents[ua]; ok {
		return entry, true
	}

	// 检查路径黑名单
	if entry, ok := re.blacklist.Paths[path]; ok {
		return entry, true
	}

	return nil, false
}

func (re *RuleEngine) isIPBlacklisted(ipStr string) (*ListEntry, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, false
	}

	// 直接匹配
	if entry, ok := re.blacklist.IPs[ipStr]; ok {
		return entry, true
	}

	// CIDR 匹配
	for _, cidr := range re.blacklist.CIDRs {
		if cidr.Contains(ip) {
			return &ListEntry{Value: cidr.String(), Reason: "CIDR match"}, true
		}
	}

	// 范围匹配
	for _, ipRange := range re.blacklist.IPRanges {
		if bytesCompare(ip, ipRange.Start) >= 0 && bytesCompare(ip, ipRange.End) <= 0 {
			return &ListEntry{Value: ipRange.Start.String() + "-" + ipRange.End.String(), Reason: "IP range match"}, true
		}
	}

	return nil, false
}

func (re *RuleEngine) isIPInList(ipStr string, list *RuleList) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 直接匹配
	if _, ok := list.IPs[ipStr]; ok {
		return true
	}

	// CIDR 匹配
	for _, cidr := range list.CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	// 范围匹配
	for _, ipRange := range list.IPRanges {
		if bytesCompare(ip, ipRange.Start) >= 0 && bytesCompare(ip, ipRange.End) <= 0 {
			return true
		}
	}

	return false
}

func bytesCompare(a, b net.IP) int {
	aa := a.To4()
	bb := b.To4()
	if aa == nil {
		aa = a
	}
	if bb == nil {
		bb = b
	}
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

// CheckRequest 检查请求
func (re *RuleEngine) CheckRequest(req *http.Request) RuleCheckResult {
	re.mu.RLock()
	defer re.mu.RUnlock()

	re.stats.mu.Lock()
	re.stats.TotalChecked++
	re.stats.mu.Unlock()

	result := RuleCheckResult{Action: RuleActionAllow}

	// 首先检查白名单
	if re.IsWhitelisted(req) {
		re.stats.mu.Lock()
		re.stats.WhitelistHits++
		re.stats.AllowedTotal++
		re.stats.mu.Unlock()
		result.Action = RuleActionAllow
		result.Whitelisted = true
		return result
	}

	// 检查黑名单
	if entry, ok := re.IsBlacklisted(req); ok {
		re.stats.mu.Lock()
		re.stats.BlacklistHits++
		re.stats.BlockedTotal++
		re.stats.mu.Unlock()
		result.Action = RuleActionBlock
		result.Blocked = true
		result.Reason = entry.Reason
		return result
	}

	// 检查自定义规则
	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}

		if re.matchRule(req, rule) {
			re.stats.mu.Lock()
			re.stats.CustomRuleHits++
			re.stats.mu.Unlock()

			rule.HitCount++
			rule.LastHitAt = time.Now()

			result.MatchedRule = rule
			result.Action = rule.Action
			return result
		}
	}

	return result
}

// RuleCheckResult 规则检查结果
type RuleCheckResult struct {
	Action       RuleAction
	Whitelisted  bool
	Blocked      bool
	Reason       string
	MatchedRule  *Rule
}

// matchRule 匹配规则
func (re *RuleEngine) matchRule(req *http.Request, rule *Rule) bool {
	match := &rule.Match

	// 检查 IP
	if match.IP != "" {
		clientIP := getClientIP(req)
		if clientIP != match.IP {
			return false
		}
	}

	// 检查路径
	if match.Path != "" {
		path := req.URL.Path
		if !strings.HasPrefix(path, match.Path) {
			return false
		}
	}

	// 检查方法
	if match.Method != "" && req.Method != match.Method {
		return false
	}

	// 检查 UA
	if match.UserAgent != "" {
		ua := req.UserAgent()
		if !strings.Contains(ua, match.UserAgent) {
			return false
		}
	}

	// 检查 Header
	for key, value := range match.Header {
		if req.Header.Get(key) != value {
			return false
		}
	}

	return true
}

// AddRule 添加自定义规则
func (re *RuleEngine) AddRule(rule *Rule) {
	re.mu.Lock()
	defer re.mu.Unlock()

	rule.CreatedAt = time.Now()
	re.rules = append(re.rules, rule)
}

// RemoveRule 移除规则
func (re *RuleEngine) RemoveRule(ruleID string) {
	re.mu.Lock()
	defer re.mu.Unlock()

	for i, rule := range re.rules {
		if rule.ID == ruleID {
			re.rules = append(re.rules[:i], re.rules[i+1:]...)
			return
		}
	}
}

// GetRules 获取所有规则
func (re *RuleEngine) GetRules() []*Rule {
	re.mu.RLock()
	defer re.mu.RUnlock()

	return re.rules
}

// GetStats 获取统计
func (re *RuleEngine) GetStats() RuleEngineStats {
	re.stats.mu.RLock()
	defer re.stats.mu.RUnlock()

	re.stats.TotalRules = len(re.rules)
	re.stats.ActiveRules = 0
	for _, rule := range re.rules {
		if rule.Enabled {
			re.stats.ActiveRules++
		}
	}

	return re.stats
}

// ClearBlacklist 清空黑名单
func (re *RuleEngine) ClearBlacklist() {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.blacklist = &RuleList{
		IPs:        make(map[string]*ListEntry),
		UserAgents: make(map[string]*ListEntry),
		Paths:      make(map[string]*ListEntry),
		Headers:    make(map[string]map[string]*ListEntry),
		domains:    make(map[string]*ListEntry),
	}
}

// ClearWhitelist 清空白名单
func (re *RuleEngine) ClearWhitelist() {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.whitelist = &RuleList{
		IPs:        make(map[string]*ListEntry),
		UserAgents: make(map[string]*ListEntry),
		Paths:      make(map[string]*ListEntry),
		Headers:    make(map[string]map[string]*ListEntry),
		domains:    make(map[string]*ListEntry),
	}
}

// GetBlacklistSize 获取黑名单大小
func (re *RuleEngine) GetBlacklistSize() int {
	re.mu.RLock()
	defer re.mu.RUnlock()

	size := len(re.blacklist.IPs) + len(re.blacklist.UserAgents) +
		len(re.blacklist.Paths) + len(re.blacklist.CIDRs) + len(re.blacklist.IPRanges)
	return size
}

// GetWhitelistSize 获取白名单大小
func (re *RuleEngine) GetWhitelistSize() int {
	re.mu.RLock()
	defer re.mu.RUnlock()

	size := len(re.whitelist.IPs) + len(re.whitelist.UserAgents) +
		len(re.whitelist.Paths) + len(re.whitelist.CIDRs) + len(re.whitelist.IPRanges)
	return size
}

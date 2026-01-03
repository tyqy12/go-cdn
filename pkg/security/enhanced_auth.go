package security

import (
	"crypto/subtle"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EnhancedURLAuth 增强版URL鉴权服务
type EnhancedURLAuth struct {
	*URLAuth
	ipAnalyzer   *IPAnalyzer
	refererRules *RefererRules
}

// IPAnalyzer IP分析器（支持CIDR）
type IPAnalyzer struct {
	mu         sync.RWMutex
	cidrRanges []*net.IPNet
	ipCache    *IPCache
}

// IPCache IP缓存
type IPCache struct {
	cache map[string]*CachedIP
	mu    sync.RWMutex
	ttl   time.Duration
}

// CachedIP 缓存的IP信息
type CachedIP struct {
	IP            net.IP
	IPNet         *net.IPNet
	IsWhitelisted bool
	CachedAt      time.Time
}

// RefererRules 增强的Referer规则
type RefererRules struct {
	mu              sync.RWMutex
	allowedPatterns []*regexp.Regexp
	blockedPatterns []*regexp.Regexp
	allowedDomains  map[string]bool
	allowedSuffixes map[string]bool
}

// NewEnhancedURLAuth 创建增强版URL鉴权
func NewEnhancedURLAuth(config *AuthConfig) *EnhancedURLAuth {
	auth := &EnhancedURLAuth{
		URLAuth:      NewURLAuth(config),
		ipAnalyzer:   NewIPAnalyzer(),
		refererRules: NewRefererRules(),
	}

	// 初始化CIDR白名单
	if len(config.WhiteListConfig.CIDRWhitelist) > 0 {
		for _, cidr := range config.WhiteListConfig.CIDRWhitelist {
			auth.ipAnalyzer.AddCIDR(cidr)
		}
	}

	// 初始化Referer规则
	if len(config.RefererConfig.AllowedReferers) > 0 {
		for _, domain := range config.RefererConfig.AllowedReferers {
			auth.refererRules.AddAllowedDomain(domain)
		}
	}

	if len(config.RefererConfig.BlockedReferers) > 0 {
		for _, pattern := range config.RefererConfig.BlockedReferers {
			auth.refererRules.AddBlockedPattern(pattern)
		}
	}

	return auth
}

// NewIPAnalyzer 创建IP分析器
func NewIPAnalyzer() *IPAnalyzer {
	return &IPAnalyzer{
		cidrRanges: make([]*net.IPNet, 0),
		ipCache: &IPCache{
			cache: make(map[string]*CachedIP),
			ttl:   5 * time.Minute,
		},
	}
}

// NewRefererRules 创建Referer规则
func NewRefererRules() *RefererRules {
	return &RefererRules{
		allowedPatterns: make([]*regexp.Regexp, 0),
		blockedPatterns: make([]*regexp.Regexp, 0),
		allowedDomains:  make(map[string]bool),
		allowedSuffixes: make(map[string]bool),
	}
}

// AddCIDR 添加CIDR范围
func (a *IPAnalyzer) AddCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// 检查是否已存在
	for _, existing := range a.cidrRanges {
		if existing.String() == ipNet.String() {
			return nil
		}
	}

	a.cidrRanges = append(a.cidrRanges, ipNet)
	return nil
}

// RemoveCIDR 移除CIDR范围
func (a *IPAnalyzer) RemoveCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for i, existing := range a.cidrRanges {
		if existing.String() == ipNet.String() {
			a.cidrRanges = append(a.cidrRanges[:i], a.cidrRanges[i+1:]...)
			return nil
		}
	}

	return nil
}

// IsInCIDR 检查IP是否在CIDR范围内
func (a *IPAnalyzer) IsInCIDR(ipStr string) (bool, error) {
	// 先检查缓存
	a.ipCache.mu.RLock()
	if cached, ok := a.ipCache.cache[ipStr]; ok {
		if time.Since(cached.CachedAt) < a.ipCache.ttl {
			a.ipCache.mu.RUnlock()
			return cached.IsWhitelisted, nil
		}
	}
	a.ipCache.mu.RUnlock()

	// 解析IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, nil
	}

	// 检查是否在任何CIDR范围内
	a.mu.RLock()
	for _, ipNet := range a.cidrRanges {
		if ipNet.Contains(ip) {
			a.mu.RUnlock()

			// 更新缓存
			a.updateCache(ipStr, ip, ipNet, true)
			return true, nil
		}
	}
	a.mu.RUnlock()

	// 更新缓存（不在白名单）
	a.updateCache(ipStr, ip, nil, false)
	return false, nil
}

// updateCache 更新缓存
func (a *IPAnalyzer) updateCache(ipStr string, ip net.IP, ipNet *net.IPNet, isWhitelisted bool) {
	a.ipCache.mu.Lock()
	a.ipCache.cache[ipStr] = &CachedIP{
		IP:            ip,
		IPNet:         ipNet,
		IsWhitelisted: isWhitelisted,
		CachedAt:      time.Now(),
	}
	a.ipCache.mu.Unlock()
}

// ClearCache 清除缓存
func (a *IPAnalyzer) ClearCache() {
	a.ipCache.mu.Lock()
	a.ipCache.cache = make(map[string]*CachedIP)
	a.ipCache.mu.Unlock()
}

// GetCIDRRanges 获取所有CIDR范围
func (a *IPAnalyzer) GetCIDRRanges() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ranges := make([]string, len(a.cidrRanges))
	for i, ipNet := range a.cidrRanges {
		ranges[i] = ipNet.String()
	}
	return ranges
}

// AddAllowedDomain 添加允许的域名
func (r *RefererRules) AddAllowedDomain(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 清理域名
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "www.")

	// 添加精确匹配
	r.allowedDomains[domain] = true

	// 添加后缀匹配
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		suffix := strings.Join(parts[1:], ".")
		r.allowedSuffixes[suffix] = true
	}

	// 添加正则表达式模式
	// 允许任意子域名
	pattern := regexp.MustCompile(`^https?://[^/]*\.` + regexp.QuoteMeta(domain) + `(/|$)`)
	r.allowedPatterns = append(r.allowedPatterns, pattern)
}

// AddBlockedPattern 添加阻止模式
func (r *RefererRules) AddBlockedPattern(pattern string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 编译正则表达式
	regex, err := regexp.Compile(pattern)
	if err == nil {
		r.blockedPatterns = append(r.blockedPatterns, regex)
	} else {
		// 如果不是有效的正则表达式，作为普通字符串处理
		escaped := regexp.QuoteMeta(pattern)
		regex = regexp.MustCompile("^" + escaped + "$")
		r.blockedPatterns = append(r.blockedPatterns, regex)
	}
}

// VerifyRefererEnhanced 增强版Referer验证
func (auth *EnhancedURLAuth) VerifyRefererEnhanced(referer, targetURL string) *AuthResult {
	if !auth.config.RefererConfig.Enabled {
		return &AuthResult{
			Success:  true,
			Reason:   "Referer验证已禁用",
			AuthType: "referer",
		}
	}

	// 空Referer处理
	if referer == "" {
		if auth.config.RefererConfig.AllowEmptyReferer {
			return &AuthResult{
				Success:  true,
				Reason:   "允许空Referer",
				AuthType: "referer",
			}
		}
		return &AuthResult{
			Success:  false,
			Reason:   "禁止空Referer访问",
			AuthType: "referer",
		}
	}

	// 解析Referer
	refURL, err := url.Parse(referer)
	if err != nil {
		return &AuthResult{
			Success:  false,
			Reason:   "无效的Referer格式",
			AuthType: "referer",
		}
	}

	// 获取主机名（小写）
	host := strings.ToLower(refURL.Host)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// 使用增强的Referer规则验证
	auth.refererRules.mu.RLock()
	defer auth.refererRules.mu.RUnlock()

	// 检查阻止列表
	for _, pattern := range auth.refererRules.blockedPatterns {
		if pattern.MatchString(referer) || pattern.MatchString(host) {
			return &AuthResult{
				Success:  false,
				Reason:   "Referer被阻止",
				AuthType: "referer",
			}
		}
	}

	// 检查允许列表
	// 1. 精确匹配
	if auth.refererRules.allowedDomains[host] {
		return &AuthResult{
			Success:  true,
			Reason:   "Referer验证通过（精确匹配）",
			AuthType: "referer",
		}
	}

	// 2. 后缀匹配
	for suffix := range auth.refererRules.allowedSuffixes {
		if strings.HasSuffix(host, "."+suffix) {
			return &AuthResult{
				Success:  true,
				Reason:   "Referer验证通过（后缀匹配）",
				AuthType: "referer",
			}
		}
	}

	// 3. 正则表达式匹配
	for _, pattern := range auth.refererRules.allowedPatterns {
		if pattern.MatchString(referer) {
			return &AuthResult{
				Success:  true,
				Reason:   "Referer验证通过（模式匹配）",
				AuthType: "referer",
			}
		}
	}

	return &AuthResult{
		Success:  false,
		Reason:   "Referer不在允许列表",
		AuthType: "referer",
	}
}

// authenticateByIPEnhanced 增强版IP白名单鉴权（支持CIDR）
func (auth *EnhancedURLAuth) authenticateByIPEnhanced(req *AuthRequest) *AuthResult {
	// 检查简单IP白名单
	for _, allowedIP := range auth.config.WhiteListConfig.IPWhitelist {
		if req.IP == allowedIP {
			return &AuthResult{
				Success:  true,
				Reason:   "IP在白名单中（精确匹配）",
				AuthType: "ip_whitelist",
			}
		}
	}

	// 检查CIDR白名单
	inCIDR, err := auth.ipAnalyzer.IsInCIDR(req.IP)
	if err == nil && inCIDR {
		return &AuthResult{
			Success:  true,
			Reason:   "IP在白名单中（CIDR匹配）",
			AuthType: "ip_whitelist",
		}
	}

	return &AuthResult{
		Success:  false,
		Reason:   "IP不在白名单中",
		AuthType: "ip_whitelist",
	}
}

// authenticateBySignEnhanced 增强版签名鉴权（支持多密钥）
func (auth *EnhancedURLAuth) authenticateBySignEnhanced(req *AuthRequest) *AuthResult {
	// 获取签名参数
	sign := req.Query[auth.config.SignConfig.SignParamName]
	timestampStr := req.Query[auth.config.SignConfig.TimestampParamName]

	if sign == "" || timestampStr == "" {
		return &AuthResult{
			Success:  false,
			Reason:   "缺少签名参数",
			AuthType: "sign",
		}
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return &AuthResult{
			Success:  false,
			Reason:   "无效的时间戳",
			AuthType: "sign",
		}
	}

	// 验证时间戳
	now := time.Now().Unix()
	if int64(math.Abs(float64(now-timestamp))) > int64(auth.config.ClockSkewTolerance.Seconds()) {
		return &AuthResult{
			Success:  false,
			Reason:   "时间戳已过期或无效",
			AuthType: "sign",
		}
	}

	// 尝试使用配置的密钥验证
	_, expectedSign, err := auth.GenerateSign(req.URL, auth.config.SignConfig.SecretKey, timestamp)
	if err != nil {
		return &AuthResult{
			Success:  false,
			Reason:   "生成签名失败",
			AuthType: "sign",
		}
	}

	if subtle.ConstantTimeCompare([]byte(sign), []byte(expectedSign)) == 1 {
		return &AuthResult{
			Success:   true,
			Reason:    "签名验证通过",
			AuthType:  "sign",
			ExpiresAt: time.Unix(timestamp, 0).Add(auth.config.ExpiryTime),
		}
	}

	// 尝试使用额外的密钥验证
	auth.mu.RLock()
	for keyID, secret := range auth.secrets {
		_, expectedSign, err := auth.GenerateSign(req.URL, secret.Key, timestamp)
		if err != nil {
			continue
		}

		if subtle.ConstantTimeCompare([]byte(sign), []byte(expectedSign)) == 1 {
			auth.mu.RUnlock()
			return &AuthResult{
				Success:   true,
				Reason:    "签名验证通过（密钥ID: " + keyID + "）",
				AuthType:  "sign",
				ExpiresAt: time.Unix(timestamp, 0).Add(auth.config.ExpiryTime),
				Metadata: map[string]interface{}{
					"key_id": keyID,
				},
			}
		}
	}
	auth.mu.RUnlock()

	return &AuthResult{
		Success:  false,
		Reason:   "签名验证失败",
		AuthType: "sign",
	}
}

// AuthenticateEnhanced 综合鉴权（增强版）
func (auth *EnhancedURLAuth) AuthenticateEnhanced(req *AuthRequest) *AuthResult {
	switch auth.config.AuthType {
	case "sign":
		return auth.authenticateBySignEnhanced(req)
	case "token":
		return auth.authenticateByToken(req)
	case "ip_whitelist":
		return auth.authenticateByIPEnhanced(req)
	case "referer":
		return auth.VerifyRefererEnhanced(req.Referer, req.URL)
	default:
		return &AuthResult{
			Success: false,
			Reason:  "未知的鉴权方式",
		}
	}
}

// GetAllowedDomains 获取允许的域名列表
func (r *RefererRules) GetAllowedDomains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domains := make([]string, 0, len(r.allowedDomains))
	for domain := range r.allowedDomains {
		domains = append(domains, domain)
	}
	return domains
}

// GetBlockedPatterns 获取阻止的模式列表
func (r *RefererRules) GetBlockedPatterns() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	patterns := make([]string, 0, len(r.blockedPatterns))
	for _, pattern := range r.blockedPatterns {
		patterns = append(patterns, pattern.String())
	}
	return patterns
}

package security

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestAnalyzer 请求行为分析器
type RequestAnalyzer struct {
	mu             sync.RWMutex
	profiles       map[string]*RequestProfile
	ipProfiles     map[string]*IPBehaviorProfile
	requestCounts  map[string]int64
	lastRequest    map[string]time.Time
	logger         Logger
	stats          AnalyzerStats
	config         *AnalysisConfig
}

// RequestProfile 请求档案
type RequestProfile struct {
	UserID       string
	SessionID    string
	Requests     []RequestRecord
	FirstSeen    time.Time
	LastSeen     time.Time
	TotalReqs    int64
	TotalErrs    int64
	Score        float64
	RiskLevel    RiskLevel
	Flags        []string
	mu           sync.RWMutex
}

// RequestRecord 请求记录
type RequestRecord struct {
	Timestamp    time.Time
	Path         string
	Method       string
	UserAgent    string
	Referer      string
	StatusCode   int
	ResponseTime time.Duration
	SourceIP     string
}

// IPBehaviorProfile IP 行为档案
type IPBehaviorProfile struct {
	IP           string
	Requests     int64
	FirstSeen    time.Time
	LastSeen     time.Time
	Countries    map[string]int
	UserAgents   map[string]int
	Paths        map[string]int
	StatusCodes  map[int]int
	Suspicious   bool
	Score        float64
	BlockExpires time.Time
}

// AnalyzerStats 分析器统计
type AnalyzerStats struct {
	TotalAnalyzed   int64
	SuspiciousFound int64
	BlockedTotal    int64
	ProfilesActive  int64
	mu              sync.RWMutex
}

// RiskLevel 风险等级
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// AnalysisResult 分析结果
type AnalysisResult struct {
	RiskLevel     RiskLevel
	Score         float64
	Reasons       []string
	Action        Action
	RequireCaptcha bool
	BlockExpires  time.Time
}

// Action 动作
type Action string

const (
	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
)

// AnalysisConfig 分析配置
type AnalysisConfig struct {
	// 评分权重
	UAWeight           float64
	RefererWeight      float64
	FrequencyWeight    float64
	PathWeight         float64
	StatusCodeWeight   float64

	// 阈值
	LowRiskThreshold    float64
	MediumRiskThreshold float64
	HighRiskThreshold   float64

	// 检查项
	CheckUA        bool
	CheckReferer   bool
	CheckFrequency bool
	CheckPath      bool
	CheckStatusCode bool

	// 频率限制
	MaxRequestsPerMin int64
	MaxErrRate        float64

	// 路径模式
	AdminPaths     []string
	SensitivePaths []string
	PublicPaths    []string

	// 用户代理
	BannedUAs      []string
	SuspiciousUAs  []string

	// 国家
	BannedCountries []string
}

// NewRequestAnalyzer 创建请求行为分析器
func NewRequestAnalyzer(config *AnalysisConfig) *RequestAnalyzer {
	if config == nil {
		config = &AnalysisConfig{
			UAWeight:            0.2,
			RefererWeight:       0.15,
			FrequencyWeight:     0.25,
			PathWeight:          0.2,
			StatusCodeWeight:    0.2,
			LowRiskThreshold:    30,
			MediumRiskThreshold: 50,
			HighRiskThreshold:   70,
			CheckUA:             true,
			CheckReferer:        true,
			CheckFrequency:      true,
			CheckPath:           true,
			CheckStatusCode:     true,
			MaxRequestsPerMin:   1000,
			MaxErrRate:          0.5,
			AdminPaths:          []string{"/admin", "/wp-admin", "/manage", "/console"},
			SensitivePaths:      []string{"/api/user", "/api/account", "/api/payment", "/api/order"},
			PublicPaths:         []string{"/api/public", "/api/health", "/api/info"},
			BannedUAs:           []string{"curl", "wget", "python", "java", "bot", "crawler", "spider"},
			SuspiciousUAs:       []string{"", "Mozilla/4.0", "Mozilla/3.0"},
		}
	}

	return &RequestAnalyzer{
		profiles:      make(map[string]*RequestProfile),
		ipProfiles:    make(map[string]*IPBehaviorProfile),
		requestCounts: make(map[string]int64),
		lastRequest:   make(map[string]time.Time),
		logger:        &DefaultLogger{},
		config:        config,
	}
}

// Analyze 分析请求
func (ra *RequestAnalyzer) Analyze(ctx context.Context, req *http.Request) *AnalysisResult {
	atomic.AddInt64(&ra.stats.TotalAnalyzed, 1)

	result := &AnalysisResult{
		RiskLevel: RiskLevelLow,
		Score:     0,
		Reasons:   make([]string, 0),
		Action:    ActionAllow,
	}

	// 获取客户端信息
	clientIP := getClientIP(req)
	userAgent := req.UserAgent()
	referer := req.Referer()
	path := req.URL.Path
	method := req.Method

	// 1. 用户代理分析
	if ra.analyzeUA(userAgent, result) {
		result.Score += 30
	}

	// 2. 来源分析
	if ra.analyzeReferer(referer, path, result) {
		result.Score += 20
	}

	// 3. 路径分析
	if ra.analyzePath(path, method, result) {
		result.Score += 25
	}

	// 4. 频率分析
	if ra.analyzeFrequency(clientIP, result) {
		result.Score += 25
	}

	// 5. 状态码分析
	if ra.analyzeStatusCode(result) {
		result.Score += 20
	}

	// 更新 IP 档案
	ra.updateIPProfile(clientIP, userAgent, path, 200)

	// 确定风险等级和动作
	ra.determineAction(result)

	return result
}

// analyzeUA 分析用户代理
func (ra *RequestAnalyzer) analyzeUA(ua string, result *AnalysisResult) bool {
	if ua == "" {
		result.Reasons = append(result.Reasons, "missing_user_agent")
		return true
	}

	bannedUAs := []string{"curl", "wget", "python", "java", "bot", "crawler", "spider", "scrapy"}
	uaLower := strings.ToLower(ua)

	for _, banned := range bannedUAs {
		if strings.Contains(uaLower, banned) {
			result.Reasons = append(result.Reasons, "suspicious_ua:"+banned)
			return true
		}
	}

	return false
}

// analyzeReferer 分析来源
func (ra *RequestAnalyzer) analyzeReferer(referer, path string, result *AnalysisResult) bool {
	// 敏感操作必须有来源
	sensitivePaths := []string{"/api/login", "/api/register", "/api/order", "/api/payment"}
	for _, sp := range sensitivePaths {
		if strings.HasPrefix(path, sp) && referer == "" {
			result.Reasons = append(result.Reasons, "missing_referer_for_sensitive_path")
			return true
		}
	}

	// 检查 referer 是否来自可信域名
	// 这里简化处理，实际应该检查域名
	if referer != "" && !strings.Contains(referer, "://") {
		result.Reasons = append(result.Reasons, "invalid_referer_format")
		return true
	}

	return false
}

// analyzePath 分析路径
func (ra *RequestAnalyzer) analyzePath(path, method string, result *AnalysisResult) bool {
	// 检查管理路径
	adminPaths := []string{"/admin", "/wp-admin", "/manage", "/console", "/dashboard"}
	for _, ap := range adminPaths {
		if strings.HasPrefix(path, ap) {
			// 管理路径只能是特定方法
			if method != "GET" && method != "POST" {
				result.Reasons = append(result.Reasons, "admin_path_with_unsafe_method:"+method)
				return true
			}
		}
	}

	// 检查敏感操作
	sensitivePaths := []string{"/api/user", "/api/account", "/api/payment", "/api/order", "/api/delete"}
	for _, sp := range sensitivePaths {
		if strings.HasPrefix(path, sp) {
			if method == "GET" {
				result.Reasons = append(result.Reasons, "sensitive_path_with_get:"+sp)
				return true
			}
		}
	}

	return false
}

// analyzeFrequency 分析频率
func (ra *RequestAnalyzer) analyzeFrequency(ip string, result *AnalysisResult) bool {
	ra.mu.RLock()
	count := ra.requestCounts[ip]
	lastTime := ra.lastRequest[ip]
	ra.mu.RUnlock()

	now := time.Now()

	// 检查请求间隔
	if !lastTime.IsZero() {
		interval := now.Sub(lastTime)
		if interval < time.Millisecond*10 {
			result.Reasons = append(result.Reasons, "extremely_high_request_frequency")
			return true
		}
	}

	if count > 1000 {
		result.Reasons = append(result.Reasons, "high_frequency_requests")
		return true
	}

	// 增加计数
	ra.mu.Lock()
	ra.requestCounts[ip]++
	ra.lastRequest[ip] = now
	ra.mu.Unlock()

	return false
}

// analyzeStatusCode 分析状态码
func (ra *RequestAnalyzer) analyzeStatusCode(result *AnalysisResult) bool {
	// 状态码分析在响应后进行，这里预留接口
	return false
}

// determineAction 确定动作
func (ra *RequestAnalyzer) determineAction(result *AnalysisResult) {
	switch {
	case result.Score >= 80:
		result.RiskLevel = RiskLevelCritical
		result.Action = ActionBlock
		result.BlockExpires = time.Now().Add(1 * time.Hour)
	case result.Score >= 60:
		result.RiskLevel = RiskLevelHigh
		result.Action = ActionChallenge
		result.RequireCaptcha = true
	case result.Score >= 40:
		result.RiskLevel = RiskLevelMedium
		result.Action = ActionChallenge
	default:
		result.RiskLevel = RiskLevelLow
		result.Action = ActionAllow
	}
}

// updateIPProfile 更新 IP 档案
func (ra *RequestAnalyzer) updateIPProfile(ip, ua, path string, statusCode int) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	profile, ok := ra.ipProfiles[ip]
	if !ok {
		profile = &IPBehaviorProfile{
			IP:          ip,
			FirstSeen:   time.Now(),
			Countries:   make(map[string]int),
			UserAgents:  make(map[string]int),
			Paths:       make(map[string]int),
			StatusCodes: make(map[int]int),
		}
		ra.ipProfiles[ip] = profile
	}

	profile.Requests++
	profile.LastSeen = time.Now()
	profile.UserAgents[ua]++
	profile.Paths[path]++
	profile.StatusCodes[statusCode]++
}

// GetIPProfile 获取 IP 档案
func (ra *RequestAnalyzer) GetIPProfile(ip string) (*IPBehaviorProfile, bool) {
	ra.mu.RLock()
	defer ra.mu.RUnlock()

	profile, ok := ra.ipProfiles[ip]
	return profile, ok
}

// BlockIP 封禁 IP
func (ra *RequestAnalyzer) BlockIP(ip string, duration time.Duration) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	profile, ok := ra.ipProfiles[ip]
	if ok {
		profile.Suspicious = true
		profile.BlockExpires = time.Now().Add(duration)
		profile.Score = 100
	}

	atomic.AddInt64(&ra.stats.BlockedTotal, 1)
	atomic.AddInt64(&ra.stats.SuspiciousFound, 1)
}

// UnblockIP 解封 IP
func (ra *RequestAnalyzer) UnblockIP(ip string) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	profile, ok := ra.ipProfiles[ip]
	if ok {
		profile.Suspicious = false
		profile.BlockExpires = time.Time{}
		profile.Score = 0
	}
}

// IsBlocked 检查是否被封禁
func (ra *RequestAnalyzer) IsBlocked(ip string) bool {
	ra.mu.RLock()
	defer ra.mu.RUnlock()

	profile, ok := ra.ipProfiles[ip]
	if !ok {
		return false
	}

	if profile.Suspicious && profile.BlockExpires.After(time.Now()) {
		return true
	}

	return false
}

// GetStats 获取统计
func (ra *RequestAnalyzer) GetStats() AnalyzerStats {
	return AnalyzerStats{
		TotalAnalyzed:   atomic.LoadInt64(&ra.stats.TotalAnalyzed),
		SuspiciousFound: atomic.LoadInt64(&ra.stats.SuspiciousFound),
		BlockedTotal:    atomic.LoadInt64(&ra.stats.BlockedTotal),
		ProfilesActive:  int64(len(ra.profiles)),
	}
}

// GetHighRiskIPs 获取高风险 IP 列表
func (ra *RequestAnalyzer) GetHighRiskIPs() []string {
	ra.mu.RLock()
	defer ra.mu.RUnlock()

	ips := make([]string, 0)
	for ip, profile := range ra.ipProfiles {
		if profile.Score > 70 || profile.Requests > 10000 {
			ips = append(ips, ip)
		}
	}
	return ips
}

// Reset 重置分析器
func (ra *RequestAnalyzer) Reset() {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	ra.profiles = make(map[string]*RequestProfile)
	ra.ipProfiles = make(map[string]*IPBehaviorProfile)
	ra.requestCounts = make(map[string]int64)
	ra.lastRequest = make(map[string]time.Time)
	ra.stats = AnalyzerStats{}
}

// getClientIP 获取客户端 IP
func getClientIP(req *http.Request) string {
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	xri := req.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	addr, _, _ := net.SplitHostPort(req.RemoteAddr)
	return addr
}

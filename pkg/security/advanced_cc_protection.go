package security

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sync"
	"time"
)

// AdvancedCCProtection 高级CC防护系统
type AdvancedCCProtection struct {
	config        *AdvancedCCConfig
	detector      *CCAttackDetector
	mitigator     *CCAttackMitigator
	challengeMgr  *ChallengeManager
	resourceRules map[string]*ResourceProtectionRule
	adaptiveRules []*AdaptiveProtectionRule
	whiteList     map[string]bool
	blackList     map[string]bool
	mu            sync.RWMutex
	stats         *AdvancedCCStats
	ctx           context.Context
	cancel        context.CancelFunc
}

// AdvancedCCConfig 高级CC防护配置
type AdvancedCCConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 检测模式
	DetectionMode string `yaml:"detection_mode"` // "standalone", "distributed"

	// 防护模式
	ProtectionMode string `yaml:"protection_mode"` // "standard", "strict", "adaptive"

	// 全局阈值
	GlobalThresholds *GlobalThresholds `yaml:"global_thresholds"`

	// 检测配置
	Detection *CCDetectionConfig `yaml:"detection"`

	// 挑战配置
	Challenge *AdvancedChallengeConfig `yaml:"challenge"`

	// 自适应配置
	Adaptive *AdaptiveConfig `yaml:"adaptive"`

	// 资源保护规则
	ResourceRules []ResourceProtectionRuleConfig `yaml:"resource_rules"`

	// 响应策略
	Response *CCResponseConfig `yaml:"response"`

	// 白名单
	WhiteList []string `yaml:"white_list"`

	// 黑名单
	BlackList []string `yaml:"black_list"`
}

// GlobalThresholds 全局阈值
type GlobalThresholds struct {
	// 每秒请求数
	RequestsPerSecond int `yaml:"requests_per_second"`

	// 并发连接数
	ConcurrentConnections int `yaml:"concurrent_connections"`

	// 带宽阈值 (Mbps)
	BandwidthMbps float64 `yaml:"bandwidth_mbps"`

	// 单IP请求数
	PerIPRequests int `yaml:"per_ip_requests"`

	// 单IP连接数
	PerIPConnections int `yaml:"per_ip_connections"`

	// 请求大小限制
	MaxRequestSize int64 `yaml:"max_request_size"`
}

// CCDetectionConfig 检测配置
type CCDetectionConfig struct {
	// 启用签名检测
	SignatureDetection bool `yaml:"signature_detection"`

	// 启用行为分析
	BehavioralAnalysis bool `yaml:"behavioral_analysis"`

	// 启用机器学习检测
	MLDetection bool `yaml:"ml_detection"`

	// 启用速率检测
	RateDetection bool `yaml:"rate_detection"`

	// 启用连接检测
	ConnectionDetection bool `yaml:"connection_detection"`

	// 检测间隔
	DetectionInterval time.Duration `yaml:"detection_interval"`

	// 敏感度级别
	SensitivityLevel string `yaml:"sensitivity_level"` // "low", "medium", "high"
}

// AdvancedChallengeConfig 挑战配置
type AdvancedChallengeConfig struct {
	// 启用挑战
	Enabled bool `yaml:"enabled"`

	// 启用JavaScript挑战
	JSChallenge bool `yaml:"js_challenge"`

	// 启用验证码挑战
	CAPTCHAChallenge bool `yaml:"captcha_challenge"`

	// 启用滑动验证
	SliderChallenge bool `yaml:"slider_challenge"`

	// 启用行为验证
	BehavioralChallenge bool `yaml:"behavioral_challenge"`

	// 挑战超时时间
	ChallengeTimeout time.Duration `yaml:"challenge_timeout"`

	// 挑战有效期
	ChallengeValidDuration time.Duration `yaml:"challenge_valid_duration"`

	// 重试限制
	MaxRetries int `yaml:"max_retries"`

	// 难度级别
	DifficultyLevel int `yaml:"difficulty_level"` // 1-10

	// 自动升级
	AutoUpgrade bool `yaml:"auto_upgrade"`
}

// AdaptiveConfig 自适应配置
type AdaptiveConfig struct {
	// 启用自适应防护
	Enabled bool `yaml:"enabled"`

	// 自动调整阈值
	AutoThreshold bool `yaml:"auto_threshold"`

	// 最小阈值百分比
	MinThresholdPercent float64 `yaml:"min_threshold_percent"`

	// 最大阈值百分比
	MaxThresholdPercent float64 `yaml:"max_threshold_percent"`

	// 调整间隔
	AdjustmentInterval time.Duration `yaml:"adjustment_interval"`

	// 学习周期
	LearningPeriod time.Duration `yaml:"learning_period"`
}

// ResourceProtectionRuleConfig 资源保护规则配置
type ResourceProtectionRuleConfig struct {
	// 规则名称
	Name string `yaml:"name"`

	// 匹配类型
	MatchType string `yaml:"match_type"` // "extension", "path", "full_path", "regex"

	// 匹配值
	MatchValue string `yaml:"match_value"`

	// 请求阈值
	RequestThreshold int `yaml:"request_threshold"`

	// 时间窗口
	TimeWindow time.Duration `yaml:"time_window"`

	// 封锁时间
	BlockDuration time.Duration `yaml:"block_duration"`

	// 挑战类型
	ChallengeType string `yaml:"challenge_type"`

	// 优先级
	Priority int `yaml:"priority"`
}

// ResourceProtectionRule 资源保护规则
type ResourceProtectionRule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	MatchType        string        `json:"match_type"`
	MatchValue       string        `json:"match_value"`
	RequestThreshold int           `json:"request_threshold"`
	TimeWindow       time.Duration `json:"time_window"`
	BlockDuration    time.Duration `json:"block_duration"`
	ChallengeType    string        `json:"challenge_type"`
	Priority         int           `json:"priority"`
	Enabled          bool          `json:"enabled"`
}

// AdaptiveProtectionRule 自适应保护规则
type AdaptiveProtectionRule struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	ResourceType     string  `json:"resource_type"`
	BaselineQPS      float64 `json:"baseline_qps"`
	ThresholdPercent float64 `json:"threshold_percent"`
	CurrentThreshold float64 `json:"current_threshold"`
	Enabled          bool    `json:"enabled"`
}

// CCResponseConfig 响应配置
type CCResponseConfig struct {
	// 响应模式
	Mode string `yaml:"mode"` // "rate_limit", "challenge", "block", "redirect"

	// 限速配置
	RateLimit *CCRateLimitConfig `yaml:"rate_limit"`

	// 重定向配置
	Redirect *CCRedirectConfig `yaml:"redirect"`

	// 阻断配置
	Block *CCBlockConfig `yaml:"block"`
}

// CCRateLimitConfig 限速配置
type CCRateLimitConfig struct {
	// 限制模式
	Mode string `yaml:"mode"` // "per_ip", "global"

	// 请求数限制
	MaxRequests int `yaml:"max_requests"`

	// 时间窗口
	Window time.Duration `yaml:"window"`

	// 惩罚时间
	PenaltyDuration time.Duration `yaml:"penalty_duration"`

	// 延迟响应
	DelayResponse bool `yaml:"delay_response"`

	// 延迟时间
	DelayTime time.Duration `yaml:"delay_time"`
}

// CCRedirectConfig 重定向配置
type CCRedirectConfig struct {
	// 启用重定向
	Enabled bool `yaml:"enabled"`

	// 重定向URL
	URL string `yaml:"url"`

	// 重定向状态码
	StatusCode int `yaml:"status_code"`

	// 重定向条件
	Condition string `yaml:"condition"`
}

// CCBlockConfig 阻断配置
type CCBlockConfig struct {
	// 启用阻断
	Enabled bool `yaml:"enabled"`

	// 阻断状态码
	StatusCode int `yaml:"status_code"`

	// 阻断响应内容
	Response string `yaml:"response"`

	// 阻断响应Content-Type
	ContentType string `yaml:"content_type"`
}

// AdvancedCCStats 高级CC防护统计
type AdvancedCCStats struct {
	TotalRequests        int64                     `json:"total_requests"`
	AllowedRequests      int64                     `json:"allowed_requests"`
	BlockedRequests      int64                     `json:"blocked_requests"`
	ChallengedRequests   int64                     `json:"challenged_requests"`
	RateLimitedRequests  int64                     `json:"rate_limited_requests"`
	DetectedAttacks      int64                     `json:"detected_attacks"`
	ActiveThreatIPs      int                       `json:"active_threat_ips"`
	CurrentQPS           float64                   `json:"current_qps"`
	PeakQPS              float64                   `json:"peak_qps"`
	CurrentBandwidth     float64                   `json:"current_bandwidth"`
	PeakBandwidth        float64                   `json:"peak_bandwidth"`
	ChallengeSuccessRate float64                   `json:"challenge_success_rate"`
	ProtectionLevel      string                    `json:"protection_level"`
	AttackTypes          map[string]int64          `json:"attack_types"`
	ResourceProtection   map[string]*ResourceStats `json:"resource_protection"`
	AdaptiveThreshold    float64                   `json:"adaptive_threshold"`
	mu                   sync.RWMutex
}

// ResourceStats 资源统计
type ResourceStats struct {
	Requests   int64     `json:"requests"`
	Blocked    int64     `json:"blocked"`
	Challenged int64     `json:"challenged"`
	LastAttack time.Time `json:"last_attack"`
	CurrentQPS float64   `json:"current_qps"`
}

// ChallengeInfo 挑战信息
type ChallengeInfo struct {
	// 挑战ID
	ID string `json:"id"`

	// 挑战类型
	Type string `json:"type"` // "js", "captcha", "slider", "behavioral"

	// 挑战令牌
	Token string `json:"token"`

	// 过期时间
	ExpiresAt time.Time `json:"expires_at"`

	// 状态
	Status string `json:"status"` // "pending", "completed", "expired"

	// 重试次数
	RetryCount int `json:"retry_count"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`
}

// CCRequestInfo CC攻击检测请求信息
type CCRequestInfo struct {
	IP           string            `json:"ip"`
	UserAgent    string            `json:"user_agent"`
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers"`
	BodySize     int64             `json:"body_size"`
	Timestamp    time.Time         `json:"timestamp"`
	ConnectionID string            `json:"connection_id"`
	Referer      string            `json:"referer"`
	Cookies      map[string]string `json:"cookies"`
}

// NewAdvancedCCProtection 创建高级CC防护
func NewAdvancedCCProtection(config *AdvancedCCConfig) *AdvancedCCProtection {
	if config == nil {
		config = &AdvancedCCConfig{
			Enabled:        true,
			DetectionMode:  "standalone",
			ProtectionMode: "standard",
		}
	}
	if config.Detection == nil {
		config.Detection = &CCDetectionConfig{}
	}
	if config.Response == nil {
		config.Response = &CCResponseConfig{Mode: "challenge"}
	}

	ctx, cancel := context.WithCancel(context.Background())

	protection := &AdvancedCCProtection{
		config:        config,
		detector:      NewCCAttackDetector(config),
		mitigator:     NewCCAttackMitigator(config),
		challengeMgr:  NewChallengeManager(config.Challenge),
		resourceRules: make(map[string]*ResourceProtectionRule),
		adaptiveRules: make([]*AdaptiveProtectionRule, 0),
		whiteList:     make(map[string]bool),
		blackList:     make(map[string]bool),
		stats:         &AdvancedCCStats{AttackTypes: make(map[string]int64), ResourceProtection: make(map[string]*ResourceStats)},
		ctx:           ctx,
		cancel:        cancel,
	}

	// 加载白名单和黑名单
	for _, ip := range config.WhiteList {
		protection.whiteList[ip] = true
	}
	for _, ip := range config.BlackList {
		protection.blackList[ip] = true
	}

	// 加载资源保护规则
	protection.loadResourceRules()

	// 启动后台任务
	go protection.runBackgroundTasks()

	return protection
}

// loadResourceRules 加载资源保护规则
func (p *AdvancedCCProtection) loadResourceRules() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, ruleConfig := range p.config.ResourceRules {
		rule := &ResourceProtectionRule{
			ID:               fmt.Sprintf("resource_%d", len(p.resourceRules)+1),
			Name:             ruleConfig.Name,
			MatchType:        ruleConfig.MatchType,
			MatchValue:       ruleConfig.MatchValue,
			RequestThreshold: ruleConfig.RequestThreshold,
			TimeWindow:       ruleConfig.TimeWindow,
			BlockDuration:    ruleConfig.BlockDuration,
			ChallengeType:    ruleConfig.ChallengeType,
			Priority:         ruleConfig.Priority,
			Enabled:          true,
		}
		p.resourceRules[rule.ID] = rule

		// 初始化资源统计
		p.stats.ResourceProtection[rule.ID] = &ResourceStats{}
	}
}

// CheckRequest 检查请求
func (p *AdvancedCCProtection) CheckRequest(req *CCRequestInfo) *CCCheckResult {
	startTime := time.Now()

	p.mu.RLock()
	enabled := p.config.Enabled
	p.mu.RUnlock()

	if !enabled {
		return &CCCheckResult{
			Allowed:        true,
			Action:         "allow",
			ProcessingTime: time.Since(startTime),
		}
	}

	// 1. 检查白名单
	if p.isWhiteListed(req.IP) {
		p.updateStats(func(s *AdvancedCCStats) {
			s.AllowedRequests++
		})
		return &CCCheckResult{
			Allowed:        true,
			Action:         "allow",
			Reason:         "白名单",
			ProcessingTime: time.Since(startTime),
		}
	}

	// 2. 检查黑名单
	if p.isBlackListed(req.IP) {
		p.updateStats(func(s *AdvancedCCStats) {
			s.BlockedRequests++
		})
		return &CCCheckResult{
			Allowed:        false,
			Action:         "block",
			Reason:         "黑名单",
			ProcessingTime: time.Since(startTime),
		}
	}

	// 3. 资源保护检查
	resourceResult := p.checkResourceProtection(req)
	if resourceResult.Action != "allow" {
		p.updateStats(func(s *AdvancedCCStats) {
			s.BlockedRequests++
		})
		return resourceResult
	}

	// 4. 攻击检测
	attack := p.detector.Detect(req)
	if attack != nil {
		return p.handleAttack(attack, req, startTime)
	}

	// 5. 自适应检查
	if p.config.Adaptive != nil && p.config.Adaptive.Enabled {
		if !p.checkAdaptiveProtection(req) {
			return &CCCheckResult{
				Allowed:        false,
				Action:         "challenge",
				Reason:         "自适应防护",
				ProcessingTime: time.Since(startTime),
			}
		}
	}

	p.updateStats(func(s *AdvancedCCStats) {
		s.AllowedRequests++
	})

	return &CCCheckResult{
		Allowed:        true,
		Action:         "allow",
		ProcessingTime: time.Since(startTime),
	}
}

// isWhiteListed 检查白名单
func (p *AdvancedCCProtection) isWhiteListed(ip string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.whiteList[ip]
}

// isBlackListed 检查黑名单
func (p *AdvancedCCProtection) isBlackListed(ip string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.blackList[ip]
}

// checkResourceProtection 检查资源保护
func (p *AdvancedCCProtection) checkResourceProtection(req *CCRequestInfo) *CCCheckResult {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, rule := range p.resourceRules {
		if !rule.Enabled {
			continue
		}

		matched := p.matchResourceRule(rule, req)
		if matched {
			// 更新资源统计
			if stats, ok := p.stats.ResourceProtection[rule.ID]; ok {
				stats.Requests++
				stats.CurrentQPS = float64(stats.Requests) / rule.TimeWindow.Seconds()
			}

			// 检查是否超出阈值
			if stats, ok := p.stats.ResourceProtection[rule.ID]; ok {
				if stats.CurrentQPS > float64(rule.RequestThreshold) {
					stats.Blocked++
					stats.LastAttack = time.Now()

					return &CCCheckResult{
						Allowed:           false,
						Action:            rule.ChallengeType,
						Reason:            fmt.Sprintf("资源保护: %s", rule.Name),
						MatchedResourceID: rule.ID,
					}
				}
			}
		}
	}

	return &CCCheckResult{Allowed: true, Action: "allow"}
}

// matchResourceRule 匹配资源规则
func (p *AdvancedCCProtection) matchResourceRule(rule *ResourceProtectionRule, req *CCRequestInfo) bool {
	switch rule.MatchType {
	case "extension":
		return p.matchExtension(rule.MatchValue, req.URL)
	case "path":
		return p.matchPath(rule.MatchValue, req.URL)
	case "full_path":
		return req.URL == rule.MatchValue
	case "regex":
		if rule.MatchValue == "" {
			return false
		}
		matched, err := regexp.MatchString(rule.MatchValue, req.URL)
		if err != nil {
			return false
		}
		return matched
	}
	return false
}

func (p *AdvancedCCProtection) matchExtension(ext, url string) bool {
	// 提取扩展名
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '.' {
			return url[i+1:] == ext
		}
		if url[i] == '/' {
			break
		}
	}
	return false
}

func (p *AdvancedCCProtection) matchPath(path, url string) bool {
	return len(url) >= len(path) && url[:len(path)] == path
}

// checkAdaptiveProtection 检查自适应保护
func (p *AdvancedCCProtection) checkAdaptiveProtection(req *CCRequestInfo) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, rule := range p.adaptiveRules {
		if !rule.Enabled {
			continue
		}

		// 检查当前QPS是否超过自适应阈值
		if stats, ok := p.stats.ResourceProtection[rule.ID]; ok {
			if stats.CurrentQPS > rule.CurrentThreshold {
				return false
			}
		}
	}

	return true
}

// handleAttack 处理攻击
func (p *AdvancedCCProtection) handleAttack(attack *CCAttackInfo, req *CCRequestInfo, startTime time.Time) *CCCheckResult {
	p.updateStats(func(s *AdvancedCCStats) {
		s.DetectedAttacks++
		s.AttackTypes[string(attack.Type)]++
	})

	// 根据响应策略处理
	mode := ""
	if p.config.Response != nil {
		mode = p.config.Response.Mode
	}
	switch mode {
	case "block":
		p.mitigator.BlockIP(req.IP, attack.Duration)
		return &CCCheckResult{
			Allowed:        false,
			Action:         "block",
			Reason:         fmt.Sprintf("攻击检测: %s", attack.Type),
			ProcessingTime: time.Since(startTime),
		}
	case "challenge":
		challenge := p.challengeMgr.CreateChallenge(req.IP, req.UserAgent)
		return &CCCheckResult{
			Allowed:        false,
			Action:         "challenge",
			Reason:         fmt.Sprintf("攻击检测: %s", attack.Type),
			Challenge:      challenge,
			ProcessingTime: time.Since(startTime),
		}
	case "rate_limit":
		p.mitigator.LimitRate(req.IP)
		return &CCCheckResult{
			Allowed:        false,
			Action:         "rate_limit",
			Reason:         fmt.Sprintf("攻击检测: %s", attack.Type),
			ProcessingTime: time.Since(startTime),
		}
	default:
		// 默认挑战模式
		challenge := p.challengeMgr.CreateChallenge(req.IP, req.UserAgent)
		return &CCCheckResult{
			Allowed:        false,
			Action:         "challenge",
			Reason:         fmt.Sprintf("攻击检测: %s", attack.Type),
			Challenge:      challenge,
			ProcessingTime: time.Since(startTime),
		}
	}
}

// updateStats 更新统计
func (p *AdvancedCCProtection) updateStats(f func(*AdvancedCCStats)) {
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()
	f(p.stats)
}

// runBackgroundTasks 运行后台任务
func (p *AdvancedCCProtection) runBackgroundTasks() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.updateAdaptiveRules()
			p.cleanupChallenges()
			p.updateStats(func(*AdvancedCCStats) {})
		}
	}
}

// updateAdaptiveRules 更新自适应规则
func (p *AdvancedCCProtection) updateAdaptiveRules() {
	if p.config.Adaptive == nil || !p.config.Adaptive.Enabled {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, rule := range p.adaptiveRules {
		// 根据历史数据调整阈值
		if _, ok := p.stats.ResourceProtection[rule.ID]; ok {
			// 简单实现：基于当前QPS调整阈值
			targetThreshold := rule.BaselineQPS * rule.ThresholdPercent
			rule.CurrentThreshold = targetThreshold
		}
	}

	p.stats.AdaptiveThreshold = p.adaptiveRules[0].CurrentThreshold
}

// cleanupChallenges 清理过期挑战
func (p *AdvancedCCProtection) cleanupChallenges() {
	p.challengeMgr.Cleanup()
}

// GetStats 获取统计
func (p *AdvancedCCProtection) GetStats() *AdvancedCCStats {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()

	return p.stats
}

// GetThreatIPs 获取威胁IP列表
func (p *AdvancedCCProtection) GetThreatIPs() []string {
	return p.mitigator.GetBlockedIPs()
}

// BlockIP 封锁IP
func (p *AdvancedCCProtection) BlockIP(ip string, duration time.Duration) {
	p.mitigator.BlockIP(ip, duration)

	p.mu.Lock()
	p.blackList[ip] = true
	p.mu.Unlock()
}

// AllowIP 允许IP
func (p *AdvancedCCProtection) AllowIP(ip string) {
	p.mu.Lock()
	p.whiteList[ip] = true
	p.mu.Unlock()
}

// CCCheckResult CC检查结果
type CCCheckResult struct {
	Allowed           bool           `json:"allowed"`
	Action            string         `json:"action"`
	Reason            string         `json:"reason,omitempty"`
	Challenge         *ChallengeInfo `json:"challenge,omitempty"`
	MatchedResourceID string         `json:"matched_resource_id,omitempty"`
	ProcessingTime    time.Duration  `json:"processing_time"`
}

// CCAttackDetector CC攻击检测器
type CCAttackDetector struct {
	config           *AdvancedCCConfig
	signatures       []CCAttackSignature
	behaviorAnalyzer *BehaviorAnalyzer
	mlModel          *CCMLModel
	mu               sync.RWMutex
}

// CCAttackSignature CC攻击签名
type CCAttackSignature struct {
	Name       string `json:"name"`
	Pattern    string `json:"pattern"`
	AttackType string `json:"attack_type"`
	Severity   string `json:"severity"`
}

// CCAttackInfo CC攻击信息
type CCAttackInfo struct {
	Type         string        `json:"type"`
	SourceIP     string        `json:"source_ip"`
	TargetURL    string        `json:"target_url"`
	Severity     string        `json:"severity"`
	RequestCount int           `json:"request_count"`
	Duration     time.Duration `json:"duration"`
	DetectedAt   time.Time     `json:"detected_at"`
	ThreatScore  float64       `json:"threat_score"`
	Indicators   []string      `json:"indicators"`
}

// NewCCAttackDetector 创建CC攻击检测器
func NewCCAttackDetector(config *AdvancedCCConfig) *CCAttackDetector {
	return &CCAttackDetector{
		config:           config,
		signatures:       loadCCSignatures(),
		behaviorAnalyzer: &BehaviorAnalyzer{},
		mlModel:          &CCMLModel{},
	}
}

// Detect 检测攻击
func (d *CCAttackDetector) Detect(req *CCRequestInfo) *CCAttackInfo {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. 签名检测
	for _, sig := range d.signatures {
		if d.matchSignature(sig, req) {
			return &CCAttackInfo{
				Type:         sig.AttackType,
				SourceIP:     req.IP,
				TargetURL:    req.URL,
				Severity:     sig.Severity,
				RequestCount: 1,
				DetectedAt:   time.Now(),
				ThreatScore:  0.9,
				Indicators:   []string{sig.Name},
			}
		}
	}

	// 2. 行为分析
	if d.config != nil && d.config.Detection != nil && d.config.Detection.BehavioralAnalysis {
		score := d.behaviorAnalyzer.Analyze(req)
		if score > 0.7 {
			return &CCAttackInfo{
				Type:         "bot",
				SourceIP:     req.IP,
				TargetURL:    req.URL,
				Severity:     "high",
				RequestCount: 1,
				DetectedAt:   time.Now(),
				ThreatScore:  score,
				Indicators:   []string{"行为异常"},
			}
		}
	}

	// 3. 机器学习检测
	if d.config != nil && d.config.Detection != nil && d.config.Detection.MLDetection {
		score := d.mlModel.Predict(req)
		if score > 0.8 {
			return &CCAttackInfo{
				Type:         "bot",
				SourceIP:     req.IP,
				TargetURL:    req.URL,
				Severity:     "high",
				RequestCount: 1,
				DetectedAt:   time.Now(),
				ThreatScore:  score,
				Indicators:   []string{"ML检测异常"},
			}
		}
	}

	// 4. 速率检测
	if d.config != nil && d.config.Detection != nil && d.config.Detection.RateDetection {
		if d.detectRateAnomaly(req) {
			return &CCAttackInfo{
				Type:         "flood",
				SourceIP:     req.IP,
				TargetURL:    req.URL,
				Severity:     "high",
				RequestCount: 1,
				DetectedAt:   time.Now(),
				ThreatScore:  0.8,
				Indicators:   []string{"请求频率异常"},
			}
		}
	}

	return nil
}

func (d *CCAttackDetector) matchSignature(sig CCAttackSignature, req *CCRequestInfo) bool {
	// 简化实现
	return false
}

func (d *CCAttackDetector) detectRateAnomaly(req *CCRequestInfo) bool {
	// 简化实现
	return false
}

// loadCCSignatures 加载CC攻击签名
func loadCCSignatures() []CCAttackSignature {
	return []CCAttackSignature{
		{Name: "Slowloris特征", Pattern: "", AttackType: "slowloris", Severity: "high"},
		{Name: "HTTP Flood特征", Pattern: "", AttackType: "http_flood", Severity: "high"},
		{Name: "暴力请求特征", Pattern: "", AttackType: "brute_force", Severity: "medium"},
	}
}

// BehaviorAnalyzer 行为分析器
type BehaviorAnalyzer struct{}

// Analyze 分析行为
func (a *BehaviorAnalyzer) Analyze(req *CCRequestInfo) float64 {
	// 简化实现
	score := 0.0

	// 检查User-Agent
	if len(req.UserAgent) < 10 {
		score += 0.2
	}

	// 检查Referer
	if req.Referer == "" {
		score += 0.1
	}

	// 检查请求间隔
	// 实际实现需要跟踪请求时间

	return math.Min(score, 1.0)
}

// CCMLModel CC机器学习模型
type CCMLModel struct{}

// Predict 预测
func (m *CCMLModel) Predict(req *CCRequestInfo) float64 {
	// 简化实现
	return 0.0
}

// CCAttackMitigator CC攻击缓解器
type CCAttackMitigator struct {
	config      *AdvancedCCConfig
	firewall    *CCIPFirewall
	rateLimiter *CCRateLimiter
	mu          sync.RWMutex
}

// NewCCAttackMitigator 创建CC攻击缓解器
func NewCCAttackMitigator(config *AdvancedCCConfig) *CCAttackMitigator {
	return &CCAttackMitigator{
		config:      config,
		firewall:    &CCIPFirewall{rules: make(map[string]*CCFirewallRule)},
		rateLimiter: &CCRateLimiter{},
	}
}

// BlockIP 封锁IP
func (m *CCAttackMitigator) BlockIP(ip string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.firewall.rules[ip] = &CCFirewallRule{
		IP:     ip,
		Action: "block",
		Expiry: time.Now().Add(duration),
		Reason: "CC攻击检测",
	}
}

// LimitRate 限速
func (m *CCAttackMitigator) LimitRate(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.firewall.rules[ip] = &CCFirewallRule{
		IP:     ip,
		Action: "rate_limit",
		Expiry: time.Now().Add(5 * time.Minute),
		Reason: "请求频率限制",
	}
}

// GetBlockedIPs 获取被封锁的IP
func (m *CCAttackMitigator) GetBlockedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	blocked := make([]string, 0)
	for ip, rule := range m.firewall.rules {
		if rule.Action == "block" && time.Now().Before(rule.Expiry) {
			blocked = append(blocked, ip)
		}
	}
	return blocked
}

// CCIPFirewall CC IP防火墙
type CCIPFirewall struct {
	rules map[string]*CCFirewallRule
	mu    sync.RWMutex
}

// CCFirewallRule CC防火墙规则
type CCFirewallRule struct {
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Expiry time.Time `json:"expiry"`
	Reason string    `json:"reason"`
}

// CCRateLimiter CC限速器
type CCRateLimiter struct{}

// ChallengeManager 挑战管理器
type ChallengeManager struct {
	config     *AdvancedChallengeConfig
	challenges map[string]*ChallengeInfo
	mu         sync.RWMutex
}

// NewChallengeManager 创建挑战管理器
func NewChallengeManager(config *AdvancedChallengeConfig) *ChallengeManager {
	if config == nil {
		config = &AdvancedChallengeConfig{
			Enabled:                true,
			ChallengeValidDuration: 5 * time.Minute,
			MaxRetries:             3,
		}
	}

	return &ChallengeManager{
		config:     config,
		challenges: make(map[string]*ChallengeInfo),
	}
}

// CreateChallenge 创建挑战
func (m *ChallengeManager) CreateChallenge(ip, userAgent string) *ChallengeInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	challenge := &ChallengeInfo{
		ID:        fmt.Sprintf("challenge_%d", time.Now().UnixNano()),
		Type:      m.getChallengeType(),
		Token:     m.generateToken(),
		ExpiresAt: time.Now().Add(m.config.ChallengeValidDuration),
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	m.challenges[challenge.Token] = challenge

	return challenge
}

func (m *ChallengeManager) getChallengeType() string {
	if m.config.SliderChallenge {
		return "slider"
	}
	if m.config.CAPTCHAChallenge {
		return "captcha"
	}
	if m.config.JSChallenge {
		return "js"
	}
	return "behavioral"
}

func (m *ChallengeManager) generateToken() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (m *ChallengeManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for token, challenge := range m.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(m.challenges, token)
		}
	}
}

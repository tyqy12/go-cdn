package security

import (
	"context"
	"math"
	"sync"
	"time"
)

// CCProtection 增强版CC防护
type CCProtection struct {
	config      *CCConfig
	requestChan chan *RequestInfo
	analyzer    *TrafficAnalyzer
	detector    *BasicAttackDetector
	mitigator   *AttackMitigator
	whiteList   map[string]bool
	blackList   map[string]bool
	mu          sync.RWMutex
	stats       *CCStats
	ctx         context.Context
	cancel      context.CancelFunc
}

// CCConfig CC防护配置
type CCConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 检测模式
	DetectionMode string `yaml:"detection_mode"` // "standalone", "distributed"

	// 检测阈值
	Thresholds CCThresholds `yaml:"thresholds"`

	// 响应策略
	ResponseStrategy string `yaml:"response_strategy"` // "rate_limit", "captcha", "block", "challenge"

	// 挑战配置
	ChallengeConfig CCChallengeConfig `yaml:"challenge_config"`

	// 机器学习配置
	MLConfig MLConfig `yaml:"ml_config"`

	// 白名单
	WhiteList []string `yaml:"white_list"`

	// 黑名单
	BlackList []string `yaml:"black_list"`

	// 学习模式
	LearningMode bool `yaml:"learning_mode"`
}

// CCThresholds 检测阈值
type CCThresholds struct {
	// 每秒请求数阈值
	RequestsPerSecond int `yaml:"requests_per_second"`

	// 并发连接数阈值
	ConcurrentConnections int `yaml:"concurrent_connections"`

	// 带宽阈值 (Mbps)
	BandwidthMbps int `yaml:"bandwidth_mbps"`

	// 错误率阈值 (%)
	ErrorRate float64 `yaml:"error_rate"`

	// 响应时间阈值 (ms)
	ResponseTimeMs int `yaml:"response_time_ms"`

	// 特定URL请求阈值
	URLThreshold int `yaml:"url_threshold"`
}

// CCChallengeConfig 挑战配置
type CCChallengeConfig struct {
	// 启用JavaScript挑战
	JSChallenge bool `yaml:"js_challenge"`

	// 启用CAPTCHA挑战
	CAPTCHA bool `yaml:"captcha"`

	// 挑战超时时间
	ChallengeTimeout time.Duration `yaml:"challenge_timeout"`

	// 挑战有效期
	ChallengeValidDuration time.Duration `yaml:"challenge_valid_duration"`

	// 难度级别
	DifficultyLevel int `yaml:"difficulty_level"` // 1-10
}

// MLConfig 机器学习配置
type MLConfig struct {
	// 启用ML检测
	Enabled bool `yaml:"enabled"`

	// 模型类型
	ModelType string `yaml:"model_type"` // "isolation_forest", "lstm", "xgboost"

	// 训练数据量
	TrainingDataSize int `yaml:"training_data_size"`

	// 更新间隔
	UpdateInterval time.Duration `yaml:"update_interval"`

	// 异常分数阈值
	AnomalyScoreThreshold float64 `yaml:"anomaly_score_threshold"` // 0.5-1.0
}

// RequestInfo 请求信息
type RequestInfo struct {
	IP           string            `json:"ip"`
	UserAgent    string            `json:"user_agent"`
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers"`
	BodySize     int               `json:"body_size"`
	Timestamp    time.Time         `json:"timestamp"`
	ResponseTime time.Duration     `json:"response_time"`
	StatusCode   int               `json:"status_code"`
	Referer      string            `json:"referer"`
}

// CCStats 统计信息
type CCStats struct {
	TotalRequests       int64            `json:"total_requests"`
	AllowedRequests     int64            `json:"allowed_requests"`
	BlockedRequests     int64            `json:"blocked_requests"`
	ChallengedRequests  int64            `json:"challenged_requests"`
	DetectedAttacks     int64            `json:"detected_attacks"`
	AttackTypes         map[string]int64 `json:"attack_types"`
	CurrentQPS          float64          `json:"current_qps"`
	PeakQPS             float64          `json:"peak_qps"`
	AverageResponseTime time.Duration    `json:"average_response_time"`
	ActiveThreatIPs     int              `json:"active_threat_ips"`
	WhiteListedRequests int64            `json:"white_listed_requests"`
	mu                  sync.RWMutex
}

// AttackType 攻击类型
type AttackType string

const (
	AttackTypeFlood        AttackType = "flood"
	AttackTypeBruteForce   AttackType = "brute_force"
	AttackTypeCrawl        AttackType = "crawl"
	AttackTypeSlowloris    AttackType = "slowloris"
	AttackTypeDDoS         AttackType = "ddos"
	AttackTypeSQLInjection AttackType = "sql_injection"
	AttackTypeXSS          AttackType = "xss"
	AttackTypeBot          AttackType = "bot"
)

// AttackInfo 攻击信息
type AttackInfo struct {
	Type         AttackType    `json:"type"`
	SourceIP     string        `json:"source_ip"`
	TargetURL    string        `json:"target_url"`
	Severity     string        `json:"severity"` // "low", "medium", "high", "critical"
	RequestCount int           `json:"request_count"`
	Duration     time.Duration `json:"duration"`
	DetectedAt   time.Time     `json:"detected_at"`
	ThreatScore  float64       `json:"threat_score"`
	Indicators   []string      `json:"indicators"`
}

// TrafficAnalyzer 流量分析器
type TrafficAnalyzer struct {
	config  *CCConfig
	metrics *TrafficMetrics
	mu      sync.RWMutex
}

// TrafficMetrics 流量指标
type TrafficMetrics struct {
	RequestsPerSecond     float64
	ConcurrentConnections int
	BandwidthUsage        float64
	ErrorRate             float64
	AverageResponseTime   time.Duration
	URLRequestCounts      map[string]int
	IPRequestCounts       map[string]int
	UserAgentCounts       map[string]int
	RefererCounts         map[string]int
	mu                    sync.RWMutex
}

// BasicAttackDetector 攻击检测器
type BasicAttackDetector struct {
	analyzer   *TrafficAnalyzer
	mlModel    *MLModel
	signatures []AttackSignature
	config     *CCConfig
	mu         sync.RWMutex
}

// AttackSignature 攻击签名
type AttackSignature struct {
	Name       string     `json:"name"`
	Pattern    string     `json:"pattern"`
	AttackType AttackType `json:"attack_type"`
	Severity   string     `json:"severity"`
}

// MLModel 机器学习模型
type MLModel struct {
	config      *MLConfig
	model       interface{}
	isTrained   bool
	lastTrained time.Time
	mu          sync.RWMutex
}

// AttackMitigator 攻击缓解器
type AttackMitigator struct {
	config   *CCConfig
	firewall *IPFirewall
	mu       sync.RWMutex
}

// IPFirewall IP防火墙
type IPFirewall struct {
	rules map[string]*FirewallRule
	mu    sync.RWMutex
}

// FirewallRule 防火墙规则
type FirewallRule struct {
	IP           string    `json:"ip"`
	Action       string    `json:"action"` // "allow", "block", "challenge"
	Priority     int       `json:"priority"`
	Expiry       time.Time `json:"expiry"`
	Reason       string    `json:"reason"`
	RequestCount int       `json:"request_count"`
}

// NewCCProtection 创建CC防护
func NewCCProtection(config *CCConfig) *CCProtection {
	if config == nil {
		config = &CCConfig{
			Enabled:          true,
			DetectionMode:    "standalone",
			ResponseStrategy: "challenge",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	protection := &CCProtection{
		config:      config,
		requestChan: make(chan *RequestInfo, 10000),
		analyzer:    NewTrafficAnalyzer(config),
		detector:    NewAttackDetector(config),
		mitigator:   NewAttackMitigator(config),
		whiteList:   make(map[string]bool),
		blackList:   make(map[string]bool),
		stats:       &CCStats{AttackTypes: make(map[string]int64)},
		ctx:         ctx,
		cancel:      cancel,
	}

	// 加载白名单和黑名单
	for _, ip := range config.WhiteList {
		protection.whiteList[ip] = true
	}
	for _, ip := range config.BlackList {
		protection.blackList[ip] = true
	}

	// 启动处理协程
	go protection.processRequests()

	return protection
}

// NewTrafficAnalyzer 创建流量分析器
func NewTrafficAnalyzer(config *CCConfig) *TrafficAnalyzer {
	return &TrafficAnalyzer{
		config: config,
		metrics: &TrafficMetrics{
			URLRequestCounts: make(map[string]int),
			IPRequestCounts:  make(map[string]int),
			UserAgentCounts:  make(map[string]int),
			RefererCounts:    make(map[string]int),
		},
	}
}

// NewAttackDetector 创建攻击检测器
func NewAttackDetector(config *CCConfig) *BasicAttackDetector {
	return &BasicAttackDetector{
		config:     config,
		signatures: loadDefaultSignatures(),
		mlModel: &MLModel{
			config: &config.MLConfig,
		},
	}
}

// NewAttackMitigator 创建攻击缓解器
func NewAttackMitigator(config *CCConfig) *AttackMitigator {
	return &AttackMitigator{
		config:   config,
		firewall: &IPFirewall{rules: make(map[string]*FirewallRule)},
	}
}

// loadDefaultSignatures 加载默认攻击签名
func loadDefaultSignatures() []AttackSignature {
	return []AttackSignature{
		{
			Name:       "SQL注入特征",
			Pattern:    "'|OR 1=1|UNION SELECT|--",
			AttackType: AttackTypeSQLInjection,
			Severity:   "high",
		},
		{
			Name:       "XSS特征",
			Pattern:    "<script>|javascript:|onerror=",
			AttackType: AttackTypeXSS,
			Severity:   "high",
		},
	}
}

// ProcessRequest 处理请求
func (cc *CCProtection) ProcessRequest(req *RequestInfo) bool {
	cc.mu.RLock()
	enabled := cc.config.Enabled
	cc.mu.RUnlock()

	if !enabled {
		return true
	}

	// 发送到处理通道
	select {
	case cc.requestChan <- req:
	default:
		// 通道满，允许请求通过
	}

	// 发送到分析器
	cc.analyzer.Analyze(req)

	return true
}

// processRequests 处理请求
func (cc *CCProtection) processRequests() {
	for {
		select {
		case <-cc.ctx.Done():
			return
		case req := <-cc.requestChan:
			cc.analyzeAndProtect(req)
		}
	}
}

// analyzeAndProtect 分析并保护
func (cc *CCProtection) analyzeAndProtect(req *RequestInfo) {
	// 白名单检查
	if cc.whiteList[req.IP] {
		cc.updateStats(func(s *CCStats) {
			s.WhiteListedRequests++
			s.AllowedRequests++
		})
		return
	}

	// 黑名单检查
	if cc.blackList[req.IP] {
		cc.updateStats(func(s *CCStats) {
			s.BlockedRequests++
		})
		return
	}

	// 流量分析
	cc.analyzer.Analyze(req)

	// 攻击检测
	attack := cc.detector.Detect(req, cc.analyzer.GetMetrics())

	if attack != nil {
		cc.handleAttack(attack)
	} else {
		cc.updateStats(func(s *CCStats) {
			s.AllowedRequests++
		})
	}
}

// handleAttack 处理攻击
func (cc *CCProtection) handleAttack(attack *AttackInfo) {
	cc.updateStats(func(s *CCStats) {
		s.DetectedAttacks++
		s.AttackTypes[string(attack.Type)]++
	})

	// 根据响应策略处理
	switch cc.config.ResponseStrategy {
	case "block":
		cc.mitigator.BlockIP(attack.SourceIP, attack.Duration)
		cc.updateStats(func(s *CCStats) {
			s.BlockedRequests++
		})
	case "challenge":
		// 发送挑战
		cc.mitigator.ChallengeIP(attack.SourceIP, &cc.config.ChallengeConfig)
		cc.updateStats(func(s *CCStats) {
			s.ChallengedRequests++
		})
	case "rate_limit":
		cc.mitigator.LimitRate(attack.SourceIP)
	default:
		cc.mitigator.BlockIP(attack.SourceIP, 1*time.Minute)
	}
}

// GetStats 获取统计
func (cc *CCProtection) GetStats() *CCStats {
	cc.stats.mu.RLock()
	defer cc.stats.mu.RUnlock()

	return cc.stats
}

// updateStats 更新统计
func (cc *CCProtection) updateStats(f func(*CCStats)) {
	cc.stats.mu.Lock()
	defer cc.stats.mu.Unlock()

	f(cc.stats)
}

// GetThreatIPs 获取威胁IP列表
func (cc *CCProtection) GetThreatIPs() []string {
	return cc.mitigator.firewall.GetBlockedIPs()
}

// Analyze 分析流量
func (a *TrafficAnalyzer) Analyze(req *RequestInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 更新URL请求计数
	a.metrics.URLRequestCounts[req.URL]++

	// 更新IP请求计数
	a.metrics.IPRequestCounts[req.IP]++

	// 更新UserAgent计数
	a.metrics.UserAgentCounts[req.UserAgent]++

	// 更新Referer计数
	if req.Referer != "" {
		a.metrics.RefererCounts[req.Referer]++
	}
}

// GetMetrics 获取指标
func (a *TrafficAnalyzer) GetMetrics() *TrafficMetrics {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.metrics
}

// Detect 检测攻击
func (d *BasicAttackDetector) Detect(req *RequestInfo, metrics *TrafficMetrics) *AttackInfo {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 签名检测
	for _, sig := range d.signatures {
		if containsPattern(req.URL, sig.Pattern) {
			return &AttackInfo{
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

	// 阈值检测
	if metrics.RequestsPerSecond > float64(d.config.Thresholds.RequestsPerSecond) {
		return &AttackInfo{
			Type:         AttackTypeFlood,
			SourceIP:     req.IP,
			TargetURL:    req.URL,
			Severity:     "high",
			RequestCount: int(metrics.RequestsPerSecond),
			DetectedAt:   time.Now(),
			ThreatScore:  0.8,
			Indicators:   []string{"请求频率异常"},
		}
	}

	// 机器学习检测
	if d.config.MLConfig.Enabled && d.mlModel.isTrained {
		score := d.mlModel.Predict(req)
		if score > d.config.MLConfig.AnomalyScoreThreshold {
			return &AttackInfo{
				Type:         AttackTypeBot,
				SourceIP:     req.IP,
				TargetURL:    req.URL,
				Severity:     "medium",
				RequestCount: 1,
				DetectedAt:   time.Now(),
				ThreatScore:  score,
				Indicators:   []string{"ML检测异常"},
			}
		}
	}

	return nil
}

// BlockIP 封锁IP
func (m *AttackMitigator) BlockIP(ip string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.firewall.rules[ip] = &FirewallRule{
		IP:     ip,
		Action: "block",
		Expiry: time.Now().Add(duration),
		Reason: "CC攻击检测",
	}
}

// ChallengeIP 对IP发起挑战
func (m *AttackMitigator) ChallengeIP(ip string, config *CCChallengeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.firewall.rules[ip] = &FirewallRule{
		IP:     ip,
		Action: "challenge",
		Expiry: time.Now().Add(config.ChallengeValidDuration),
		Reason: "需要通过挑战验证",
	}
}

// LimitRate 限速
func (m *AttackMitigator) LimitRate(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.firewall.rules[ip] = &FirewallRule{
		IP:     ip,
		Action: "rate_limit",
		Expiry: time.Now().Add(5 * time.Minute),
		Reason: "请求频率限制",
	}
}

// GetBlockedIPs 获取被封锁的IP
func (f *IPFirewall) GetBlockedIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	blocked := make([]string, 0)
	for ip, rule := range f.rules {
		if rule.Action == "block" && time.Now().Before(rule.Expiry) {
			blocked = append(blocked, ip)
		}
	}
	return blocked
}

// Predict ML预测
func (m *MLModel) Predict(req *RequestInfo) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 简化的异常检测实现
	// 实际应该使用训练好的模型
	score := 0.0

	// 简单的启发式规则
	if len(req.UserAgent) < 10 {
		score += 0.3
	}
	if req.Referer == "" {
		score += 0.2
	}

	return math.Min(score, 1.0)
}

// containsPattern 检查是否包含模式
func containsPattern(text, pattern string) bool {
	// 简化实现
	return len(text) > 0 && len(pattern) > 0
}

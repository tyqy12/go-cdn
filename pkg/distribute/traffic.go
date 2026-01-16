package distribute

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/pkg/security"
)

// TrafficDistributor 流量分发器
type TrafficDistributor struct {
	config       *TrafficDistributorConfig
	analyzer     *security.RequestAnalyzer
	ruleEngine   *security.RuleEngine
	scorer       *security.SecurityScorer
	mu           sync.RWMutex
	decisionChan chan *TrafficRequest
	normalChan   chan *TrafficRequest
	cleanChan    chan *TrafficRequest
	logger       Logger
	stats        *TrafficDistributorStats
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
}

// TrafficDistributorConfig 流量分发配置
type TrafficDistributorConfig struct {
	// 清洗模式
	CleaningMode string `yaml:"cleaning_mode"` // "sinkhole", "scrubbing"

	// Sinkhole配置
	SinkholeConfig *SinkholeConfig `yaml:"sinkhole"`

	// Scrubbing配置
	ScrubbingConfig *ScrubbingConfig `yaml:"scrubbing"`

	// 决策阈值
	DecisionThreshold *DecisionThresholdConfig `yaml:"decision_threshold"`

	// 回注配置
	ReInjection *ReInjectionConfig `yaml:"reinjection"`
}

// SinkholeConfig 黑洞配置
type SinkholeConfig struct {
	// 启用黑洞
	Enabled bool `yaml:"enabled"`

	// 丢弃策略
	DropPolicy string `yaml:"drop_policy"` // "immediate", "delayed", "sampled"

	// 采样率（sampled模式）
	SampleRate float64 `yaml:"sample_rate"`

	// 丢弃动作
	DropAction string `yaml:"drop_action"` // "tcp_reset", "udp_drop", "icmp_unreachable"

	// 记录详细级别
	LogLevel string `yaml:"log_level"` // "basic", "details", "full"
}

// ScrubbingConfig 清洗配置
type ScrubbingConfig struct {
	// 启用清洗
	Enabled bool `yaml:"enabled"`

	// 清洗规则
	CleaningRules []*CleaningRule `yaml:"cleaning_rules"`

	// 回注配置
	ReInjection *ReInjectionConfig `yaml:"reinjection"`

	// 回注延迟
	ReInjectionDelay time.Duration `yaml:"reinjection_delay"`

	// 持久化策略
	PersistStrategy string `yaml:"persist_strategy"` // "none", "sample", "full"
}

// CleaningRule 清洗规则
type CleaningRule struct {
	ID            string  `yaml:"id"`
	Name          string  `yaml:"name"`
	Pattern       string  `yaml:"pattern"`
	Action        string  `yaml:"action"`   // "allow", "rate_limit", "block"
	Severity      string  `yaml:"severity"` // "low", "medium", "high", "critical"
	MaxQPS        int     `yaml:"max_qps"`
	BandwidthMbps float64 `yaml:"bandwidth_mbps"`
	Enabled       bool    `yaml:"enabled"`
}

// DecisionThresholdConfig 决策阈值
type DecisionThresholdConfig struct {
	// 低风险阈值
	LowThreshold float64 `yaml:"low_threshold"` // 0-40

	// 中风险阈值
	MediumThreshold float64 `yaml:"medium_threshold"` // 41-60

	// 高风险阈值
	HighThreshold float64 `yaml:"high_threshold"` // 61-80

	// 严重风险阈值
	CriticalThreshold float64 `yaml:"critical_threshold"` // 81-100
}

// ReInjectionConfig 回注配置
type ReInjectionConfig struct {
	Enabled bool   `yaml:"enabled"`
	Target  string `yaml:"target"` // "edge", "origin"

	// 回注延迟
	Delay time.Duration `yaml:"delay"`

	// 回注策略
	Strategy string `yaml:"strategy"` // "immediate", "batch", "scheduled"

	// 批处理配置
	BatchSize   int           `yaml:"batch_size"`
	BatchWindow time.Duration `yaml:"batch_window"`

	// 重试配置
	MaxRetries int           `yaml:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay"`
}

// TrafficRequest 流量请求
type TrafficRequest struct {
	ID              string
	ClientIP        string
	RequestID       string
	RequestHeaders  map[string]string
	RequestBody     []byte
	RequestMethod   string
	RequestURL      string
	RequestTime     time.Time
	ResponseTime    *time.Time
	StatusCode      int
	ResponseHeaders map[string]string
	ResponseBody    []byte
	Duration        time.Duration
	Processed       bool
	Decision        *TrafficDecision
	ProcessingTime  time.Duration
}

// TrafficDecision 流量决策
type TrafficDecision struct {
	RequestID      string
	Action         DecisionAction
	TargetPath     string // "normal", "sinkhole", "scrubbing"
	Score          float64
	RiskLevel      string
	Reason         string
	Reasons        []string
	DecisionTime   time.Time
	ProcessingTime time.Duration
	ReInjection    bool
}

// DecisionAction 决策动作
type DecisionAction string

const (
	DecisionActionAllow     DecisionAction = "allow"      // 允许（正常转发）
	DecisionActionChallenge DecisionAction = "challenge"  // 挑战验证
	DecisionActionRateLimit DecisionAction = "rate_limit" // 限速
	DecisionActionSinkhole  DecisionAction = "sinkhole"   // 黑洞丢弃
	DecisionActionScrubbing DecisionAction = "scrubbing"  // 清洗回注
	DecisionActionBlock     DecisionAction = "block"      // 阻止
)

// TrafficDistributorStats 流量分发器统计
type TrafficDistributorStats struct {
	TotalRequests      int64
	NormalRequests     int64
	SinkholeRequests   int64
	ScrubbingRequests  int64
	BlockedRequests    int64
	ChallengedRequests int64
	AllowanceRate      float64
	AverageLatency     time.Duration
	CurrentQPS         int64
	PeakQPS            int64
	mu                 sync.RWMutex
}

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// DefaultLogger 默认日志
type DefaultLogger struct{}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {}
func (l *DefaultLogger) Infof(format string, args ...interface{})  {}
func (l *DefaultLogger) Warnf(format string, args ...interface{})  {}
func (l *DefaultLogger) Errorf(format string, args ...interface{}) {}

// NewTrafficDistributor 创建流量分发器
func NewTrafficDistributor(cfg *TrafficDistributorConfig, opts ...DistributorOption) (*TrafficDistributor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("配置不能为空")
	}

	ctx, cancel := context.WithCancel(context.Background())

	td := &TrafficDistributor{
		config:       cfg,
		decisionChan: make(chan *TrafficRequest, 10000),
		normalChan:   make(chan *TrafficRequest, 10000),
		cleanChan:    make(chan *TrafficRequest, 10000),
		logger:       &DefaultLogger{},
		stats:        &TrafficDistributorStats{},
		ctx:          ctx,
		cancel:       cancel,
	}

	for _, opt := range opts {
		opt(td)
	}

	// 初始化评分器和规则引擎
	if cfg.DecisionThreshold != nil {
		td.scorer = security.NewSecurityScorer(
			security.WithScoringConfig(&security.ScoringConfig{
				BlockThreshold:     cfg.DecisionThreshold.CriticalThreshold,
				ChallengeThreshold: cfg.DecisionThreshold.HighThreshold,
				MonitorThreshold:   cfg.DecisionThreshold.MediumThreshold,
			}),
		)
	}

	// 启动处理协程
	go td.processNormalPath()
	go td.processCleanPath()

	return td, nil
}

// DistributorOption 分发器选项
type DistributorOption func(*TrafficDistributor)

// WithDistributorLogger 设置日志
func WithDistributorLogger(l Logger) DistributorOption {
	return func(td *TrafficDistributor) {
		td.logger = l
	}
}

// Distribute 分发请求
func (td *TrafficDistributor) Distribute(req *TrafficRequest) error {
	if req == nil {
		return fmt.Errorf("请求不能为空")
	}

	// 记录请求到达时间
	now := time.Now()
	req.RequestTime = now

	// 将请求发送到决策通道
	td.decisionChan <- req

	return nil
}

// processNormalPath 处理正常路径
func (td *TrafficDistributor) processNormalPath() {
	for {
		select {
		case <-td.ctx.Done():
			return
		case req := <-td.decisionChan:
			// 进行决策
			decision := td.makeDecision(req)
			req.Decision = decision
			req.ProcessingTime = time.Since(req.RequestTime)

			// 根据决策路由到不同通道
			switch decision.Action {
			case DecisionActionAllow, DecisionActionChallenge:
				td.normalChan <- req
			case DecisionActionRateLimit:
				td.normalChan <- req // 限速后仍走正常路径
			case DecisionActionSinkhole:
				td.cleanChan <- req
			case DecisionActionScrubbing:
				td.cleanChan <- req
			case DecisionActionBlock:
				td.cleanChan <- req
			}

			// 更新统计
			td.updateStats(req, decision)
		}
	}
}

// processCleanPath 处理清洗路径
func (td *TrafficDistributor) processCleanPath() {
	for {
		select {
		case <-td.ctx.Done():
			return
		case req := <-td.cleanChan:
			// 处理清洗逻辑
			td.handleCleaning(req)
		}
	}
}

// makeDecision 做出决策
func (td *TrafficDistributor) makeDecision(req *TrafficRequest) *TrafficDecision {
	decision := &TrafficDecision{
		RequestID:    req.RequestID,
		Action:       DecisionActionAllow,
		TargetPath:   "normal",
		Score:        0,
		RiskLevel:    "low",
		Reason:       "allowed",
		DecisionTime: time.Now(),
	}

	// 如果有评分器，使用评分决策
	if td.scorer != nil {
		// 模拟评分（实际应该调用td.scorer.ScoreRequest）
		decision = td.scoreRequest(req)
	} else {
		// 基于规则引擎决策
		decision = td.ruleBasedDecision(req)
	}

	return decision
}

// scoreRequest 基于SecurityScorer的安全评分进行决策
func (td *TrafficDistributor) scoreRequest(req *TrafficRequest) *TrafficDecision {
	decision := &TrafficDecision{
		RequestID:    req.RequestID,
		Action:       DecisionActionAllow,
		TargetPath:   "normal",
		Score:        0,
		RiskLevel:    "low",
		Reason:       "allowed",
		Reasons:      []string{},
		DecisionTime: time.Now(),
	}

	if td.scorer == nil {
		return decision
	}

	httpReq := td.buildHTTPRequest(req)
	if httpReq == nil {
		td.logger.Warnf("构建HTTP请求失败: %s", req.RequestID)
		decision.Score = 50
		decision.RiskLevel = "medium"
		decision.Reason = "failed to build HTTP request"
		decision.Reasons = append(decision.Reasons, "invalid request construction")
		decision.Action = DecisionActionChallenge
		return decision
	}
	defer httpReq.Body.Close()

	ctx := context.Background()
	secDecision := td.scorer.ScoreRequest(ctx, httpReq)

	decision.Score = secDecision.Score
	decision.Reasons = append(decision.Reasons, secDecision.Reasons...)

	switch {
	case secDecision.Score >= td.config.DecisionThreshold.CriticalThreshold:
		decision.RiskLevel = "critical"
		decision.Action = DecisionActionSinkhole
		decision.Reason = fmt.Sprintf("critical risk score: %.2f", secDecision.Score)
	case secDecision.Score >= td.config.DecisionThreshold.HighThreshold:
		decision.RiskLevel = "high"
		if secDecision.RequireCaptcha {
			decision.Action = DecisionActionChallenge
			decision.Reason = fmt.Sprintf("high risk, captcha required: %.2f", secDecision.Score)
		} else {
			decision.Action = DecisionActionScrubbing
			decision.Reason = fmt.Sprintf("high risk, needs scrubbing: %.2f", secDecision.Score)
		}
	case secDecision.Score >= td.config.DecisionThreshold.MediumThreshold:
		decision.RiskLevel = "medium"
		decision.Action = DecisionActionRateLimit
		decision.Reason = fmt.Sprintf("medium risk, rate limited: %.2f", secDecision.Score)
	default:
		decision.RiskLevel = "low"
		decision.Action = DecisionActionAllow
		decision.Reason = "allowed"
	}

	for _, tag := range secDecision.Tags {
		if strings.Contains(tag, "api") || strings.Contains(tag, "llm") {
			if decision.Action == DecisionActionChallenge {
				decision.Action = DecisionActionAllow
				decision.Reason = fmt.Sprintf("%s (API bypass)", decision.Reason)
				decision.Reasons = append(decision.Reasons, "API request bypass challenge")
			}
		}
	}

	return decision
}

// buildHTTPRequest 从TrafficRequest构建http.Request
func (td *TrafficDistributor) buildHTTPRequest(req *TrafficRequest) *http.Request {
	var body io.Reader
	if len(req.RequestBody) > 0 {
		body = bytes.NewReader(req.RequestBody)
	}

	httpReq, err := http.NewRequest(req.RequestMethod, req.RequestURL, body)
	if err != nil {
		return nil
	}

	for k, v := range req.RequestHeaders {
		httpReq.Header.Set(k, v)
	}

	if clientIP, ok := req.RequestHeaders["X-Real-IP"]; ok {
		httpReq.RemoteAddr = clientIP + ":0"
	} else if req.ClientIP != "" {
		httpReq.RemoteAddr = req.ClientIP + ":0"
	}

	return httpReq
}

// ruleBasedDecision 基于规则引擎进行决策
func (td *TrafficDistributor) ruleBasedDecision(req *TrafficRequest) *TrafficDecision {
	decision := &TrafficDecision{
		RequestID:    req.RequestID,
		Action:       DecisionActionAllow,
		TargetPath:   "normal",
		Score:        0,
		RiskLevel:    "low",
		Reason:       "allowed",
		Reasons:      []string{},
		DecisionTime: time.Now(),
	}

	if td.ruleEngine == nil {
		return decision
	}

	httpReq := td.buildHTTPRequest(req)
	if httpReq == nil {
		decision.Score = 30
		decision.RiskLevel = "medium"
		decision.Reason = "rule engine: invalid request"
		decision.Reasons = append(decision.Reasons, "failed to build HTTP request for rule check")
		return decision
	}
	defer httpReq.Body.Close()

	checkResult := td.ruleEngine.CheckRequest(httpReq)

	decision.Reason = checkResult.Reason
	decision.Reasons = append(decision.Reasons, fmt.Sprintf("matched rule: %s", checkResult.MatchedRule.Name))

	if checkResult.Whitelisted {
		decision.Action = DecisionActionAllow
		decision.RiskLevel = "low"
		decision.Reason = "whitelisted request"
		decision.Score = 0
		decision.Reasons = append(decision.Reasons, "whitelist hit")
		return decision
	}

	if checkResult.Blocked {
		decision.Action = DecisionActionSinkhole
		decision.RiskLevel = "critical"
		decision.Score = 100
		decision.Reason = fmt.Sprintf("blacklisted request: %s", checkResult.Reason)
		decision.Reasons = append(decision.Reasons, "blacklist hit")
		return decision
	}

	switch checkResult.Action {
	case security.RuleActionBlock:
		decision.Action = DecisionActionSinkhole
		decision.RiskLevel = "critical"
		decision.Score = 90
		decision.Reason = fmt.Sprintf("blocked by rule: %s", checkResult.Reason)
	case security.RuleActionRateLimit:
		decision.Action = DecisionActionRateLimit
		decision.RiskLevel = "medium"
		decision.Score = 60
		decision.Reason = fmt.Sprintf("rate limited: %s", checkResult.Reason)
	case security.RuleActionChallenge:
		decision.Action = DecisionActionChallenge
		decision.RiskLevel = "medium"
		decision.Score = 50
		decision.Reason = fmt.Sprintf("challenge required: %s", checkResult.Reason)
	case security.RuleActionAllow:
		decision.Action = DecisionActionAllow
		decision.RiskLevel = "low"
		decision.Score = 20
		decision.Reason = "allowed by rules"
	default:
		decision.Action = DecisionActionAllow
		decision.Reason = checkResult.Reason
	}

	return decision
}

// handleCleaning 处理清洗逻辑
func (td *TrafficDistributor) handleCleaning(req *TrafficRequest) {
	switch td.config.CleaningMode {
	case "sinkhole":
		td.handleSinkhole(req)
	case "scrubbing":
		td.handleScrubbing(req)
	default:
		td.logger.Errorf("未知的清洗模式: %s", td.config.CleaningMode)
		td.handleSinkhole(req)
	}
}

// handleSinkhole 处理黑洞
func (td *TrafficDistributor) handleSinkhole(req *TrafficRequest) {
	switch td.config.SinkholeConfig.DropPolicy {
	case "immediate":
		td.logger.Warnf("立即丢弃请求: %s", req.RequestID)
	case "delayed":
		// 模拟延迟丢弃
		go func() {
			time.Sleep(100 * time.Millisecond)
			td.logger.Infof("延迟丢弃请求: %s", req.RequestID)
		}()
	case "sampled":
		if time.Now().UnixNano()%10 == 0 { // 10%采样
			td.logger.Debugf("采样保留请求: %s", req.RequestID)
		}
	}
}

// handleScrubbing 处理清洗回注
func (td *TrafficDistributor) handleScrubbing(req *TrafficRequest) {
	td.logger.Infof("清洗回注请求: %s", req.RequestID)

	// 检查是否需要回注
	if td.config.ScrubbingConfig.ReInjection != nil && td.config.ScrubbingConfig.ReInjection.Enabled {
		td.logger.Infof("计划回注到: %s, 延迟: %v",
			td.config.ScrubbingConfig.ReInjection.Target,
			td.config.ScrubbingConfig.ReInjection.Delay)
	}
}

// updateStats 更新统计
func (td *TrafficDistributor) updateStats(req *TrafficRequest, decision *TrafficDecision) {
	td.stats.mu.Lock()
	defer td.stats.mu.Unlock()

	td.stats.TotalRequests++

	switch decision.Action {
	case DecisionActionAllow, DecisionActionChallenge, DecisionActionRateLimit:
		td.stats.NormalRequests++
	case DecisionActionSinkhole:
		td.stats.SinkholeRequests++
	case DecisionActionScrubbing:
		td.stats.ScrubbingRequests++
	case DecisionActionBlock:
		td.stats.BlockedRequests++
	}

	td.stats.AllowanceRate = float64(td.stats.NormalRequests) / float64(td.stats.TotalRequests) * 100
}

// GetStats 获取统计
func (td *TrafficDistributor) GetStats() *TrafficDistributorStats {
	td.stats.mu.RLock()
	defer td.stats.mu.RUnlock()

	return &TrafficDistributorStats{
		TotalRequests:      td.stats.TotalRequests,
		NormalRequests:     td.stats.NormalRequests,
		SinkholeRequests:   td.stats.SinkholeRequests,
		ScrubbingRequests:  td.stats.ScrubbingRequests,
		BlockedRequests:    td.stats.BlockedRequests,
		ChallengedRequests: td.stats.ChallengedRequests,
		AllowanceRate:      td.stats.AllowanceRate,
		AverageLatency:     td.stats.AverageLatency,
		CurrentQPS:         td.stats.CurrentQPS,
		PeakQPS:            td.stats.PeakQPS,
	}
}

// Stop 停止分发器
func (td *TrafficDistributor) Stop() {
	td.logger.Infof("停止流量分发器")
	if td.cancel != nil {
		td.cancel()
	}

	// 等待正在处理的请求完成
	td.wg.Wait()
}

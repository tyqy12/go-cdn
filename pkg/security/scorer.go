package security

import (
	"context"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SecurityScorer 安全评分器 - 多维度评分系统
type SecurityScorer struct {
	mu           sync.RWMutex
	config       *ScoringConfig
	analyzer     *RequestAnalyzer
	rateLimiter  *RateLimiter
	ruleEngine   *RuleEngine
	challenge    *ChallengeVerifier
	logger       Logger
	stats        ScoringStats
	ipScores     map[string]*IPScore
	sessionScores map[string]*SessionScore
}

// ScoringConfig 评分配置
type ScoringConfig struct {
	// 权重配置
	BehaviorWeight     float64
	RateLimitWeight    float64
	RuleWeight         float64
	ChallengeWeight    float64

	// 阈值配置
	BlockThreshold     float64
	ChallengeThreshold float64
	MonitorThreshold   float64

	// 计分周期
	ScoreWindow        time.Duration
	DecayFactor        float64 // 分数衰减因子

	// 风险标签
	HighRiskTags       []string
	MediumRiskTags     []string
}

// IPScore IP 评分
type IPScore struct {
	IP           string
	TotalScore   float64
	BehaviorScore float64
	RateScore    float64
	RuleScore    float64
	ChallengeScore float64
	LastUpdate   time.Time
	RequestCount int64
	BlockCount   int64
	Tags         []string
	mu           sync.RWMutex
}

// SessionScore 会话评分
type SessionScore struct {
	SessionID    string
	IP           string
	UserAgent    string
	TotalScore   float64
	RequestCount int64
	FirstSeen    time.Time
	LastSeen     time.Time
	Tags         []string
	mu           sync.RWMutex
}

// ScoringStats 评分统计
type ScoringStats struct {
	TotalScored      int64
	TotalBlocked     int64
	TotalChallenged  int64
	ActiveIPScore    int
	ActiveSessions   int
	AverageScore     float64
	mu               sync.RWMutex
}

// SecurityDecision 安全决策
type SecurityDecision struct {
	Allow         bool
	Score         float64
	RiskLevel     RiskLevel
	Reasons       []string
	Tags          []string
	Action        Action
	RequireCaptcha bool
	WaitDuration  time.Duration
	RetryAfter    time.Duration
}

// NewSecurityScorer 创建安全评分器
func NewSecurityScorer(opts ...ScoringOption) *SecurityScorer {
	scorer := &SecurityScorer{
		config: &ScoringConfig{
			BehaviorWeight:     0.35,
			RateLimitWeight:    0.25,
			RuleWeight:         0.25,
			ChallengeWeight:    0.15,
			BlockThreshold:     80,
			ChallengeThreshold: 50,
			MonitorThreshold:   30,
			ScoreWindow:        5 * time.Minute,
			DecayFactor:        0.95,
			HighRiskTags:       []string{"brute_force", "sql_injection", "xss", "scanner"},
			MediumRiskTags:     []string{"missing_ua", "missing_referer", "high_frequency"},
		},
		ipScores:     make(map[string]*IPScore),
		sessionScores: make(map[string]*SessionScore),
		logger:       &DefaultLogger{},
	}

	for _, opt := range opts {
		opt(scorer)
	}

	return scorer
}

// ScoringOption 评分器选项
type ScoringOption func(*SecurityScorer)

// WithScoringConfig 设置配置
func WithScoringConfig(config *ScoringConfig) ScoringOption {
	return func(s *SecurityScorer) {
		s.config = config
	}
}

// WithScoringAnalyzer 设置行为分析器
func WithScoringAnalyzer(analyzer *RequestAnalyzer) ScoringOption {
	return func(s *SecurityScorer) {
		s.analyzer = analyzer
	}
}

// WithScoringRateLimiter 设置限流器
func WithScoringRateLimiter(rl *RateLimiter) ScoringOption {
	return func(s *SecurityScorer) {
		s.rateLimiter = rl
	}
}

// WithScoringRuleEngine 设置规则引擎
func WithScoringRuleEngine(re *RuleEngine) ScoringOption {
	return func(s *SecurityScorer) {
		s.ruleEngine = re
	}
}

// WithScoringChallenge 设置挑战验证器
func WithScoringChallenge(cv *ChallengeVerifier) ScoringOption {
	return func(s *SecurityScorer) {
		s.challenge = cv
	}
}

// ScoreRequest 对请求进行评分
func (ss *SecurityScorer) ScoreRequest(ctx context.Context, req *http.Request) *SecurityDecision {
	decision := &SecurityDecision{
		Allow:  true,
		Action: ActionAllow,
	}

	clientIP := getClientIP(req)
	sessionID := ss.getSessionID(req)

	// 1. 行为分析评分
	behaviorScore := ss.scoreBehavior(req)
	decision.Score += behaviorScore * ss.config.BehaviorWeight

	// 2. 限流评分
	rateScore := ss.scoreRateLimit(clientIP)
	decision.Score += rateScore * ss.config.RateLimitWeight

	// 3. 规则引擎评分
	ruleScore := ss.scoreRuleEngine(req)
	decision.Score += ruleScore * ss.config.RuleWeight

	// 4. 挑战历史评分
	challengeScore := ss.scoreChallenge(clientIP)
	decision.Score += challengeScore * ss.config.ChallengeWeight

	// 获取或创建 IP 评分
	ipScore := ss.getOrCreateIPScore(clientIP)
	ipScore.mu.Lock()
	ipScore.TotalScore = decision.Score
	ipScore.BehaviorScore = behaviorScore
	ipScore.RateScore = rateScore
	ipScore.RuleScore = ruleScore
	ipScore.ChallengeScore = challengeScore
	ipScore.LastUpdate = time.Now()
	ipScore.RequestCount++
	ipScore.mu.Unlock()

	// 更新会话评分
	ss.updateSessionScore(sessionID, clientIP, req.UserAgent(), decision.Score)

	// 更新统计
	ss.updateStats(decision)

	// 确定风险等级
	decision.RiskLevel = ss.getRiskLevel(decision.Score)

	// 生成决策
	ss.makeDecision(decision, ipScore)

	// 添加标签
	decision.Tags = ss.getTags(decision)

	return decision
}

// scoreBehavior 行为分析评分
func (ss *SecurityScorer) scoreBehavior(req *http.Request) float64 {
	if ss.analyzer == nil {
		return 0
	}

	result := ss.analyzer.Analyze(context.Background(), req)
	return result.Score
}

// scoreRateLimit 限流评分
func (ss *SecurityScorer) scoreRateLimit(ip string) float64 {
	if ss.rateLimiter == nil {
		return 0
	}

	// 检查是否被限流
	blocked, action := ss.rateLimiter.Check(context.Background(), ip)
	if blocked {
		switch action {
		case RateActionBlock:
			return 100
		case RateActionRateLimit:
			return 70
		case RateActionChallenge:
			return 50
		}
	}

	return 0
}

// scoreRuleEngine 规则引擎评分
func (ss *SecurityScorer) scoreRuleEngine(req *http.Request) float64 {
	if ss.ruleEngine == nil {
		return 0
	}

	result := ss.ruleEngine.CheckRequest(req)

	switch result.Action {
	case RuleActionBlock:
		return 100
	case RuleActionRateLimit:
		return 60
	case RuleActionChallenge:
		return 40
	default:
		return 0
	}
}

// scoreChallenge 挑战历史评分
func (ss *SecurityScorer) scoreChallenge(ip string) float64 {
	if ss.challenge == nil {
		return 0
	}

	stats := ss.challenge.GetStats()
	if stats.TotalFailed > 0 {
		// 失败次数越多，分数越高
		return math.Min(float64(stats.TotalFailed)*10, 50)
	}

	return 0
}

// getOrCreateIPScore 获取或创建 IP 评分
func (ss *SecurityScorer) getOrCreateIPScore(ip string) *IPScore {
	ss.mu.RLock()
	score, ok := ss.ipScores[ip]
	ss.mu.RUnlock()

	if ok {
		return score
	}

	ss.mu.Lock()
	defer ss.mu.Unlock()

	// 双重检查
	if score, ok = ss.ipScores[ip]; ok {
		return score
	}

	score = &IPScore{
		IP:         ip,
		TotalScore: 0,
		Tags:       make([]string, 0),
	}
	ss.ipScores[ip] = score
	return score
}

// getSessionID 获取会话 ID
func (ss *SecurityScorer) getSessionID(req *http.Request) string {
	// 尝试从 cookie 获取
	cookie, err := req.Cookie("gocdn_session")
	if err == nil {
		return cookie.Value
	}

	// 使用 IP + UA 组合作为会话 ID
	return getClientIP(req) + ":" + req.UserAgent()
}

// updateSessionScore 更新会话评分
func (ss *SecurityScorer) updateSessionScore(sessionID, ip, ua string, score float64) {
	ss.mu.RLock()
	session, ok := ss.sessionScores[sessionID]
	ss.mu.RUnlock()

	if !ok {
		ss.mu.Lock()
		if session, ok = ss.sessionScores[sessionID]; !ok {
			session = &SessionScore{
				SessionID: sessionID,
				IP:        ip,
				UserAgent: ua,
				FirstSeen: time.Now(),
				Tags:      make([]string, 0),
			}
			ss.sessionScores[sessionID] = session
		}
		ss.mu.Unlock()
	}

	session.mu.Lock()
	session.TotalScore = score
	session.RequestCount++
	session.LastSeen = time.Now()
	session.mu.Unlock()
}

// getRiskLevel 获取风险等级
func (ss *SecurityScorer) getRiskLevel(score float64) RiskLevel {
	switch {
	case score >= ss.config.BlockThreshold:
		return RiskLevelCritical
	case score >= ss.config.ChallengeThreshold:
		return RiskLevelHigh
	case score >= ss.config.MonitorThreshold:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// makeDecision 生成决策
func (ss *SecurityScorer) makeDecision(decision *SecurityDecision, ipScore *IPScore) {
	switch decision.RiskLevel {
	case RiskLevelCritical:
		decision.Allow = false
		decision.Action = ActionBlock
		decision.RetryAfter = 1 * time.Hour
		ipScore.mu.Lock()
		ipScore.BlockCount++
		ipScore.mu.Unlock()

	case RiskLevelHigh:
		decision.Allow = false
		decision.Action = ActionChallenge
		decision.RequireCaptcha = true
		decision.WaitDuration = 5 * time.Second

	case RiskLevelMedium:
		decision.Allow = true
		decision.Action = ActionLog
		decision.WaitDuration = 1 * time.Second

	default:
		decision.Allow = true
		decision.Action = ActionAllow
	}
}

// getTags 获取风险标签
func (ss *SecurityScorer) getTags(decision *SecurityDecision) []string {
	tags := make([]string, 0)

	for _, tag := range ss.config.HighRiskTags {
		for _, reason := range decision.Reasons {
			if strings.Contains(reason, tag) {
				tags = append(tags, tag)
				break
			}
		}
	}

	for _, tag := range ss.config.MediumRiskTags {
		for _, reason := range decision.Reasons {
			if strings.Contains(reason, tag) {
				tags = append(tags, tag)
				break
			}
		}
	}

	return tags
}

// updateStats 更新统计
func (ss *SecurityScorer) updateStats(decision *SecurityDecision) {
	atomic.AddInt64(&ss.stats.TotalScored, 1)

	switch decision.Action {
	case ActionBlock:
		atomic.AddInt64(&ss.stats.TotalBlocked, 1)
	case ActionChallenge:
		atomic.AddInt64(&ss.stats.TotalChallenged, 1)
	}

	ss.stats.mu.Lock()
	ss.stats.ActiveIPScore = len(ss.ipScores)
	ss.stats.ActiveSessions = len(ss.sessionScores)
	ss.stats.mu.Unlock()
}

// GetIPScore 获取 IP 评分
func (ss *SecurityScorer) GetIPScore(ip string) (*IPScore, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	score, ok := ss.ipScores[ip]
	return score, ok
}

// GetHighRiskIPs 获取高风险 IP 列表
func (ss *SecurityScorer) GetHighRiskIPs() []*IPScore {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	highRisk := make([]*IPScore, 0)
	for _, score := range ss.ipScores {
		score.mu.RLock()
		if score.TotalScore >= ss.config.ChallengeThreshold {
			highRisk = append(highRisk, score)
		}
		score.mu.RUnlock()
	}
	return highRisk
}

// GetStats 获取统计
func (ss *SecurityScorer) GetStats() ScoringStats {
	return ScoringStats{
		TotalScored:     atomic.LoadInt64(&ss.stats.TotalScored),
		TotalBlocked:    atomic.LoadInt64(&ss.stats.TotalBlocked),
		TotalChallenged: atomic.LoadInt64(&ss.stats.TotalChallenged),
		ActiveIPScore:   ss.stats.ActiveIPScore,
		ActiveSessions:  ss.stats.ActiveSessions,
		AverageScore:    ss.calculateAverageScore(),
	}
}

// calculateAverageScore 计算平均分
func (ss *SecurityScorer) calculateAverageScore() float64 {
	ss.mu.RLock()
	total := float64(len(ss.ipScores))
	ss.mu.RUnlock()

	if total == 0 {
		return 0
	}

	var sum float64
	for _, score := range ss.ipScores {
		score.mu.RLock()
		sum += score.TotalScore
		score.mu.RUnlock()
	}

	return sum / total
}

// DecayScores 衰减分数
func (ss *SecurityScorer) DecayScores() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	now := time.Now()
	for _, score := range ss.ipScores {
		score.mu.Lock()
		if now.Sub(score.LastUpdate) > ss.config.ScoreWindow {
			score.TotalScore *= ss.config.DecayFactor
			score.LastUpdate = now
		}
		score.mu.Unlock()
	}
}

// Cleanup 清理过期评分
func (ss *SecurityScorer) Cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	threshold := time.Now().Add(-ss.config.ScoreWindow * 2)
	for ip, score := range ss.ipScores {
		score.mu.Lock()
		if score.LastUpdate.Before(threshold) && score.TotalScore < ss.config.MonitorThreshold {
			delete(ss.ipScores, ip)
		}
		score.mu.Unlock()
	}

	for sessionID, session := range ss.sessionScores {
		session.mu.Lock()
		if session.LastSeen.Before(threshold) {
			delete(ss.sessionScores, sessionID)
		}
		session.mu.Unlock()
	}
}

// Reset 重置
func (ss *SecurityScorer) Reset() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.ipScores = make(map[string]*IPScore)
	ss.sessionScores = make(map[string]*SessionScore)
	ss.stats = ScoringStats{}
}

// BlockIP 封禁 IP
func (ss *SecurityScorer) BlockIP(ip string, duration time.Duration) {
	score := ss.getOrCreateIPScore(ip)
	score.mu.Lock()
	score.TotalScore = 100
	score.BlockCount++
	score.Tags = append(score.Tags, "manual_block")
	score.mu.Unlock()

	if ss.analyzer != nil {
		ss.analyzer.BlockIP(ip, duration)
	}
}

// UnblockIP 解封 IP
func (ss *SecurityScorer) UnblockIP(ip string) {
	score := ss.getOrCreateIPScore(ip)
	score.mu.Lock()
	score.TotalScore = 0
	score.Tags = nil
	score.mu.Unlock()

	if ss.analyzer != nil {
		ss.analyzer.UnblockIP(ip)
	}
}

// SetConfig 设置配置
func (ss *SecurityScorer) SetConfig(config *ScoringConfig) {
	ss.mu.Lock()
	ss.config = config
	ss.mu.Unlock()
}

// GetConfig 获取配置
func (ss *SecurityScorer) GetConfig() *ScoringConfig {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return ss.config
}

package distribute

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-gost/core/logger"
)

// Distributor 流量分发器
type Distributor struct {
	mu          sync.RWMutex
	routes      map[string]*Route
	classifier  *TrafficClassifier
	lb          interface{} // 负载均衡器引用
	logger      logger.Logger
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// Route 路由规则
type Route struct {
	Name       string
	Pattern    string
	MatchType  MatchType
	TargetPool string
	Action     RouteAction
	Priority   int
	Enabled    bool
}

// MatchType 匹配类型
type MatchType string

const (
	MatchPath       MatchType = "path"
	MatchPathPrefix MatchType = "path_prefix"
	MatchHost       MatchType = "host"
	MatchMethod     MatchType = "method"
	MatchHeader     MatchType = "header"
	MatchRegex      MatchType = "regex"
	MatchAll        MatchType = "all"
)

// RouteAction 路由动作
type RouteAction string

const (
	ActionForward    RouteAction = "forward"
	ActionChallenge  RouteAction = "challenge"
	ActionRateLimit  RouteAction = "rate_limit"
	ActionBlock      RouteAction = "block"
	ActionClean      RouteAction = "clean"
	ActionDrop       RouteAction = "drop"
)

// TrafficContext 流量上下文
type TrafficContext struct {
	Request      *http.Request
	Response     http.ResponseWriter
	ClientIP     net.IP
	UserAgent    string
	Path         string
	Method       string
	Host         string
	Headers      map[string]string
	SessionID    string
	RiskScore    float64
	TrafficType  TrafficType
	IsWebBrowser bool
	IsAPI        bool
}

// TrafficType 流量类型
type TrafficType string

const (
	TrafficNormal      TrafficType = "normal"
	TrafficSuspicious  TrafficType = "suspicious"
	TrafficAttack      TrafficType = "attack"
	TrafficBot         TrafficType = "bot"
	TrafficAPI         TrafficType = "api"
)

// DistributeResult 分发结果
type DistributeResult struct {
	Route      string
	Action     RouteAction
	TargetPool string
	Matched    bool
	Reason     string
}

// NewDistributor 创建流量分发器
func NewDistributor(opts ...Option) *Distributor {
	d := &Distributor{
		routes:     make(map[string]*Route),
		classifier: NewClassifier(),
		logger:     logger.Default(),
		stopCh:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// Option 选项
type Option func(*Distributor)

// WithDistLogger 设置日志
func WithDistLogger(l logger.Logger) Option {
	return func(d *Distributor) {
		d.logger = l
	}
}

// WithDistLoadBalancer 设置负载均衡器
func WithDistLoadBalancer(lb interface{}) Option {
	return func(d *Distributor) {
		d.lb = lb
	}
}

// AddRoute 添加路由规则
func (d *Distributor) AddRoute(route *Route) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.routes[route.Name] = route
	d.logger.Infof("route added: %s -> %s", route.Name, route.TargetPool)
}

// RemoveRoute 移除路由规则
func (d *Distributor) RemoveRoute(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.routes, name)
	d.logger.Infof("route removed: %s", name)
}

// GetRoute 获取路由规则
func (d *Distributor) GetRoute(name string) (*Route, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	route, ok := d.routes[name]
	if !ok {
		return nil, ErrRouteNotFound
	}

	return route, nil
}

// Distribute 流量分发
func (d *Distributor) Distribute(ctx context.Context, traffic *TrafficContext) (*DistributeResult, error) {
	// 1. 流量分类
	trafficType := d.classifier.Classify(traffic)
	traffic.TrafficType = trafficType
	traffic.RiskScore = d.classifier.CalculateRiskScore(traffic)

	// 2. 匹配路由
	route, err := d.matchRoute(traffic)
	if err != nil {
		return nil, err
	}

	// 3. 执行路由动作
	result := &DistributeResult{
		Route:   route.Name,
		Action:  route.Action,
		Matched: true,
	}

	switch route.Action {
	case ActionForward:
		result.TargetPool = route.TargetPool

	case ActionChallenge:
		// 执行挑战验证
		if !d.performChallenge(traffic) {
			result.Action = ActionBlock
			result.Reason = "challenge failed"
		}

	case ActionRateLimit:
		// 执行限流
		if d.isRateLimited(traffic) {
			result.Action = ActionDrop
			result.Reason = "rate limited"
		}

	case ActionBlock:
		result.Reason = "blocked by rule"
		d.logger.Warnf("traffic blocked: %s %s", traffic.Method, traffic.Path)

	case ActionDrop:
		result.Reason = "dropped"
		d.logger.Debugf("traffic dropped: %s %s", traffic.Method, traffic.Path)

	case ActionClean:
		result.TargetPool = route.TargetPool
		result.Action = ActionForward
	}

	return result, nil
}

// matchRoute 匹配路由
func (d *Distributor) matchRoute(traffic *TrafficContext) (*Route, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var bestMatch *Route
	bestPriority := -1

	for _, route := range d.routes {
		if !route.Enabled {
			continue
		}

		if d.matchRouteRule(route, traffic) {
			if route.Priority > bestPriority {
				bestPriority = route.Priority
				bestMatch = route
			}
		}
	}

	if bestMatch == nil {
		// 返回默认路由
		return &Route{
			Name:      "default",
			Action:    ActionForward,
			TargetPool: "default",
		}, nil
	}

	return bestMatch, nil
}

// matchRouteRule 匹配单个路由规则
func (d *Distributor) matchRouteRule(route *Route, traffic *TrafficContext) bool {
	switch route.MatchType {
	case MatchPath:
		return traffic.Path == route.Pattern
	case MatchPathPrefix:
		return strings.HasPrefix(traffic.Path, route.Pattern)
	case MatchHost:
		return traffic.Host == route.Pattern
	case MatchMethod:
		return traffic.Method == route.Pattern
	case MatchHeader:
		return d.matchHeader(route.Pattern, traffic.Headers)
	case MatchRegex:
		return d.matchRegex(route.Pattern, traffic.Path)
	case MatchAll:
		return true
	default:
		return false
	}
}

// matchHeader 匹配 Header
func (d *Distributor) matchHeader(pattern string, headers map[string]string) bool {
	// 格式: "HeaderName:value"
	parts := strings.SplitN(pattern, ":", 2)
	if len(parts) != 2 {
		return false
	}
	headerName := parts[0]
	expectedValue := parts[1]

	if value, ok := headers[headerName]; ok {
		return value == expectedValue
	}
	return false
}

// matchRegex 匹配正则（简化实现：检查是否包含）
func (d *Distributor) matchRegex(pattern, value string) bool {
	return strings.Contains(value, pattern)
}

// performChallenge 执行挑战验证
func (d *Distributor) performChallenge(traffic *TrafficContext) bool {
	// 检查是否是 API 请求（禁用挑战）
	if traffic.IsAPI {
		d.logger.Debugf("challenge skipped for API request: %s", traffic.Path)
		return true // API 请求跳过挑战，直接放行
	}

	// 检查是否是 WebSocket 或 SSE（禁用挑战）
	if traffic.Headers["Upgrade"] == "websocket" ||
		traffic.Headers["Accept"] == "text/event-stream" {
		return true
	}

	// TODO: 实现 JS Challenge / Captcha 挑战
	// 这里返回 true 表示挑战通过（简化实现）
	return true
}

// isRateLimited 检查是否被限流
func (d *Distributor) isRateLimited(traffic *TrafficContext) bool {
	// TODO: 实现限流逻辑
	return false
}

// Start 启动分发器
func (d *Distributor) Start(ctx context.Context) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.run(ctx)
	}()

	d.logger.Info("traffic distributor started")
}

// Stop 停止分发器
func (d *Distributor) Stop() {
	close(d.stopCh)
	d.wg.Wait()
	d.logger.Info("traffic distributor stopped")
}

// run 运行分发器
func (d *Distributor) run(ctx context.Context) {
	<-ctx.Done()
}

// GetStats 获取统计信息
func (d *Distributor) GetStats() DistributorStats {
	stats := DistributorStats{
		Routes: make([]RouteStats, 0),
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for name, route := range d.routes {
		stats.Routes = append(stats.Routes, RouteStats{
			Name:       name,
			TargetPool: route.TargetPool,
			Action:     string(route.Action),
			Enabled:    route.Enabled,
			Priority:   route.Priority,
		})
	}

	stats.TotalRoutes = len(d.routes)
	stats.ClassifierStats = d.classifier.GetStats()

	return stats
}

// DistributorStats 分发器统计
type DistributorStats struct {
	TotalRoutes     int
	Routes          []RouteStats
	ClassifierStats ClassifierStats
}

// RouteStats 路由统计
type RouteStats struct {
	Name       string
	TargetPool string
	Action     string
	Enabled    bool
	Priority   int
}

// ClassifierStats 分类器统计
type ClassifierStats struct {
	NormalRequests     int64
	SuspiciousRequests int64
	AttackRequests     int64
	BotRequests        int64
	APIRequests        int64
}

// TrafficClassifier 流量分类器
type TrafficClassifier struct {
	normalCount     atomic.Int64
	suspiciousCount atomic.Int64
	attackCount     atomic.Int64
	botCount        atomic.Int64
	apiCount        atomic.Int64
}

// NewClassifier 创建流量分类器
func NewClassifier() *TrafficClassifier {
	return &TrafficClassifier{}
}

// Classify 流量分类
func (c *TrafficClassifier) Classify(traffic *TrafficContext) TrafficType {
	// 1. 检查 User-Agent
	if isBotUserAgent(traffic.UserAgent) {
		c.botCount.Add(1)
		return TrafficBot
	}

	// 2. 检查路径模式（API）
	if isAPIPath(traffic.Path) {
		c.apiCount.Add(1)
		traffic.IsAPI = true
		return TrafficAPI
	}

	// 3. 检查风险分数
	if traffic.RiskScore > 80 {
		c.attackCount.Add(1)
		return TrafficAttack
	} else if traffic.RiskScore > 40 {
		c.suspiciousCount.Add(1)
		return TrafficSuspicious
	}

	c.normalCount.Add(1)
	return TrafficNormal
}

// CalculateRiskScore 计算风险分数
func (c *TrafficClassifier) CalculateRiskScore(traffic *TrafficContext) float64 {
	score := 0.0

	// 1. User-Agent 检查
	if traffic.UserAgent == "" {
		score += 30 // 无 UA 高风险
	} else if isSuspiciousUserAgent(traffic.UserAgent) {
		score += 50
	}

	// 2. 路径检查
	if isSuspiciousPath(traffic.Path) {
		score += 60
	}

	// 3. 请求频率（需要外部注入）

	// 4. 异常 Header
	if traffic.Headers["X-Forwarded-For"] != "" &&
		traffic.Headers["X-Real-IP"] != "" &&
		traffic.Headers["X-Forwarded-For"] != traffic.Headers["X-Real-IP"] {
		score += 20 // IP 伪造
	}

	return score
}

// GetStats 获取统计
func (c *TrafficClassifier) GetStats() ClassifierStats {
	return ClassifierStats{
		NormalRequests:     c.normalCount.Load(),
		SuspiciousRequests: c.suspiciousCount.Load(),
		AttackRequests:     c.attackCount.Load(),
		BotRequests:        c.botCount.Load(),
		APIRequests:        c.apiCount.Load(),
	}
}

// isBotUserAgent 检查是否是 Bot
func isBotUserAgent(ua string) bool {
	if ua == "" {
		return false
	}

	uaLower := strings.ToLower(ua)
	botIndicators := []string{
		"bot", "crawler", "spider", "slurp", "bingbot", "googlebot",
		"facebookexternalhit", "twitterbot", "linkedinbot", "pinterest",
	}

	for _, indicator := range botIndicators {
		if strings.Contains(uaLower, indicator) {
			return true
		}
	}
	return false
}

// isAPIPath 检查是否是 API 路径
func isAPIPath(path string) bool {
	apiPrefixes := []string{
		"/api/", "/v1/", "/v2/", "/rest/", "/graphql",
	}

	for _, prefix := range apiPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// isSuspiciousUserAgent 检查可疑 UA
func isSuspiciousUserAgent(ua string) bool {
	uaLower := strings.ToLower(ua)
	suspicious := []string{
		"python-requests", "curl", "wget", "java/", "okhttp",
	}

	for _, s := range suspicious {
		if strings.Contains(uaLower, s) {
			return true
		}
	}
	return false
}

// isSuspiciousPath 检查可疑路径
func isSuspiciousPath(path string) bool {
	suspicious := []string{
		"/../", "/.../", "/.env", "/config.php", "/wp-admin",
		"/.git/", "/.svn/", "/phpinfo", "/web.xml",
	}

	for _, s := range suspicious {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

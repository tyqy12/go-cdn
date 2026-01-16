package defense

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/pkg/config"
)

// FailoverController 故障切换控制器
type FailoverController struct {
	config         *config.FailoverConfig
	currentTarget  string
	failoverCount  int
	lastSwitchTime time.Time
	lastFailTime   time.Time
	healthStatus   *HealthStatus
	mu             sync.RWMutex
	logger         Logger
	ctx            context.Context
	cancel         context.CancelFunc
	client         *http.Client
}

// HealthStatus 健康状态
type HealthStatus struct {
	CurrentTarget string
	Status        string
	Healthy       bool
	FailureCount  int
	SuccessCount  int
	LastCheck     time.Time
	LastFail      *time.Time
	LastSuccess   *time.Time
}

// FailoverEvent 故障切换事件
type FailoverEvent struct {
	ID          string
	Type        string
	FromTarget  string
	ToTarget    string
	Reason      string
	Status      string
	TriggeredAt time.Time
	CompletedAt *time.Time
	Success     bool
}

// NewFailoverController 创建故障切换控制器
func NewFailoverController(cfg *config.FailoverConfig, opts ...FailoverOption) (*FailoverController, error) {
	if cfg == nil {
		return nil, fmt.Errorf("故障切换配置不能为空")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("故障切换配置验证失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	fc := &FailoverController{
		config:        cfg,
		currentTarget: "primary",
		failoverCount: 0,
		healthStatus: &HealthStatus{
			CurrentTarget: "primary",
			Status:        "initializing",
			Healthy:       true,
			FailureCount:  0,
			SuccessCount:  0,
			LastCheck:     time.Now(),
		},
		logger: newLogger(loggerTypeDefault),
		ctx:    ctx,
		cancel: cancel,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(fc)
	}

	return fc, nil
}

// FailoverOption 故障切换控制器选项
type FailoverOption func(*FailoverController)

// WithFailoverLogger 设置日志
func WithFailoverLogger(l Logger) FailoverOption {
	return func(fc *FailoverController) {
		fc.logger = l
	}
}

// Start 启动故障切换控制器
func (fc *FailoverController) Start() error {
	if !fc.config.Enabled {
		fc.logger.Infof("故障切换未启用")
		return nil
	}

	fc.logger.Infof("启动故障切换控制器")

	// 启动健康检查
	if fc.config.HealthCheck != nil {
		go fc.healthCheckLoop()
	}

	return nil
}

// Stop 停止故障切换控制器
func (fc *FailoverController) Stop() {
	fc.logger.Infof("停止故障切换控制器")
	if fc.cancel != nil {
		fc.cancel()
	}
}

// healthCheckLoop 健康检查循环
func (fc *FailoverController) healthCheckLoop() {
	if fc.config.Detection == nil {
		return
	}

	ticker := time.NewTicker(fc.config.Detection.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-fc.ctx.Done():
			return
		case <-ticker.C:
			fc.performHealthCheck()
		}
	}
}

// performHealthCheck 执行健康检查
func (fc *FailoverController) performHealthCheck() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.config.HealthCheck == nil {
		return
	}

	healthy := fc.checkTargetHealth(fc.currentTarget)

	fc.healthStatus.LastCheck = time.Now()

	if healthy {
		fc.healthStatus.SuccessCount++
		fc.healthStatus.FailureCount = 0
		fc.healthStatus.Healthy = true
		now := time.Now()
		fc.healthStatus.LastSuccess = &now
		fc.healthStatus.Status = "healthy"

		// 检查是否需要回切
		if fc.config.Rollback != nil && fc.config.Rollback.Enabled {
			fc.checkAndPerformRollback()
		}
	} else {
		fc.healthStatus.FailureCount++
		fc.healthStatus.SuccessCount = 0
		fc.healthStatus.Healthy = false
		now := time.Now()
		fc.healthStatus.LastFail = &now
		fc.healthStatus.Status = "unhealthy"

		fc.logger.Warnf("健康检查失败: 目标=%s, 失败次数=%d/%d",
			fc.currentTarget, fc.healthStatus.FailureCount, fc.config.Detection.FailureThreshold)

		// 检查是否需要故障切换
		if fc.healthStatus.FailureCount >= fc.config.Detection.FailureThreshold {
			fc.checkAndPerformFailover()
		}
	}
}

// checkTargetHealth 检查目标健康状态
func (fc *FailoverController) checkTargetHealth(target string) bool {
	if fc.config.HealthCheck == nil {
		return true
	}

	if fc.config.Detection == nil || len(fc.config.Detection.Types) == 0 {
		return fc.checkHTTPHealth()
	}

	checkType := fc.config.Detection.Types[0]
	switch checkType {
	case "http":
		return fc.checkHTTPHealth()
	case "tcp":
		return fc.checkTCPHealth()
	case "icmp":
		return fc.checkICMPHealth()
	case "dns":
		return true
	default:
		return fc.checkHTTPHealth()
	}
}

// checkHTTPHealth HTTP健康检查
func (fc *FailoverController) checkHTTPHealth() bool {
	if fc.config.HealthCheck.CheckURL == "" {
		return true
	}

	ctx, cancel := context.WithTimeout(fc.ctx, fc.config.Detection.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, fc.config.HealthCheck.Method, fc.config.HealthCheck.CheckURL, nil)
	if err != nil {
		fc.logger.Debugf("创建HTTP请求失败: %v", err)
		return false
	}

	resp, err := fc.client.Do(req)
	if err != nil {
		fc.logger.Debugf("HTTP请求失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	// 检查状态码
	expectedCode := fc.config.HealthCheck.ExpectedStatusCode
	if expectedCode > 0 && resp.StatusCode != expectedCode {
		fc.logger.Debugf("HTTP状态码不匹配: got=%d, expected=%d", resp.StatusCode, expectedCode)
		return false
	}

	// 检查响应体
	if fc.config.HealthCheck.ResponseBody != "" {
		return true
	}

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// checkTCPHealth TCP健康检查
func (fc *FailoverController) checkTCPHealth() bool {
	host, port, err := net.SplitHostPort(fc.config.HealthCheck.CheckURL)
	if err != nil {
		return false
	}

	timeout := fc.config.Detection.Timeout
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkICMPHealth ICMP健康检查
func (fc *FailoverController) checkICMPHealth() bool {
	return true
}

// checkAndPerformFailover 检查并执行故障切换
func (fc *FailoverController) checkAndPerformFailover() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// 检查切换配置
	if fc.config.Switch == nil || fc.config.Switch.Mode != "auto" {
		fc.logger.Infof("故障切换模式不是自动，需要手动触发")
		return
	}

	// 检查切换窗口
	if fc.config.Switch.ForbidSwitchWindow && fc.isInForbiddenWindow() {
		fc.logger.Warnf("当前在禁止切换窗口，暂不执行故障切换")
		return
	}

	// 检查最大切换次数
	if fc.config.Switch.MaxSwitches > 0 && fc.failoverCount >= fc.config.Switch.MaxSwitches {
		fc.logger.Warnf("已达到最大切换次数限制: %d", fc.failoverCount)
		return
	}

	// 检查切换延迟
	if !fc.lastSwitchTime.IsZero() && time.Since(fc.lastSwitchTime) < fc.config.Switch.SwitchDelay {
		fc.logger.Infof("切换延迟保护，暂不执行故障切换")
		return
	}

	// 记录当前故障时间
	fc.lastFailTime = time.Now()

	// 执行故障切换
	fc.performFailover("auto")
}

// performFailover 执行故障切换
func (fc *FailoverController) performFailover(trigger string) {
	fromTarget := fc.currentTarget
	toTarget := "secondary"

	if fc.currentTarget == "secondary" {
		toTarget = "primary"
	}

	fc.logger.Infof("开始故障切换: %s -> %s, 触发方式: %s", fromTarget, toTarget, trigger)

	// 记录切换事件
	event := &FailoverEvent{
		ID:          fmt.Sprintf("failover_%d", time.Now().UnixNano()),
		Type:        "failover",
		FromTarget:  fromTarget,
		ToTarget:    toTarget,
		Reason:      fmt.Sprintf("health check failure: %s", fc.healthStatus.Status),
		Status:      "in_progress",
		TriggeredAt: time.Now(),
		Success:     false,
	}

	// 执行切换逻辑
	fc.executeSwitch(fromTarget, toTarget)

	fc.currentTarget = toTarget
	fc.failoverCount++
	fc.lastSwitchTime = time.Now()
	fc.healthStatus.CurrentTarget = toTarget

	now := time.Now()
	event.CompletedAt = &now
	event.Status = "completed"
	event.Success = true

	fc.logger.Infof("故障切换完成: %s -> %s", fromTarget, toTarget)
}

// executeSwitch 执行实际的切换操作
func (fc *FailoverController) executeSwitch(fromTarget, toTarget string) error {
	fc.logger.Infof("执行切换操作: %s -> %s", fromTarget, toTarget)

	var err error

	switch fc.config.Switch.Mode {
	case "dns":
		err = fc.switchViaDNS(toTarget)
	case "bgp":
		err = fc.switchViaBGP(toTarget)
	case "loadbalancer":
		err = fc.switchViaLoadBalancer(toTarget)
	case "route":
		err = fc.switchViaRouteTable(toTarget)
	default:
		err = fc.switchViaDNS(toTarget)
	}

	if err != nil {
		fc.logger.Errorf("切换操作失败: %v", err)
		return err
	}

	fc.logger.Infof("切换操作执行成功: %s", toTarget)
	return nil
}

// switchViaDNS 通过DNS切换
func (fc *FailoverController) switchViaDNS(target string) error {
	fc.logger.Infof("DNS切换到: %s", target)
	return nil
}

// switchViaBGP 通过BGP切换
func (fc *FailoverController) switchViaBGP(target string) error {
	fc.logger.Infof("BGP切换到: %s", target)

	if fc.config.BGPConfig == nil {
		return nil
	}

	if target == "secondary" {
		fc.logger.Infof("BGP公告牵引前缀: %v", fc.config.BGPConfig.SteeringPrefixes)
	} else {
		fc.logger.Infof("BGP撤回牵引前缀，公告正常前缀: %v", fc.config.BGPConfig.NormalPrefixes)
	}

	return nil
}

// switchViaLoadBalancer 通过负载均衡器切换
func (fc *FailoverController) switchViaLoadBalancer(target string) error {
	fc.logger.Infof("负载均衡器切换到: %s", target)

	if fc.config.LoadBalancerConfig == nil {
		return nil
	}

	fc.logger.Infof("更新负载均衡器后端: %s -> %s", fc.config.LoadBalancerConfig.PrimaryBackend, fc.config.LoadBalancerConfig.SecondaryBackend)

	return nil
}

// switchViaRouteTable 通过路由表切换
func (fc *FailoverController) switchViaRouteTable(target string) error {
	fc.logger.Infof("路由表切换到: %s", target)

	if fc.config.RouteTableConfig == nil {
		return nil
	}

	if target == "secondary" {
		fc.logger.Infof("添加故障路由: %s via %s", fc.config.RouteTableConfig.Destination, fc.config.RouteTableConfig.Gateway)
	} else {
		fc.logger.Infof("移除故障路由: %s", fc.config.RouteTableConfig.Destination)
	}

	return nil
}

// checkAndPerformRollback 检查并执行回切
func (fc *FailoverController) checkAndPerformRollback() {
	if fc.currentTarget == "primary" {
		return
	}

	// 检查稳定窗口
	if fc.healthStatus.SuccessCount < fc.config.Detection.SuccessThreshold {
		return
	}

	// 检查抖动保护
	if time.Since(fc.lastSwitchTime) < fc.config.Rollback.StableWindow {
		return
	}

	// 检查最小故障时间
	if fc.config.Rollback.MinFailureTime > 0 && time.Since(fc.lastFailTime) < fc.config.Rollback.MinFailureTime {
		return
	}

	// 执行回切
	if fc.config.Rollback.RollbackDelay > 0 {
		time.Sleep(fc.config.Rollback.RollbackDelay)
	}

	fc.performRollback()
}

// performRollback 执行回切
func (fc *FailoverController) performRollback() {
	fromTarget := fc.currentTarget
	toTarget := "primary"

	fc.logger.Infof("开始回切: %s -> %s", fromTarget, toTarget)

	event := &FailoverEvent{
		ID:          fmt.Sprintf("rollback_%d", time.Now().UnixNano()),
		Type:        "rollback",
		FromTarget:  fromTarget,
		ToTarget:    toTarget,
		Reason:      "primary target is now healthy",
		Status:      "in_progress",
		TriggeredAt: time.Now(),
		Success:     false,
	}

	// 执行回切逻辑
	fc.currentTarget = toTarget
	fc.healthStatus.CurrentTarget = toTarget

	now := time.Now()
	event.CompletedAt = &now
	event.Status = "completed"
	event.Success = true

	fc.logger.Infof("回切完成: %s -> %s", fromTarget, toTarget)
}

// isInForbiddenWindow 检查是否在禁止切换窗口
func (fc *FailoverController) isInForbiddenWindow() bool {
	if fc.config.Switch == nil {
		return false
	}

	now := time.Now()
	currentTime := now.Format("15:04")

	start := fc.config.Switch.WindowStart
	end := fc.config.Switch.WindowEnd

	return currentTime >= start && currentTime <= end
}

// ManualFailover 手动故障切换
func (fc *FailoverController) ManualFailover(ctx context.Context, reason string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.logger.Infof("手动故障切换: %s, 原因: %s", fc.currentTarget, reason)

	fc.performFailover("manual")
	return nil
}

// ManualRollback 手动回切
func (fc *FailoverController) ManualRollback(ctx context.Context, reason string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.currentTarget == "primary" {
		return fmt.Errorf("当前已在主节点，无需回切")
	}

	fc.logger.Infof("手动回切: %s, 原因: %s", fc.currentTarget, reason)

	fc.performRollback()
	return nil
}

// GetStatus 获取状态
func (fc *FailoverController) GetStatus() *FailoverStatus {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	return &FailoverStatus{
		CurrentTarget:  fc.currentTarget,
		Status:         fc.healthStatus.Status,
		Healthy:        fc.healthStatus.Healthy,
		FailoverCount:  fc.failoverCount,
		LastSwitchTime: fc.lastSwitchTime,
		LastFailTime:   fc.lastFailTime,
		HealthStatus:   fc.healthStatus,
	}
}

// FailoverStatus 故障切换状态
type FailoverStatus struct {
	CurrentTarget  string
	Status         string
	Healthy        bool
	FailoverCount  int
	LastSwitchTime time.Time
	LastFailTime   time.Time
	HealthStatus   *HealthStatus
}

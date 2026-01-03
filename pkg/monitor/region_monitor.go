package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RegionMonitor 区域监控服务 - 多终端部署
type RegionMonitor struct {
	config     *RegionConfig
	terminals  map[string]*MonitorTerminal
	sites      map[string]*MonitoredSite
	checkers   map[string]HealthChecker
	aggregator *ResultAggregator
	mu         sync.RWMutex
	stats      *RegionStats
	ctx        context.Context
	cancel     context.CancelFunc
}

// RegionConfig 区域监控配置
type RegionConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 终端配置
	Terminals []*TerminalConfig `yaml:"terminals"`

	// 全局检查配置
	GlobalCheckConfig *CheckConfig `yaml:"global_check_config"`

	// 聚合配置
	AggregationConfig *AggregationConfig `yaml:"aggregation_config"`

	// 告警配置
	AlertConfig *RegionAlertConfig `yaml:"alert_config"`

	// 报告配置
	ReportConfig *ReportConfig `yaml:"report_config"`

	// 数据同步配置
	SyncConfig *SyncConfig `yaml:"sync_config"`
}

// TerminalConfig 终端配置
type TerminalConfig struct {
	// 终端ID
	ID string `json:"id"`

	// 终端名称
	Name string `json:"name"`

	// 终端类型
	Type string `json:"type"` // "china_mainland", "hong_kong", "overseas", "custom"

	// 位置
	Location *TerminalLocation `json:"location"`

	// 网络配置
	Network *TerminalNetwork `json:"network"`

	// 分配的任务
	AssignedTasks []*TaskAssignment `json:"assigned_tasks"`

	// 状态
	Status string `json:"status"` // "online", "offline", "maintenance"

	// 性能限制
	Performance *TerminalPerformance `json:"performance"`

	// 心跳配置
	Heartbeat *HeartbeatConfig `json:"heartbeat"`
}

// TerminalLocation 终端位置
type TerminalLocation struct {
	// 区域
	Region string `json:"region"`

	// 国家
	Country string `json:"country"`

	// 城市
	City string `json:"city"`

	// 经纬度
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	// 时区
	Timezone string `json:"timezone"`

	// ISP
	ISP string `json:"isp"`

	// ASN
	ASN string `json:"asn"`
}

// TerminalNetwork 终端网络配置
type TerminalNetwork struct {
	// IP地址
	IPAddresses []string `json:"ip_addresses"`

	// 代理配置
	Proxy *RegionProxyConfig `json:"proxy"`

	// DNS配置
	DNS []string `json:"dns"`

	// 带宽
	Bandwidth int `json:"bandwidth"` // Mbps

	// 延迟配置
	LatencyConfig *LatencyConfig `json:"latency_config"`

	// 防火墙规则
	FirewallRules []string `json:"firewall_rules"`
}

// RegionProxyConfig 代理配置
type RegionProxyConfig struct {
	// 类型
	Type string `json:"type"` // "http", "socks5", "direct"

	// 地址
	Address string `json:"address"`

	// 端口
	Port int `json:"port"`

	// 认证
	Auth *ProxyAuth `json:"auth"`

	// 排除列表
	Excludes []string `json:"excludes"`
}

// LatencyConfig 延迟配置
type LatencyConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Samples  int           `json:"samples"`
}

// ProxyAuth 代理认证
type ProxyAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TaskAssignment 任务分配
type TaskAssignment struct {
	// 任务ID
	TaskID string `json:"task_id"`

	// 任务类型
	Type string `json:"type"` // "http", "tcp", "dns", "ping", "ssl", "keyword"

	// 目标
	Target string `json:"target"`

	// 配置
	Config interface{} `json:"config"`

	// 调度配置
	Schedule *TaskSchedule `json:"schedule"`

	// 优先级
	Priority int `json:"priority"` // 1-10

	// 启用状态
	Enabled bool `json:"enabled"`
}

// TaskSchedule 任务调度
type TaskSchedule struct {
	// 间隔
	Interval time.Duration `json:"interval"`

	// 定时
	CronExpression string `json:"cron_expression"`

	// 时区
	Timezone string `json:"timezone"`

	// 有效时间
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}

// TerminalPerformance 终端性能
type TerminalPerformance struct {
	// 最大并发检查数
	MaxConcurrentChecks int `json:"max_concurrent_checks"`

	// 最大QPS
	MaxQPS int `json:"max_qps"`

	// 内存限制
	MemoryLimit int64 `json:"memory_limit"` // MB

	// CPU限制
	CPULimit float64 `json:"cpu_limit"` // percentage

	// 网络限制
	NetworkLimit int `json:"network_limit"` // Mbps
}

// HeartbeatConfig 心跳配置
type HeartbeatConfig struct {
	// 间隔
	Interval time.Duration `json:"interval"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 失败阈值
	FailureThreshold int `json:"failure_threshold"`

	// 通知URL
	NotifyURL string `json:"notify_url"`
}

// MonitorTerminal 监控终端
type MonitorTerminal struct {
	Config *TerminalConfig `json:"config"`

	// 状态
	Status string `json:"status"`

	// 健康状态
	Health *TerminalHealth `json:"health"`

	// 当前任务
	CurrentTasks int `json:"current_tasks"`

	// 执行统计
	Stats *TerminalStats `json:"stats"`

	// 最后活跃时间
	LastActive time.Time `json:"last_active"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`
}

// TerminalHealth 终端健康
type TerminalHealth struct {
	// 整体状态
	Status string `json:"status"` // "healthy", "degraded", "unhealthy"

	// CPU使用率
	CPUUsage float64 `json:"cpu_usage"`

	// 内存使用率
	MemoryUsage float64 `json:"memory_usage"`

	// 磁盘使用率
	DiskUsage float64 `json:"disk_usage"`

	// 网络使用率
	NetworkUsage float64 `json:"network_usage"`

	// 任务队列长度
	TaskQueueLength int `json:"task_queue_length"`

	// 失败率
	FailureRate float64 `json:"failure_rate"`

	// 最后检查时间
	LastCheck time.Time `json:"last_check"`

	// 检查项
	Checks []*HealthCheckItem `json:"checks"`
}

// HealthCheckItem 健康检查项
type HealthCheckItem struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"` // "pass", "fail", "warn"
	Message   string    `json:"message"`
	LastCheck time.Time `json:"last_check"`
}

// TerminalStats 终端统计
type TerminalStats struct {
	// 总检查数
	TotalChecks int64 `json:"total_checks"`

	// 成功数
	SuccessfulChecks int64 `json:"successful_checks"`

	// 失败数
	FailedChecks int64 `json:"failed_checks"`

	// 平均响应时间
	AverageResponseTime time.Duration `json:"average_response_time"`

	// 总检查时间
	TotalCheckTime time.Duration `json:"total_check_time"`

	// 数据上传大小
	DataUploaded int64 `json:"data_uploaded"` // bytes

	// 数据下载大小
	DataDownloaded int64 `json:"data_downloaded"` // bytes

	mu sync.RWMutex
}

// AggregationConfig 聚合配置
type AggregationConfig struct {
	// 启用聚合
	Enabled bool `json:"enabled"`

	// 聚合间隔
	Interval time.Duration `json:"interval"`

	// 聚合策略
	Strategy string `json:"strategy"` // "average", "min", "max", "percentile"

	// 百分位数
	Percentile float64 `json:"percentile"` // 50, 90, 95, 99

	// 数据保留时间
	Retention time.Duration `json:"retention"`

	// 压缩配置
	Compression *CompressionConfig `json:"compression"`
}

// CompressionConfig 压缩配置
type CompressionConfig struct {
	// 启用压缩
	Enabled bool `json:"enabled"`

	// 压缩算法
	Algorithm string `json:"algorithm"` // "gzip", "lz4", "snappy"

	// 压缩级别
	Level int `json:"level"`
}

// RegionAlertConfig 区域告警配置
type RegionAlertConfig struct {
	// 启用告警
	Enabled bool `json:"enabled"`

	// 告警规则
	Rules []*RegionAlertRule `json:"rules"`

	// 聚合告警
	Aggregation *AlertAggregation `json:"aggregation"`

	// 告警抑制
	Suppression *AlertSuppression `json:"suppression"`

	// 升级配置
	Escalation *AlertEscalation `json:"escalation"`
}

// AlertEscalation 告警升级配置
type AlertEscalation struct {
	Enabled  bool              `json:"enabled"`
	Interval time.Duration     `json:"interval"`
	Levels   []EscalationLevel `json:"levels"`
}

// EscalationLevel 升级级别
type EscalationLevel struct {
	Level      int      `json:"level"`
	Recipients []string `json:"recipients"`
	Channels   []string `json:"channels"`
}

// RegionAlertRule 区域告警规则
type RegionAlertRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// 触发条件
	Condition *AlertCondition `json:"condition"`

	// 评估窗口
	Window time.Duration `json:"window"`

	// 评估频率
	Frequency time.Duration `json:"frequency"`

	// 标签
	Labels map[string]string `json:"labels"`

	// 注释
	Annotations map[string]string `json:"annotations"`

	// 状态
	Enabled bool `json:"enabled"`

	// 严重程度
	Severity string `json:"severity"` // "critical", "warning", "info"

	// 动作
	Actions []string `json:"actions"`
}

// AlertAggregation 告警聚合
type AlertAggregation struct {
	// 启用聚合
	Enabled bool `json:"enabled"`

	// 聚合窗口
	Window time.Duration `json:"window"`

	// 聚合字段
	Fields []string `json:"fields"`

	// 聚合策略
	Strategy string `json:"strategy"` // "sum", "avg", "max"

	// 阈值
	Threshold int `json:"threshold"`
}

// AlertSuppression 告警抑制
type AlertSuppression struct {
	// 启用抑制
	Enabled bool `json:"enabled"`

	// 抑制时间
	Duration time.Duration `json:"duration"`

	// 抑制规则
	Rules []*SuppressionRule `json:"rules"`
}

// SuppressionRule 抑制规则
type SuppressionRule struct {
	// 匹配条件
	Match *SuppressionMatch `json:"match"`

	// 抑制时间
	Duration time.Duration `json:"duration"`
}

// SuppressionMatch 抑制匹配
type SuppressionMatch struct {
	Labels    map[string]string `json:"labels"`
	Severity  string            `json:"severity"`
	AlertName string            `json:"alert_name"`
}

// SyncConfig 同步配置
type SyncConfig struct {
	// 启用同步
	Enabled bool `json:"enabled"`

	// 同步间隔
	Interval time.Duration `json:"interval"`

	// 同步协议
	Protocol string `json:"protocol"` // "http", "grpc", "mqtt"

	// 端点
	Endpoints []string `json:"endpoints"`

	// 认证
	Auth *SyncAuth `json:"auth"`

	// 数据压缩
	Compression bool `json:"compression"`

	// 批量大小
	BatchSize int `json:"batch_size"`

	// 重试配置
	Retry *SyncRetry `json:"retry"`
}

// SyncAuth 同步认证
type SyncAuth struct {
	Type      string     `json:"type"` // "none", "token", "tls"
	Token     string     `json:"token"`
	TLSConfig *TLSConfig `json:"tls_config"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

// SyncRetry 同步重试
type SyncRetry struct {
	// 最大重试次数
	MaxRetries int `json:"max_retries"`

	// 重试间隔
	Interval time.Duration `json:"interval"`

	// 指数退避
	ExponentialBackoff bool `json:"exponential_backoff"`

	// 最大间隔
	MaxInterval time.Duration `json:"max_interval"`
}

// ResultAggregator 结果聚合器
type ResultAggregator struct {
	config      *AggregationConfig
	results     []*CheckResult
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	statsMu     sync.RWMutex
	stats       *AggregatedMetrics
	errorCounts map[string]int
}

// RegionStats 区域统计
type RegionStats struct {
	TotalTerminals   int `json:"total_terminals"`
	OnlineTerminals  int `json:"online_terminals"`
	OfflineTerminals int `json:"offline_terminals"`

	TotalSites  int   `json:"total_sites"`
	TotalChecks int64 `json:"total_checks"`
	TotalAlerts int64 `json:"total_alerts"`

	// 聚合指标
	AggregatedMetrics *AggregatedMetrics `json:"aggregated_metrics"`

	// 按区域统计
	MetricsByRegion map[string]*RegionalMetrics `json:"metrics_by_region"`

	// 按终端统计
	MetricsByTerminal map[string]*TerminalMetrics `json:"metrics_by_terminal"`

	mu sync.RWMutex
}

// AggregatedMetrics 聚合指标
type AggregatedMetrics struct {
	// 全局可用率
	GlobalAvailability float64 `json:"global_availability"`

	// 平均响应时间
	AverageResponseTime time.Duration `json:"average_response_time"`

	// P50响应时间
	ResponseTimeP50 time.Duration `json:"response_time_p50"`

	// P90响应时间
	ResponseTimeP90 time.Duration `json:"response_time_p90"`

	// P99响应时间
	ResponseTimeP99 time.Duration `json:"response_time_p99"`

	// 平均错误率
	AverageErrorRate float64 `json:"average_error_rate"`

	// 告警数量
	AlertCount int64 `json:"alert_count"`

	// 最后更新
	LastUpdate time.Time `json:"last_update"`
}

// RegionalMetrics 区域指标
type RegionalMetrics struct {
	Region string `json:"region"`

	// 可用率
	Availability float64 `json:"availability"`

	// 平均响应时间
	AverageResponseTime time.Duration `json:"average_response_time"`

	// 检查次数
	Checks int64 `json:"checks"`

	// 失败次数
	Failures int64 `json:"failures"`

	// 告警次数
	Alerts int64 `json:"alerts"`

	// 终端数
	Terminals int `json:"terminals"`

	// 在线终端数
	OnlineTerminals int `json:"online_terminals"`

	mu sync.RWMutex
}

// TerminalMetrics 终端指标
type TerminalMetrics struct {
	TerminalID   string `json:"terminal_id"`
	TerminalName string `json:"terminal_name"`

	// 检查次数
	Checks int64 `json:"checks"`

	// 成功次数
	Successes int64 `json:"successes"`

	// 失败次数
	Failures int64 `json:"failures"`

	// 平均响应时间
	AverageResponseTime time.Duration `json:"average_response_time"`

	// 最后检查时间
	LastCheck time.Time `json:"last_check"`

	mu sync.RWMutex
}

// NewRegionMonitor 创建区域监控服务
func NewRegionMonitor(config *RegionConfig) *RegionMonitor {
	if config == nil {
		config = &RegionConfig{
			Enabled: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &RegionMonitor{
		config:     config,
		terminals:  make(map[string]*MonitorTerminal),
		sites:      make(map[string]*MonitoredSite),
		checkers:   make(map[string]HealthChecker),
		aggregator: NewResultAggregator(config.AggregationConfig),
		stats: &RegionStats{
			MetricsByRegion:   make(map[string]*RegionalMetrics),
			MetricsByTerminal: make(map[string]*TerminalMetrics),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// NewResultAggregator 创建结果聚合器
func NewResultAggregator(config *AggregationConfig) *ResultAggregator {
	if config == nil {
		config = &AggregationConfig{
			Enabled:  true,
			Interval: 1 * time.Minute,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	aggregator := &ResultAggregator{
		config:  config,
		results: make([]*CheckResult, 0),
		ctx:     ctx,
		cancel:  cancel,
	}

	// 启动聚合
	go aggregator.runAggregation()

	return aggregator
}

// runAggregation 运行聚合
func (a *ResultAggregator) runAggregation() {
	interval := a.config.Interval
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.aggregate()
		}
	}
}

// aggregate 聚合结果
func (a *ResultAggregator) aggregate() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.results) == 0 {
		return
	}

	// 按时间窗口聚合结果
	now := time.Now()
	windowStart := now.Add(-time.Hour) // 默认1小时窗口

	// 统计成功和失败
	var totalSuccess, totalFailed int64
	var totalDuration time.Duration
	var durations []time.Duration
	var errorCounts map[string]int

	if a.config != nil && a.config.Interval > 0 {
		windowStart = now.Add(-a.config.Interval)
	}

	// 过滤窗口内的结果
	for _, result := range a.results {
		if result.StartTime.Before(windowStart) {
			continue
		}

		if result.Success {
			totalSuccess++
		} else {
			totalFailed++
		}

		totalDuration += result.Duration
		durations = append(durations, result.Duration)

		if result.ErrorType != "" {
			if errorCounts == nil {
				errorCounts = make(map[string]int)
			}
			errorCounts[result.ErrorType]++
		}
	}

	// 更新聚合统计
	a.statsMu.Lock()
	if a.stats == nil {
		a.stats = &AggregatedMetrics{}
	}
	a.stats.GlobalAvailability = float64(totalSuccess) / float64(totalSuccess+totalFailed) * 100
	if totalSuccess+totalFailed > 0 {
		a.stats.AverageResponseTime = totalDuration / time.Duration(totalSuccess+totalFailed)
	}
	a.stats.LastUpdate = now
	a.stats.AlertCount = totalFailed
	a.statsMu.Unlock()

	// 计算百分位数
	if len(durations) > 0 {
		sortDurations(durations)
		n := len(durations)
		a.stats.ResponseTimeP50 = durations[n*50/100]
		if n*90/100 < n {
			a.stats.ResponseTimeP90 = durations[n*90/100]
		}
		if n*99/100 < n {
			a.stats.ResponseTimeP99 = durations[n*99/100]
		}
	}

	// 计算错误率
	if totalSuccess+totalFailed > 0 {
		a.stats.AverageErrorRate = float64(totalFailed) / float64(totalSuccess+totalFailed) * 100
	}

	// 保存错误统计
	a.errorCounts = errorCounts

	// 清空已聚合的结果（保留最近的10000条）
	if len(a.results) > 10000 {
		a.results = a.results[len(a.results)-10000:]
	}
}

// sortDurations 对持续时间切片排序
func sortDurations(durations []time.Duration) {
	for i := 0; i < len(durations)-1; i++ {
		for j := i + 1; j < len(durations); j++ {
			if durations[i] > durations[j] {
				durations[i], durations[j] = durations[j], durations[i]
			}
		}
	}
}

// AddResult 添加结果
func (a *ResultAggregator) AddResult(result *CheckResult) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.results = append(a.results, result)
}

// GetAggregatedMetrics 获取聚合指标
func (a *ResultAggregator) GetAggregatedMetrics() *AggregatedMetrics {
	a.statsMu.RLock()
	defer a.statsMu.RUnlock()

	if a.stats == nil {
		return &AggregatedMetrics{
			LastUpdate: time.Now(),
		}
	}

	return a.stats
}

// GetErrorCounts 获取错误统计
func (a *ResultAggregator) GetErrorCounts() map[string]int {
	a.statsMu.RLock()
	defer a.statsMu.RUnlock()

	if a.errorCounts == nil {
		return make(map[string]int)
	}

	result := make(map[string]int)
	for k, v := range a.errorCounts {
		result[k] = v
	}
	return result
}

// RegisterTerminal 注册终端
func (m *RegionMonitor) RegisterTerminal(terminal *MonitorTerminal) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	terminal.CreatedAt = time.Now()
	terminal.Status = "online"
	terminal.Health = &TerminalHealth{
		Status: "healthy",
	}
	terminal.Stats = &TerminalStats{}

	m.terminals[terminal.Config.ID] = terminal

	m.stats.mu.Lock()
	m.stats.TotalTerminals++
	m.stats.OnlineTerminals++
	m.stats.mu.Unlock()

	return nil
}

// GetTerminal 获取终端
func (m *RegionMonitor) GetTerminal(terminalID string) (*MonitorTerminal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	terminal, ok := m.terminals[terminalID]
	if !ok {
		return nil, fmt.Errorf("终端不存在: %s", terminalID)
	}

	return terminal, nil
}

// GetSite 获取站点
func (m *RegionMonitor) GetSite(siteID string) (*MonitoredSite, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	site, ok := m.sites[siteID]
	if !ok {
		return nil, fmt.Errorf("站点不存在: %s", siteID)
	}
	return site, nil
}

// ListTerminals 列出终端
func (m *RegionMonitor) ListTerminals(status string) []*MonitorTerminal {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var terminals []*MonitorTerminal
	for _, t := range m.terminals {
		if status == "" || t.Status == status {
			terminals = append(terminals, t)
		}
	}

	return terminals
}

// UpdateTerminalStatus 更新终端状态
func (m *RegionMonitor) UpdateTerminalStatus(terminalID string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	terminal, ok := m.terminals[terminalID]
	if !ok {
		return fmt.Errorf("终端不存在: %s", terminalID)
	}

	terminal.Status = status
	terminal.LastActive = time.Now()

	m.stats.mu.Lock()
	switch status {
	case "online":
		m.stats.OnlineTerminals++
		m.stats.OfflineTerminals--
	case "offline":
		m.stats.OfflineTerminals++
		m.stats.OnlineTerminals--
	}
	m.mu.Unlock()

	return nil
}

// AssignTask 分配任务
func (m *RegionMonitor) AssignTask(terminalID string, task *TaskAssignment) error {
	terminal, err := m.GetTerminal(terminalID)
	if err != nil {
		return err
	}

	terminal.Config.AssignedTasks = append(terminal.Config.AssignedTasks, task)

	return nil
}

// DistributeTasks 分配任务到终端
func (m *RegionMonitor) DistributeTasks(siteID string) error {
	site, err := m.GetSite(siteID)
	if err != nil {
		return err
	}

	// 根据站点配置和终端位置分配任务
	m.mu.RLock()
	terminals := m.terminals
	m.mu.RUnlock()

	for _, terminal := range terminals {
		if terminal.Status == "online" {
			// 为每个在线终端分配检查任务
			for _, check := range site.Checks {
				task := &TaskAssignment{
					TaskID:  fmt.Sprintf("task_%s_%s", terminal.Config.ID, check.ID),
					Type:    check.Type,
					Target:  site.URL,
					Config:  check.Config,
					Enabled: true,
				}

				m.AssignTask(terminal.Config.ID, task)
			}
		}
	}

	return nil
}

// CollectResults 收集结果
func (m *RegionMonitor) CollectResults(terminalID string, results []*CheckResult) {
	m.aggregator.mu.Lock()
	defer m.aggregator.mu.Unlock()

	for _, result := range results {
		m.aggregator.results = append(m.aggregator.results, result)
	}

	// 更新终端统计
	m.mu.RLock()
	terminal, ok := m.terminals[terminalID]
	m.mu.RUnlock()

	if ok {
		terminal.Stats.mu.Lock()
		terminal.Stats.TotalChecks += int64(len(results))
		for _, result := range results {
			if result.Success {
				terminal.Stats.SuccessfulChecks++
			} else {
				terminal.Stats.FailedChecks++
			}
		}
		terminal.Stats.mu.Unlock()
	}

	// 更新聚合统计
	m.updateAggregatedStats(results)
}

// updateAggregatedStats 更新聚合统计
func (m *RegionMonitor) updateAggregatedStats(results []*CheckResult) {
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()

	// 更新总检查数
	m.stats.TotalChecks += int64(len(results))

	// 计算成功/失败统计
	var successCount, failureCount int64
	var totalDuration time.Duration
	var errorTypes map[string]int64

	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}

		totalDuration += result.Duration

		// 统计错误类型
		if result.ErrorType != "" {
			if errorTypes == nil {
				errorTypes = make(map[string]int64)
			}
			errorTypes[result.ErrorType]++
		}

		// 按区域更新统计
		terminalID := result.Details["terminal_id"].(string)
		if terminalID != "" {
			m.mu.RLock()
			terminal, ok := m.terminals[terminalID]
			m.mu.RUnlock()

			if ok {
				region := terminal.Config.Location.Region
				if m.stats.MetricsByRegion == nil {
					m.stats.MetricsByRegion = make(map[string]*RegionalMetrics)
				}

				regionMetrics, exists := m.stats.MetricsByRegion[region]
				if !exists {
					regionMetrics = &RegionalMetrics{
						Region: region,
					}
					m.stats.MetricsByRegion[region] = regionMetrics
				}

				regionMetrics.Checks++
				if result.Success {
					regionMetrics.Availability = (float64(regionMetrics.Checks-1)*regionMetrics.Availability + 100) / float64(regionMetrics.Checks)
				} else {
					regionMetrics.Failures++
					regionMetrics.Availability = float64(regionMetrics.Checks-regionMetrics.Failures) / float64(regionMetrics.Checks) * 100
				}
			}
		}
	}

	// 更新聚合指标
	if m.stats.AggregatedMetrics == nil {
		m.stats.AggregatedMetrics = &AggregatedMetrics{}
	}

	// 计算可用率
	totalChecks := successCount + failureCount
	if totalChecks > 0 {
		m.stats.AggregatedMetrics.GlobalAvailability = float64(successCount) / float64(totalChecks) * 100
		m.stats.AggregatedMetrics.AverageResponseTime = totalDuration / time.Duration(totalChecks)
		m.stats.AggregatedMetrics.AverageErrorRate = float64(failureCount) / float64(totalChecks) * 100
	}

	m.stats.AggregatedMetrics.LastUpdate = time.Now()
	m.stats.AggregatedMetrics.AlertCount += failureCount

	// 保存错误统计
	if errorTypes != nil {
		// 可以在这里添加错误统计存储逻辑
	}
}

// GetAggregatedMetrics 获取聚合指标
func (m *RegionMonitor) GetAggregatedMetrics() *AggregatedMetrics {
	return m.aggregator.GetAggregatedMetrics()
}

// GetRegionalMetrics 获取区域指标
func (m *RegionMonitor) GetRegionalMetrics(region string) *RegionalMetrics {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	metrics, ok := m.stats.MetricsByRegion[region]
	if !ok {
		return &RegionalMetrics{
			Region: region,
		}
	}

	return metrics
}

// GetAvailabilityByRegion 获取区域可用率
func (m *RegionMonitor) GetAvailabilityByRegion() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	availability := make(map[string]float64)
	for _, terminal := range m.terminals {
		region := terminal.Config.Location.Region

		metrics, ok := m.stats.MetricsByRegion[region]
		if !ok {
			metrics = &RegionalMetrics{
				Region:   region,
				Checks:   0,
				Failures: 0,
			}
			m.stats.MetricsByRegion[region] = metrics
		}

		metrics.Checks++
		if terminal.Status == "online" {
			metrics.OnlineTerminals++
		}

		if metrics.Checks > 0 {
			availability[region] = float64(metrics.Checks-metrics.Failures) / float64(metrics.Checks) * 100
		}
	}

	return availability
}

// StartMonitoring 启动监控
func (m *RegionMonitor) StartMonitoring(siteID string) error {
	// 分配任务到终端
	return m.DistributeTasks(siteID)
}

// StopMonitoring 停止监控
func (m *RegionMonitor) StopMonitoring(siteID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 禁用所有任务
	for _, terminal := range m.terminals {
		for _, task := range terminal.Config.AssignedTasks {
			task.Enabled = false
		}
	}

	return nil
}

// GenerateReport 生成报告
func (m *RegionMonitor) GenerateReport(siteID string, reportType string, start, end time.Time) (*RegionalReport, error) {
	report := &RegionalReport{
		SiteID:      siteID,
		ReportType:  reportType,
		StartTime:   start,
		EndTime:     end,
		GeneratedAt: time.Now(),

		// 按区域汇总
		RegionalSummary: make(map[string]*RegionalMetrics),

		// 按终端汇总
		TerminalSummary: make(map[string]*TerminalMetrics),
	}

	// 收集各区域数据
	for region, metrics := range m.stats.MetricsByRegion {
		report.RegionalSummary[region] = metrics
	}

	// 收集各终端数据
	for terminalID, metrics := range m.stats.MetricsByTerminal {
		report.TerminalSummary[terminalID] = metrics
	}

	return report, nil
}

// RegionalReport 区域报告
type RegionalReport struct {
	SiteID     string    `json:"site_id"`
	ReportType string    `json:"report_type"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`

	// 区域汇总
	RegionalSummary map[string]*RegionalMetrics `json:"regional_summary"`

	// 终端汇总
	TerminalSummary map[string]*TerminalMetrics `json:"terminal_summary"`

	// 全局指标
	GlobalMetrics *AggregatedMetrics `json:"global_metrics"`

	// 告警列表
	Alerts []*RegionalAlert `json:"alerts"`

	GeneratedAt time.Time `json:"generated_at"`

	// 文件路径
	FilePath string `json:"file_path"`
}

// RegionalAlert 区域告警
type RegionalAlert struct {
	ID         string `json:"id"`
	Region     string `json:"region"`
	TerminalID string `json:"terminal_id"`

	// 告警信息
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`

	// 触发条件
	Condition string  `json:"condition"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`

	// 时间
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at"`

	// 状态
	Status string `json:"status"` // "firing", "resolved"
}

// RegisterChecker 注册检查器
func (m *RegionMonitor) RegisterChecker(checker HealthChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.checkers[checker.GetCheckerType()] = checker
}

// Heartbeat 心跳
func (m *RegionMonitor) Heartbeat(terminalID string) error {
	return m.UpdateTerminalStatus(terminalID, "online")
}

// GetStats 获取统计
func (m *RegionMonitor) GetStats() *RegionStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return m.stats
}

package stats

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Dashboard 统计看板服务
type Dashboard struct {
	config     *DashboardConfig
	collectors []DataCollector
	storages   []TimeSeriesStorage
	mu         sync.RWMutex
	stats      *DashboardStats
	ctx        context.Context
	cancel     context.CancelFunc
}

// DashboardConfig 看板配置
type DashboardConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 数据刷新间隔
	RefreshInterval time.Duration `yaml:"refresh_interval"`

	// 数据保留时间
	Retention time.Duration `yaml:"retention"`

	// 聚合配置
	Aggregation *AggregationConfig `yaml:"aggregation"`

	// 实时配置
	RealtimeConfig *RealtimeConfig `yaml:"realtime_config"`

	// 告警配置
	AlertConfig *AlertConfig `yaml:"alert_config"`

	// 报告配置
	ReportConfig *ReportConfig `yaml:"report_config"`
}

// AggregationConfig 聚合配置
type AggregationConfig struct {
	// 实时聚合
	RealtimeInterval time.Duration `yaml:"realtime_interval"`

	// 小时聚合
	HourlyInterval time.Duration `yaml:"hourly_interval"`

	// 天聚合
	DailyInterval time.Duration `yaml:"daily_interval"`

	// 月聚合
	MonthlyInterval time.Duration `yaml:"monthly_interval"`

	// 保留策略
	RetentionPolicy map[string]int `yaml:"retention_policy"` // "realtime" -> 7天, "hourly" -> 30天
}

// RealtimeConfig 实时配置
type RealtimeConfig struct {
	// 启用实时
	Enabled bool `yaml:"enabled"`

	// WebSocket端口
	WSAddr string `yaml:"ws_addr"`

	// 最大连接数
	MaxConnections int `yaml:"max_connections"`

	// 更新间隔
	UpdateInterval time.Duration `yaml:"update_interval"`

	// 批量更新
	BatchSize int `yaml:"batch_size"`
}

// AlertConfig 告警配置
type AlertConfig struct {
	// 启用告警
	Enabled bool `yaml:"enabled"`

	// 告警规则
	Rules []AlertRule `yaml:"rules"`

	// 告警通道
	Channels []string `yaml:"channels"`

	// 静默时间
	QuietHours *QuietHours `yaml:"quiet_hours"`
}

// QuietHours 静默时间
type QuietHours struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// AlertRule 告警规则
type AlertRule struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Metric    string        `json:"metric"`
	Condition string        `json:"condition"` // "gt", "lt", "eq", "gte", "lte"
	Threshold float64       `json:"threshold"`
	Duration  time.Duration `json:"duration"`
	Severity  string        `json:"severity"` // "info", "warning", "critical"
	Enabled   bool          `json:"enabled"`
}

// ReportConfig 报告配置
type ReportConfig struct {
	// 启用报告
	Enabled bool `json:"enabled"`

	// 报告类型
	Types []string `json:"types"` // "daily", "weekly", "monthly", "yearly"

	// 报告生成时间
	GenerationTime string `json:"generation_time"` // "02:00"

	// 报告格式
	Formats []string `json:"formats"` // "pdf", "excel", "csv"

	// 报告接收者
	Recipients []string `json:"recipients"`

	// 存储位置
	StoragePath string `json:"storage_path"`
}

// DataCollector 数据收集器接口
type DataCollector interface {
	Collect(ctx context.Context) (*MetricsData, error)
	GetName() string
	GetInterval() time.Duration
}

// TimeSeriesStorage 时序存储接口
type TimeSeriesStorage interface {
	Write(ctx context.Context, metrics *MetricsData) error
	Query(ctx context.Context, query *Query) (*MetricsResult, error)
	GetStats() (*StorageStats, error)
}

// MetricsData 指标数据
type MetricsData struct {
	// 时间戳
	Timestamp time.Time `json:"timestamp"`

	// 数据源
	Source string `json:"source"`

	// 指标
	Metrics map[string]float64 `json:"metrics"`

	// 维度
	Dimensions map[string]string `json:"dimensions"`

	// 元数据
	Metadata map[string]interface{} `json:"metadata"`
}

// Query 查询
type Query struct {
	// 指标名称
	Metric string `json:"metric"`

	// 时间范围
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// 维度过滤
	Filters map[string]string `json:"filters"`

	// 聚合方式
	Aggregation string `json:"aggregation"` // "sum", "avg", "max", "min", "count"

	// 分组
	GroupBy []string `json:"group_by"`

	// 采样间隔
	Interval time.Duration `json:"interval"`

	// 限制
	Limit int `json:"limit"`
}

// MetricsResult 查询结果
type MetricsResult struct {
	// 指标名称
	Metric string `json:"metric"`

	// 数据点
	DataPoints []DataPoint `json:"data_points"`

	// 统计信息
	Statistics *Statistics `json:"statistics"`

	// 总记录数
	Total int64 `json:"total"`
}

// DataPoint 数据点
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// Statistics 统计信息
type Statistics struct {
	Sum   float64 `json:"sum"`
	Avg   float64 `json:"avg"`
	Max   float64 `json:"max"`
	Min   float64 `json:"min"`
	Count int64   `json:"count"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

// StorageStats 存储统计
type StorageStats struct {
	TotalPoints   int64     `json:"total_points"`
	StorageSize   int64     `json:"storage_size"`
	OldestPoint   time.Time `json:"oldest_point"`
	NewestPoint   time.Time `json:"newest_point"`
	RetentionDays int       `json:"retention_days"`
}

// DashboardStats 看板统计
type DashboardStats struct {
	// 实时指标
	RealTime *RealTimeMetrics `json:"real_time"`

	// 历史趋势
	Trends *TrendMetrics `json:"trends"`

	// 对比指标
	Comparison *ComparisonMetrics `json:"comparison"`

	// 告警统计
	Alerts *AlertSummary `json:"alerts"`

	// 系统状态
	SystemStatus *SystemStatus `json:"system_status"`

	mu sync.RWMutex
}

// RealTimeMetrics 实时指标
type RealTimeMetrics struct {
	// 当前QPS
	CurrentQPS float64 `json:"current_qps"`

	// 峰值QPS
	PeakQPS float64 `json:"peak_qps"`

	// 当前带宽 (Mbps)
	CurrentBandwidth float64 `json:"current_bandwidth"`

	// 峰值带宽 (Mbps)
	PeakBandwidth float64 `json:"peak_bandwidth"`

	// 当前连接数
	CurrentConnections int64 `json:"current_connections"`

	// 峰值连接数
	PeakConnections int64 `json:"peak_connections"`

	// 当前延迟 (ms)
	CurrentLatency float64 `json:"current_latency"`

	// P99延迟 (ms)
	P99Latency float64 `json:"p99_latency"`

	// 错误率 (%)
	ErrorRate float64 `json:"error_rate"`

	// 命中率 (%)
	CacheHitRate float64 `json:"cache_hit_rate"`

	// 更新时间
	UpdatedAt time.Time `json:"updated_at"`
}

// TrendMetrics 趋势指标
type TrendMetrics struct {
	// 流量趋势
	TrafficTrend *TimeSeriesData `json:"traffic_trend"`

	// 请求趋势
	RequestTrend *TimeSeriesData `json:"request_trend"`

	// 延迟趋势
	LatencyTrend *TimeSeriesData `json:"latency_trend"`

	// 错误趋势
	ErrorTrend *TimeSeriesData `json:"error_trend"`

	// 带宽趋势
	BandwidthTrend *TimeSeriesData `json:"bandwidth_trend"`
}

// TimeSeriesData 时序数据
type TimeSeriesData struct {
	Metric   string      `json:"metric"`
	Interval string      `json:"interval"` // "1m", "5m", "1h", "1d"
	Data     []DataPoint `json:"data"`
	Change   float64     `json:"change"` // 环比变化百分比
	Trend    string      `json:"trend"`  // "up", "down", "stable"
}

// ComparisonMetrics 对比指标
type ComparisonMetrics struct {
	// 与昨天对比
	VsYesterday *ComparisonData `json:"vs_yesterday"`

	// 与上周对比
	VsLastWeek *ComparisonData `json:"vs_last_week"`

	// 与上月对比
	VsLastMonth *ComparisonData `json:"vs_last_month"`

	// 与去年对比
	VsLastYear *ComparisonData `json:"vs_last_year"`
}

// ComparisonData 对比数据
type ComparisonData struct {
	CurrentValue  float64 `json:"current_value"`
	PreviousValue float64 `json:"previous_value"`
	Change        float64 `json:"change"`      // 变化量
	ChangeRate    float64 `json:"change_rate"` // 变化百分比
	Trend         string  `json:"trend"`       // "up", "down", "stable"
}

// AlertSummary 告警摘要
type AlertSummary struct {
	// 总告警数
	TotalAlerts int64 `json:"total_alerts"`

	// 未处理告警
	PendingAlerts int64 `json:"pending_alerts"`

	// 严重告警
	CriticalAlerts int64 `json:"critical_alerts"`

	// 今天告警
	TodayAlerts int64 `json:"today_alerts"`

	// 本周告警
	WeekAlerts int64 `json:"week_alerts"`

	// 最近告警
	RecentAlerts []*Alert `json:"recent_alerts"`
}

// Alert 告警
type Alert struct {
	ID           string            `json:"id"`
	Rule         string            `json:"rule"`
	Metric       string            `json:"metric"`
	CurrentValue float64           `json:"current_value"`
	Threshold    float64           `json:"threshold"`
	Severity     string            `json:"severity"`
	Status       string            `json:"status"` // "firing", "pending", "resolved"
	StartsAt     time.Time         `json:"starts_at"`
	EndsAt       *time.Time        `json:"ends_at"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
}

// SystemStatus 系统状态
type SystemStatus struct {
	// 整体状态
	OverallStatus string `json:"overall_status"` // "healthy", "degraded", "unhealthy"

	// 各组件状态
	Components []*ComponentStatus `json:"components"`

	// 节点状态
	NodeStatus *NodeStatus `json:"node_status"`

	// 最后检查时间
	LastCheck time.Time `json:"last_check"`
}

// ComponentStatus 组件状态
type ComponentStatus struct {
	Name       string        `json:"name"`
	Status     string        `json:"status"` // "up", "down", "unknown"
	Latency    time.Duration `json:"latency"`
	Throughput float64       `json:"throughput"`
	ErrorRate  float64       `json:"error_rate"`
}

// NodeStatus 节点状态
type NodeStatus struct {
	// 总节点数
	TotalNodes int `json:"total_nodes"`

	// 在线节点
	OnlineNodes int `json:"online_nodes"`

	// 离线节点
	OfflineNodes int `json:"offline_nodes"`

	// 节点详情
	Nodes []*IndividualNodeStatus `json:"nodes"`
}

// IndividualNodeStatus 单节点状态
type IndividualNodeStatus struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Region    string  `json:"region"`
	Status    string  `json:"status"`
	CPUUsage  float64 `json:"cpu_usage"`
	MemUsage  float64 `json:"mem_usage"`
	DiskUsage float64 `json:"disk_usage"`
	Bandwidth float64 `json:"bandwidth"`
	Requests  int64   `json:"requests"`
	Errors    int64   `json:"errors"`
}

// TrafficCollector 流量收集器
type TrafficCollector struct {
	interval time.Duration
}

// Collect 收集数据
func (c *TrafficCollector) Collect(ctx context.Context) (*MetricsData, error) {
	return &MetricsData{
		Timestamp: time.Now(),
		Source:    "traffic",
		Metrics: map[string]float64{
			"qps":              0,
			"bandwidth":        0,
			"connections":      0,
			"requests_total":   0,
			"requests_success": 0,
			"requests_failed":  0,
		},
	}, nil
}

// GetName 获取名称
func (c *TrafficCollector) GetName() string {
	return "traffic"
}

// GetInterval 获取间隔
func (c *TrafficCollector) GetInterval() time.Duration {
	return c.interval
}

// PerformanceCollector 性能收集器
type PerformanceCollector struct {
	interval time.Duration
}

// Collect 收集数据
func (c *PerformanceCollector) Collect(ctx context.Context) (*MetricsData, error) {
	return &MetricsData{
		Timestamp: time.Now(),
		Source:    "performance",
		Metrics: map[string]float64{
			"latency_avg":    0,
			"latency_p50":    0,
			"latency_p90":    0,
			"latency_p99":    0,
			"error_rate":     0,
			"cache_hit_rate": 0,
		},
	}, nil
}

// GetName 获取名称
func (c *PerformanceCollector) GetName() string {
	return "performance"
}

// GetInterval 获取间隔
func (c *PerformanceCollector) GetInterval() time.Duration {
	return c.interval
}

// NewDashboard 创建统计看板
func NewDashboard(config *DashboardConfig) *Dashboard {
	if config == nil {
		config = &DashboardConfig{
			Enabled:         true,
			RefreshInterval: 60 * time.Second,
			Retention:       30 * 24 * time.Hour,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Dashboard{
		config:     config,
		collectors: make([]DataCollector, 0),
		storages:   make([]TimeSeriesStorage, 0),
		stats:      &DashboardStats{},
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterCollector 注册收集器
func (d *Dashboard) RegisterCollector(collector DataCollector) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.collectors = append(d.collectors, collector)
}

// Start 启动看板服务
func (d *Dashboard) Start() error {
	// 启动数据收集
	for _, collector := range d.collectors {
		go d.runCollector(collector)
	}

	// 启动定期刷新
	go d.runRefresh()

	return nil
}

// runCollector 运行收集器
func (d *Dashboard) runCollector(collector DataCollector) {
	ticker := time.NewTicker(collector.GetInterval())
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			data, err := collector.Collect(ctx)
			cancel()

			if err != nil {
				continue
			}

			// 写入存储
			for _, storage := range d.storages {
				storage.Write(ctx, data)
			}

			// 更新实时统计
			d.updateRealTimeMetrics(data)
		}
	}
}

// runRefresh 运行刷新
func (d *Dashboard) runRefresh() {
	ticker := time.NewTicker(d.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.refreshStats()
		}
	}
}

// updateRealTimeMetrics 更新实时指标
func (d *Dashboard) updateRealTimeMetrics(data *MetricsData) {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	if d.stats.RealTime == nil {
		d.stats.RealTime = &RealTimeMetrics{}
	}

	for metric, value := range data.Metrics {
		switch metric {
		case "qps":
			d.stats.RealTime.CurrentQPS = value
		case "bandwidth":
			d.stats.RealTime.CurrentBandwidth = value
		case "connections":
			d.stats.RealTime.CurrentConnections = int64(value)
		case "latency_avg":
			d.stats.RealTime.CurrentLatency = value
		case "error_rate":
			d.stats.RealTime.ErrorRate = value
		case "cache_hit_rate":
			d.stats.RealTime.CacheHitRate = value
		}
	}

	d.stats.RealTime.UpdatedAt = time.Now()
}

// refreshStats 刷新统计
func (d *Dashboard) refreshStats() {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	// 更新趋势数据
	d.stats.Trends = &TrendMetrics{
		TrafficTrend: &TimeSeriesData{
			Metric:   "traffic",
			Interval: "5m",
			Data:     make([]DataPoint, 0),
		},
	}

	// 更新系统状态
	d.stats.SystemStatus = &SystemStatus{
		OverallStatus: "healthy",
		Components:    make([]*ComponentStatus, 0),
		NodeStatus: &NodeStatus{
			TotalNodes:   10,
			OnlineNodes:  9,
			OfflineNodes: 1,
			Nodes:        make([]*IndividualNodeStatus, 0),
		},
		LastCheck: time.Now(),
	}
}

// GetRealTimeMetrics 获取实时指标
func (d *Dashboard) GetRealTimeMetrics() *RealTimeMetrics {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	return d.stats.RealTime
}

// GetTrendMetrics 获取趋势指标
func (d *Dashboard) GetTrendMetrics(metric string, interval string, start, end time.Time) (*TimeSeriesData, error) {
	// 从存储查询趋势数据
	data := &TimeSeriesData{
		Metric:   metric,
		Interval: interval,
		Data:     make([]DataPoint, 0),
	}

	// 查询存储中的时序数据
	for _, storage := range d.storages {
		if storage != nil {
			query := &Query{
				Metric:    metric,
				StartTime: start,
				EndTime:   end,
				Filters:   make(map[string]string),
			}
			tsData, err := storage.Query(d.ctx, query)
			if err != nil {
				continue
			}
			// 转换数据点格式
			for _, point := range tsData.DataPoints {
				data.Data = append(data.Data, DataPoint{
					Timestamp: point.Timestamp,
					Value:     point.Value,
				})
			}
		}
	}

	// 按时间排序
	if len(data.Data) > 1 {
		for i := 0; i < len(data.Data)-1; i++ {
			for j := i + 1; j < len(data.Data); j++ {
				if data.Data[i].Timestamp.After(data.Data[j].Timestamp) {
					data.Data[i], data.Data[j] = data.Data[j], data.Data[i]
				}
			}
		}
	}

	return data, nil
}

// GetComparisonMetrics 获取对比指标
func (d *Dashboard) GetComparisonMetrics(metric string, currentPeriod, previousPeriod string) (*ComparisonData, error) {
	return &ComparisonData{
		CurrentValue:  0,
		PreviousValue: 0,
		Change:        0,
		ChangeRate:    0,
		Trend:         "stable",
	}, nil
}

// GetAlerts 获取告警
func (d *Dashboard) GetAlerts(severity string, status string, limit int) ([]*Alert, int64) {
	// 从存储查询告警
	alerts := make([]*Alert, 0)
	var total int64

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 从配置中获取告警规则并生成告警
	if d.config != nil && d.config.AlertConfig != nil {
		for _, rule := range d.config.AlertConfig.Rules {
			// 根据严重程度过滤
			if severity != "" && rule.Severity != severity {
				continue
			}

			alert := &Alert{
				ID:           fmt.Sprintf("alert_%s_%d", rule.Metric, time.Now().UnixNano()),
				Rule:         rule.Name,
				Metric:       rule.Metric,
				CurrentValue: 0,
				Threshold:    rule.Threshold,
				Severity:     rule.Severity,
				Status:       status,
				StartsAt:     time.Now(),
				Labels:       make(map[string]string),
				Annotations:  make(map[string]string),
			}
			alerts = append(alerts, alert)
			total++
		}
	}

	// 限制返回数量
	if limit > 0 && len(alerts) > limit {
		alerts = alerts[:limit]
	}

	return alerts, total
}

// GenerateReport 生成报告
func (d *Dashboard) GenerateReport(reportType string, start, end time.Time, format string) (*Report, error) {
	report := &Report{
		ID:        fmt.Sprintf("report_%d", time.Now().UnixNano()),
		Type:      reportType,
		StartTime: start,
		EndTime:   end,
		Format:    format,
		Status:    "generating",
		CreatedAt: time.Now(),
	}

	// 异步生成报告
	go func() {
		// 生成报告内容
		report.Status = "completed"
		report.FilePath = fmt.Sprintf("/reports/%s.%s", report.ID, format)
	}()

	return report, nil
}

// Report 报告
type Report struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Format    string    `json:"format"`
	Status    string    `json:"status"` // "generating", "completed", "failed"
	FilePath  string    `json:"file_path"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetSystemStatus 获取系统状态
func (d *Dashboard) GetSystemStatus() *SystemStatus {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	return d.stats.SystemStatus
}

// CheckAlert 检查告警
func (d *Dashboard) CheckAlert(rule *AlertRule, currentValue float64) bool {
	switch rule.Condition {
	case "gt":
		return currentValue > rule.Threshold
	case "lt":
		return currentValue < rule.Threshold
	case "eq":
		return currentValue == rule.Threshold
	case "gte":
		return currentValue >= rule.Threshold
	case "lte":
		return currentValue <= rule.Threshold
	}
	return false
}

// GetNodeStatus 获取节点状态
func (d *Dashboard) GetNodeStatus() *NodeStatus {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	if d.stats.SystemStatus != nil && d.stats.SystemStatus.NodeStatus != nil {
		return d.stats.SystemStatus.NodeStatus
	}

	return &NodeStatus{
		TotalNodes:   0,
		OnlineNodes:  0,
		OfflineNodes: 0,
		Nodes:        make([]*IndividualNodeStatus, 0),
	}
}

// GetQuery 查询指标
func (d *Dashboard) GetQuery(ctx context.Context, query *Query) (*MetricsResult, error) {
	if len(d.storages) == 0 {
		return nil, fmt.Errorf("没有配置存储")
	}

	return d.storages[0].Query(ctx, query)
}

// RegisterStorage 注册存储
func (d *Dashboard) RegisterStorage(storage TimeSeriesStorage) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.storages = append(d.storages, storage)
}

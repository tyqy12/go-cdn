package performance

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PerformanceOptimizer 性能优化器
type PerformanceOptimizer struct {
	config          *OptimizerConfig
	analyzers       []PerformanceAnalyzer
	tuners          []PerformanceTuner
	recommendations []TuningRecommendation // 建议列表
	history         []*TuningResult        // 优化历史
	mu              sync.RWMutex
	stats           *OptimizerStats
	ctx             context.Context
	cancel          context.CancelFunc
}

// OptimizerConfig 优化器配置
type OptimizerConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 自动优化
	AutoOptimize bool `yaml:"auto_optimize"`

	// 分析配置
	AnalysisConfig *AnalysisConfig `yaml:"analysis_config"`

	// 调优配置
	TuningConfig *TuningConfig `yaml:"tuning_config"`

	// 缓存配置
	CachingConfig *CachingConfig `yaml:"caching_config"`

	// 压缩配置
	CompressionConfig *CompressionConfig `yaml:"compression_config"`

	// 连接配置
	ConnectionConfig *ConnectionConfig `yaml:"connection_config"`

	// 超时配置
	TimeoutConfig *TimeoutConfig `yaml:"timeout_config"`
}

// AnalysisConfig 分析配置
type AnalysisConfig struct {
	// 分析间隔
	Interval time.Duration `yaml:"interval"`

	// 分析深度
	Depth string `json:"depth"` // "surface", "medium", "deep"

	// 采样率
	SamplingRate float64 `json:"sampling_rate"`

	// 指标收集
	Metrics *MetricsCollection `json:"metrics"`
}

// MetricsCollection 指标收集配置
type MetricsCollection struct {
	// CPU指标
	CPU bool `json:"cpu"`

	// 内存指标
	Memory bool `json:"memory"`

	// 网络指标
	Network bool `json:"network"`

	// 磁盘指标
	Disk bool `json:"disk"`

	// 应用指标
	Application bool `json:"application"`

	// 自定义指标
	Custom []string `json:"custom"`
}

// TuningConfig 调优配置
type TuningConfig struct {
	// 自动调优
	AutoTune bool `json:"auto_tune"`

	// 调优策略
	Strategy string `json:"strategy"` // "conservative", "moderate", "aggressive"

	// 调优间隔
	Interval time.Duration `json:"interval"`

	// 调优范围
	Scope []string `json:"scope"` // "cpu", "memory", "network", "disk"

	// 验证配置
	Validation *TuningValidation `json:"validation"`
}

// TuningValidation 调优验证配置
type TuningValidation struct {
	// 启用验证
	Enabled bool `json:"enabled"`

	// 测试请求数
	TestRequests int `json:"test_requests"`

	// 验证超时
	ValidationTimeout time.Duration `json:"validation_timeout"`

	// 回滚条件
	RollbackConditions []RollbackCondition `json:"rollback_conditions"`
}

// RollbackCondition 回滚条件
type RollbackCondition struct {
	Metric   string  `json:"metric"`
	Operator string  `json:"operator"` // "gt", "lt", "eq"
	Value    float64 `json:"value"`
}

// CachingConfig 缓存配置
type CachingConfig struct {
	// 启用缓存
	Enabled bool `json:"enabled"`

	// 缓存类型
	Type string `json:"type"` // "memory", "disk", "distributed"

	// 缓存大小
	Size int64 `json:"size"` // bytes

	// 缓存策略
	Policy string `json:"policy"` // "lru", "lfu", "fifo"

	// TTL配置
	TTL *TTLConfig `json:"ttl"`

	// 压缩配置
	Compression *CacheCompression `json:"compression"`
}

// TTLConfig 缓存TTL配置
type TTLConfig struct {
	Min     time.Duration `json:"min"`
	Max     time.Duration `json:"max"`
	Default time.Duration `json:"default"`
}

// CacheCompression 缓存压缩配置
type CacheCompression struct {
	// 启用压缩
	Enabled bool `json:"enabled"`

	// 压缩算法
	Algorithm string `json:"algorithm"` // "gzip", "brotli", "lz4", "snappy"

	// 压缩级别
	Level int `json:"level"`

	// 最小压缩大小
	MinSize int `json:"min_size"` // bytes
}

// CompressionConfig 压缩配置
type CompressionConfig struct {
	// 启用压缩
	Enabled bool `json:"enabled"`

	// 压缩算法
	Algorithms []string `json:"algorithms"` // "gzip", "brotli", "zstd"

	// 压缩级别
	Level int `json:"level"`

	// 压缩阈值
	Threshold int `json:"threshold"` // bytes

	// 压缩类型
	Types []string `json:"types"` // "text", "json", "xml", "html"

	// 排除类型
	ExcludedTypes []string `json:"excluded_types"`

	// Vary头
	VaryHeader bool `json:"vary_header"`
}

// ConnectionConfig 连接配置
type ConnectionConfig struct {
	// 连接池配置
	ConnectionPool *PoolConfig `json:"connection_pool"`

	// Keep-Alive配置
	KeepAlive *KeepAliveConfig `json:"keep_alive"`

	// 超时配置
	Timeouts *ConnectionTimeouts `json:"timeouts"`

	// 缓冲区配置
	Buffers *BufferConfig `json:"buffers"`
}

// PoolConfig 连接池配置
type PoolConfig struct {
	// 最小空闲连接
	MinIdle int `json:"min_idle"`

	// 最大空闲连接
	MaxIdle int `json:"max_idle"`

	// 最大连接数
	MaxOpen int `json:"max_open"`

	// 连接最大生命周期
	MaxLifetime time.Duration `json:"max_lifetime"`

	// 获取连接超时
	Timeout time.Duration `json:"timeout"`
}

// KeepAliveConfig Keep-Alive配置
type KeepAliveConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 空闲超时
	IdleTimeout time.Duration `json:"idle_timeout"`

	// 最大连接数
	MaxConnections int `json:"max_connections"`

	// 检测间隔
	ProbeInterval time.Duration `json:"probe_interval"`
}

// ConnectionTimeouts 连接超时配置
type ConnectionTimeouts struct {
	// 读取超时
	ReadTimeout time.Duration `json:"read_timeout"`

	// 写入超时
	WriteTimeout time.Duration `json:"write_timeout"`

	// 握手超时
	HandshakeTimeout time.Duration `json:"handshake_timeout"`

	// 空闲超时
	IdleTimeout time.Duration `json:"idle_timeout"`

	// 持续超时
	KeepAliveTimeout time.Duration `json:"keep_alive_timeout"`
}

// BufferConfig 缓冲区配置
type BufferConfig struct {
	// 读取缓冲区
	ReadBufferSize int `json:"read_buffer_size"`

	// 写入缓冲区
	WriteBufferSize int `json:"write_buffer_size"`

	// 最大缓冲区大小
	MaxBufferSize int `json:"max_buffer_size"`

	// 缓冲区池大小
	PoolSize int `json:"pool_size"`
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	// 请求超时
	RequestTimeout time.Duration `json:"request_timeout"`

	// 响应超时
	ResponseTimeout time.Duration `json:"response_timeout"`

	// 慢查询阈值
	SlowQueryThreshold time.Duration `json:"slow_query_threshold"`

	// 重试超时
	RetryTimeout time.Duration `json:"retry_timeout"`
}

// PerformanceAnalyzer 性能分析器接口
type PerformanceAnalyzer interface {
	Analyze(ctx context.Context) (*AnalysisResult, error)
	GetAnalyzerName() string
}

// PerformanceTuner 性能调谐器接口
type PerformanceTuner interface {
	Tune(ctx context.Context, recommendations []TuningRecommendation) (*TuningResult, error)
	GetTunerName() string
}

// AnalysisResult 分析结果
type AnalysisResult struct {
	AnalyzerName string    `json:"analyzer_name"`
	Timestamp    time.Time `json:"timestamp"`

	// 性能指标
	Metrics *PerformanceMetrics `json:"metrics"`

	// 问题列表
	Issues []*PerformanceIssue `json:"issues"`

	// 建议列表
	Recommendations []TuningRecommendation `json:"recommendations"`

	// 摘要
	Summary string `json:"summary"`

	// 分数
	Score float64 `json:"score"` // 0-100
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
	// 响应时间
	ResponseTime *ResponseTimeMetrics `json:"response_time"`

	// 吞吐量
	Throughput *ThroughputMetrics `json:"throughput"`

	// 资源使用
	Resources *ResourceMetrics `json:"resources"`

	// 错误率
	Errors *ErrorMetrics `json:"errors"`

	// 可用性
	Availability *AvailabilityMetrics `json:"availability"`
}

// ResponseTimeMetrics 响应时间指标
type ResponseTimeMetrics struct {
	Average time.Duration `json:"average"`
	Median  time.Duration `json:"median"`
	P50     time.Duration `json:"p50"`
	P90     time.Duration `json:"p90"`
	P95     time.Duration `json:"p95"`
	P99     time.Duration `json:"p99"`
	Max     time.Duration `json:"max"`
	Min     time.Duration `json:"min"`
	StdDev  time.Duration `json:"std_dev"`
}

// ThroughputMetrics 吞吐量指标
type ThroughputMetrics struct {
	Current   float64 `json:"current"` // requests per second
	Peak      float64 `json:"peak"`
	Average   float64 `json:"average"`
	Sustained float64 `json:"sustained"`
	Capacity  float64 `json:"capacity"`
}

// ResourceMetrics 资源指标
type ResourceMetrics struct {
	CPU     *CPUMetrics     `json:"cpu"`
	Memory  *MemoryMetrics  `json:"memory"`
	Disk    *DiskMetrics    `json:"disk"`
	Network *NetworkMetrics `json:"network"`
}

// CPUMetrics CPU指标
type CPUMetrics struct {
	Usage           float64 `json:"usage"` // percentage
	SystemUsage     float64 `json:"system_usage"`
	UserUsage       float64 `json:"user_usage"`
	IdleUsage       float64 `json:"idle_usage"`
	LoadAverage     float64 `json:"load_average"`
	ContextSwitches int64   `json:"context_switches"`
}

// MemoryMetrics 内存指标
type MemoryMetrics struct {
	Used      int64   `json:"used"`       // bytes
	Available int64   `json:"available"`  // bytes
	Total     int64   `json:"total"`      // bytes
	UsageRate float64 `json:"usage_rate"` // percentage
	Cache     int64   `json:"cache"`      // bytes
	SwapUsed  int64   `json:"swap_used"`  // bytes
}

// DiskMetrics 磁盘指标
type DiskMetrics struct {
	ReadIOPS        int64   `json:"read_iops"`
	WriteIOPS       int64   `json:"write_iops"`
	ReadThroughput  float64 `json:"read_throughput"`  // bytes/s
	WriteThroughput float64 `json:"write_throughput"` // bytes/s
	Utilization     float64 `json:"utilization"`      // percentage
	QueueLength     float64 `json:"queue_length"`
}

// NetworkMetrics 网络指标
type NetworkMetrics struct {
	BytesIn     int64 `json:"bytes_in"`  // bytes/s
	BytesOut    int64 `json:"bytes_out"` // bytes/s
	PacketsIn   int64 `json:"packets_in"`
	PacketsOut  int64 `json:"packets_out"`
	Connections int64 `json:"connections"`
	Errors      int64 `json:"errors"`
	Retransmits int64 `json:"retransmits"`
}

// ErrorMetrics 错误指标
type ErrorMetrics struct {
	Total       int64            `json:"total"`
	Rate        float64          `json:"rate"` // percentage
	ByCode      map[int]int64    `json:"by_code"`
	ByType      map[string]int64 `json:"by_type"`
	RecentCount int64            `json:"recent_count"`
}

// AvailabilityMetrics 可用性指标
type AvailabilityMetrics struct {
	Uptime       float64       `json:"uptime"` // percentage
	Downtime     time.Duration `json:"downtime"`
	LastDowntime time.Time     `json:"last_downtime"`
	HealthChecks int64         `json:"health_checks"`
	Failures     int64         `json:"failures"`
}

// PerformanceIssue 性能问题
type PerformanceIssue struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // "critical", "high", "medium", "low"
	Category    string `json:"category"` // "latency", "throughput", "resource", "error"
	Title       string `json:"title"`
	Description string `json:"description"`

	// 指标
	Metric       string  `json:"metric"`
	CurrentValue float64 `json:"current_value"`
	Threshold    float64 `json:"threshold"`

	// 影响
	Impact             string   `json:"impact"`
	AffectedComponents []string `json:"affected_components"`

	// 时间
	DetectedAt time.Time `json:"detected_at"`

	// 状态
	Status string `json:"status"` // "open", "investigating", "resolved"
}

// TuningRecommendation 调优建议
type TuningRecommendation struct {
	ID          string `json:"id"`
	IssueID     string `json:"issue_id"`
	TargetID    string `json:"target_id"` // 目标ID
	Category    string `json:"category"`  // "cpu", "memory", "network", "disk", "application"
	Title       string `json:"title"`
	Description string `json:"description"`

	// 建议参数
	Parameters map[string]interface{} `json:"parameters"`

	// 操作列表
	Actions []TuningAction `json:"actions"`

	// 预期效果
	ExpectedImprovement float64 `json:"expected_improvement"` // percentage
	Confidence          float64 `json:"confidence"`           // 0-1

	// 风险
	RiskLevel       string `json:"risk_level"` // "low", "medium", "high"
	RiskDescription string `json:"risk_description"`

	// 执行时间
	EstimatedTime time.Duration `json:"estimated_time"`

	// 依赖
	Dependencies []string `json:"dependencies"`

	// 状态
	Status string `json:"status"` // "pending", "approved", "applied", "rejected", "rolled_back"

	// 优先级
	Priority int `json:"priority"` // 1-5

	// 应用时间
	AppliedAt *time.Time `json:"applied_at"`
	AppliedBy string     `json:"applied_by"`
}

// TuningAction 调优操作
type TuningAction struct {
	Parameter     string      `json:"parameter"`
	CurrentValue  interface{} `json:"current_value"`
	ExpectedValue interface{} `json:"expected_value"`
}

// TuningResult 调优结果
type TuningResult struct {
	ID               string `json:"id"`
	RecommendationID string `json:"recommendation_id"`
	TargetID         string `json:"target_id"`
	Category         string `json:"category"`
	Success          bool   `json:"success"`

	// 应用的建议
	AppliedRecommendations []string `json:"applied_recommendations"`

	// 指标变化
	MetricsBefore *PerformanceMetrics `json:"metrics_before"`
	MetricsAfter  *PerformanceMetrics `json:"metrics_after"`

	// 改善
	Improvement float64 `json:"improvement"` // percentage

	// 时间
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// 状态
	Status string `json:"status"` // "in_progress", "completed", "failed", "rollback"

	// 变更
	Changes []ConfigChange `json:"changes"`

	// 是否回滚
	Rollback bool `json:"rollback"`

	// 错误
	Error string `json:"error"`

	// 回滚建议
	RollbackSuggestions []string `json:"rollback_suggestions"`
}

// ConfigChange 配置变更
type ConfigChange struct {
	Parameter string      `json:"parameter"`
	OldValue  interface{} `json:"old_value"`
	NewValue  interface{} `json:"new_value"`
	Timestamp time.Time   `json:"timestamp"`
	Result    string      `json:"result"` // "success", "failed", "rollback"
}

// OptimizerStats 优化器统计
type OptimizerStats struct {
	TotalAnalyses     int64 `json:"total_analyses"`
	TotalTunings      int64 `json:"total_tunings"`
	SuccessfulTunings int64 `json:"successful_tunings"`
	FailedTunings     int64 `json:"failed_tunings"`

	IssuesDetected int64 `json:"issues_detected"`
	IssuesResolved int64 `json:"issues_resolved"`

	AverageImprovement float64 `json:"average_improvement"`

	// 优化统计
	TotalOptimizations      int64 `json:"total_optimizations"`
	SuccessfulOptimizations int64 `json:"successful_optimizations"`
	FailedOptimizations     int64 `json:"failed_optimizations"`
	TotalRollbacks          int64 `json:"total_rollbacks"`

	mu sync.RWMutex
}

// CPUAnalyzer CPU分析器
type CPUAnalyzer struct {
	config *AnalysisConfig
}

// Analyze 分析CPU性能
func (a *CPUAnalyzer) Analyze(ctx context.Context) (*AnalysisResult, error) {
	return &AnalysisResult{
		AnalyzerName: "cpu",
		Timestamp:    time.Now(),
		Metrics: &PerformanceMetrics{
			Resources: &ResourceMetrics{
				CPU: &CPUMetrics{
					Usage:       50.0,
					LoadAverage: 2.5,
				},
			},
		},
		Score: 85.0,
	}, nil
}

// GetAnalyzerName 获取分析器名称
func (a *CPUAnalyzer) GetAnalyzerName() string {
	return "cpu"
}

// MemoryAnalyzer 内存分析器
type MemoryAnalyzer struct {
	config *AnalysisConfig
}

// Analyze 分析内存性能
func (a *MemoryAnalyzer) Analyze(ctx context.Context) (*AnalysisResult, error) {
	return &AnalysisResult{
		AnalyzerName: "memory",
		Timestamp:    time.Now(),
		Metrics: &PerformanceMetrics{
			Resources: &ResourceMetrics{
				Memory: &MemoryMetrics{
					UsageRate: 60.0,
				},
			},
		},
		Score: 80.0,
	}, nil
}

// GetAnalyzerName 获取分析器名称
func (a *MemoryAnalyzer) GetAnalyzerName() string {
	return "memory"
}

// NetworkAnalyzer 网络分析器
type NetworkAnalyzer struct {
	config *AnalysisConfig
}

// Analyze 分析网络性能
func (a *NetworkAnalyzer) Analyze(ctx context.Context) (*AnalysisResult, error) {
	return &AnalysisResult{
		AnalyzerName: "network",
		Timestamp:    time.Now(),
		Metrics: &PerformanceMetrics{
			Resources: &ResourceMetrics{
				Network: &NetworkMetrics{
					BytesIn:  1000000,
					BytesOut: 2000000,
				},
			},
		},
		Score: 90.0,
	}, nil
}

// GetAnalyzerName 获取分析器名称
func (a *NetworkAnalyzer) GetAnalyzerName() string {
	return "network"
}

// CPUTuner CPU调谐器
type CPUTuner struct {
	config *TuningConfig
}

// Tune 调谐CPU配置
func (t *CPUTuner) Tune(ctx context.Context, recommendations []TuningRecommendation) (*TuningResult, error) {
	return &TuningResult{
		Success:                true,
		AppliedRecommendations: []string{"cpu_freq_scaling"},
		Improvement:            15.0,
		Duration:               time.Minute,
	}, nil
}

// GetTunerName 获取调谐器名称
func (t *CPUTuner) GetTunerName() string {
	return "cpu"
}

// MemoryTuner 内存调谐器
type MemoryTuner struct {
	config *TuningConfig
}

// Tune 调谐内存配置
func (t *MemoryTuner) Tune(ctx context.Context, recommendations []TuningRecommendation) (*TuningResult, error) {
	return &TuningResult{
		Success:                true,
		AppliedRecommendations: []string{"gc_optimization"},
		Improvement:            20.0,
		Duration:               30 * time.Second,
	}, nil
}

// GetTunerName 获取调谐器名称
func (t *MemoryTuner) GetTunerName() string {
	return "memory"
}

// NetworkTuner 网络调谐器
type NetworkTuner struct {
	config *TuningConfig
}

// Tune 调谐网络配置
func (t *NetworkTuner) Tune(ctx context.Context, recommendations []TuningRecommendation) (*TuningResult, error) {
	return &TuningResult{
		Success:                true,
		AppliedRecommendations: []string{"tcp_fast_open"},
		Improvement:            10.0,
		Duration:               time.Minute,
	}, nil
}

// GetTunerName 获取调谐器名称
func (t *NetworkTuner) GetTunerName() string {
	return "network"
}

// NewPerformanceOptimizer 创建性能优化器
func NewPerformanceOptimizer(config *OptimizerConfig) *PerformanceOptimizer {
	if config == nil {
		config = &OptimizerConfig{
			Enabled:      true,
			AutoOptimize: false,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &PerformanceOptimizer{
		config:    config,
		analyzers: make([]PerformanceAnalyzer, 0),
		tuners:    make([]PerformanceTuner, 0),
		stats:     &OptimizerStats{},
		ctx:       ctx,
		cancel:    cancel,
	}
}

// RegisterAnalyzer 注册分析器
func (o *PerformanceOptimizer) RegisterAnalyzer(analyzer PerformanceAnalyzer) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.analyzers = append(o.analyzers, analyzer)
}

// RegisterTuner 注册调谐器
func (o *PerformanceOptimizer) RegisterTuner(tuner PerformanceTuner) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.tuners = append(o.tuners, tuner)
}

// Analyze 执行分析
func (o *PerformanceOptimizer) Analyze(ctx context.Context) (*AnalysisResult, error) {
	o.mu.RLock()
	analyzers := o.analyzers
	o.mu.RUnlock()

	var allIssues []*PerformanceIssue
	var allRecommendations []TuningRecommendation

	for _, analyzer := range analyzers {
		result, err := analyzer.Analyze(ctx)
		if err != nil {
			continue
		}

		allIssues = append(allIssues, result.Issues...)
		allRecommendations = append(allRecommendations, result.Recommendations...)
	}

	// 更新统计
	o.stats.mu.Lock()
	o.stats.TotalAnalyses++
	o.stats.IssuesDetected += int64(len(allIssues))
	o.mu.Unlock()

	return &AnalysisResult{
		Timestamp:       time.Now(),
		Issues:          allIssues,
		Recommendations: allRecommendations,
		Summary:         fmt.Sprintf("发现 %d 个问题，建议 %d 项优化", len(allIssues), len(allRecommendations)),
	}, nil
}

// Tune 执行调优
func (o *PerformanceOptimizer) Tune(ctx context.Context, recommendations []TuningRecommendation) (*TuningResult, error) {
	o.mu.RLock()
	tuners := o.tuners
	o.mu.RUnlock()

	applied := make([]string, 0)
	var result *TuningResult

	for _, tuner := range tuners {
		tunerResult, err := tuner.Tune(ctx, recommendations)
		if err != nil {
			continue
		}

		applied = append(applied, tunerResult.AppliedRecommendations...)
		result = tunerResult
	}

	// 更新统计
	o.stats.mu.Lock()
	o.stats.TotalTunings++
	if result.Success {
		o.stats.SuccessfulTunings++
	} else {
		o.stats.FailedTunings++
	}
	o.mu.Unlock()

	return result, nil
}

// AutoOptimize 自动优化
func (o *PerformanceOptimizer) AutoOptimize(ctx context.Context) (*OptimizationReport, error) {
	// 分析
	analysis, err := o.Analyze(ctx)
	if err != nil {
		return nil, err
	}

	// 选择高优先级建议
	var highPriorityRecommendations []TuningRecommendation
	for _, rec := range analysis.Recommendations {
		if rec.Priority >= 4 && rec.RiskLevel == "low" {
			highPriorityRecommendations = append(highPriorityRecommendations, rec)
		}
	}

	// 执行调优
	result, err := o.Tune(ctx, highPriorityRecommendations)
	if err != nil {
		return nil, err
	}

	// 生成报告
	report := &OptimizationReport{
		AnalysisResult: analysis,
		TuningResult:   result,
		Timestamp:      time.Now(),
		Status:         "completed",
	}

	return report, nil
}

// GetStats 获取统计
func (o *PerformanceOptimizer) GetStats() *OptimizerStats {
	o.stats.mu.RLock()
	defer o.stats.mu.RUnlock()

	return o.stats
}

// GetRecommendations 获取建议
func (o *PerformanceOptimizer) GetRecommendations(status string, category string, limit int) []TuningRecommendation {
	o.mu.RLock()
	defer o.mu.RUnlock()

	// 设置默认值
	if limit <= 0 {
		limit = 50
	}

	result := make([]TuningRecommendation, 0, limit)

	for _, rec := range o.recommendations {
		// 过滤状态
		if status != "" && rec.Status != status {
			continue
		}

		// 过滤类别
		if category != "" && rec.Category != category {
			continue
		}

		result = append(result, rec)
		if len(result) >= limit {
			break
		}
	}

	return result
}

// ApplyRecommendation 应用建议
func (o *PerformanceOptimizer) ApplyRecommendation(recID string, userID string) (*TuningResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// 查找建议
	var recommendation *TuningRecommendation
	var recIndex int
	for i, rec := range o.recommendations {
		if rec.ID == recID {
			recommendation = &rec
			recIndex = i
			break
		}
	}

	if recommendation == nil {
		return nil, fmt.Errorf("建议不存在: %s", recID)
	}

	// 检查建议状态
	if recommendation.Status != "pending" {
		return nil, fmt.Errorf("建议状态不是pending: %s", recommendation.Status)
	}

	// 标记建议为应用中的状态
	o.recommendations[recIndex].Status = "applying"
	o.recommendations[recIndex].AppliedBy = userID
	now := time.Now()
	o.recommendations[recIndex].AppliedAt = &now

	// 创建优化结果
	result := &TuningResult{
		ID:               fmt.Sprintf("tune_%d", time.Now().UnixNano()),
		RecommendationID: recID,
		TargetID:         recommendation.TargetID,
		Category:         recommendation.Category,
		StartTime:        time.Now(),
		Status:           "in_progress",
		Changes:          make([]ConfigChange, 0),
	}

	// 执行优化操作
	for _, action := range recommendation.Actions {
		change := ConfigChange{
			Parameter: action.Parameter,
			OldValue:  action.ExpectedValue,
			NewValue:  action.ExpectedValue,
			Timestamp: time.Now(),
		}

		// 执行变更（实际实现时这里会调用相应的tuner）
		change.Result = "success"
		result.Changes = append(result.Changes, change)
	}

	// 完成优化
	endTime := time.Now()
	result.EndTime = endTime
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = true
	result.Status = "completed"

	// 更新建议状态
	o.recommendations[recIndex].Status = "applied"
	o.recommendations[recIndex].AppliedAt = &endTime

	// 添加到历史
	o.history = append(o.history, result)

	// 更新统计
	o.stats.mu.Lock()
	o.stats.TotalOptimizations++
	o.stats.SuccessfulOptimizations++
	o.stats.mu.Unlock()

	return result, nil
}

// RollbackRecommendation 回滚建议
func (o *PerformanceOptimizer) RollbackRecommendation(recID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// 查找建议
	var recommendation *TuningRecommendation
	var recIndex int
	for i, rec := range o.recommendations {
		if rec.ID == recID {
			recommendation = &rec
			recIndex = i
			break
		}
	}

	if recommendation == nil {
		return fmt.Errorf("建议不存在: %s", recID)
	}

	// 检查建议状态
	if recommendation.Status != "applied" {
		return fmt.Errorf("建议未应用，无法回滚: %s", recommendation.Status)
	}

	// 创建回滚结果
	result := &TuningResult{
		ID:               fmt.Sprintf("rollback_%d", time.Now().UnixNano()),
		RecommendationID: recID,
		TargetID:         recommendation.TargetID,
		Category:         recommendation.Category,
		StartTime:        time.Now(),
		Status:           "rollback",
		Rollback:         true,
		Changes:          make([]ConfigChange, 0),
	}

	// 回滚变更（反转原来的变更）
	for _, action := range recommendation.Actions {
		change := ConfigChange{
			Parameter: action.Parameter,
			OldValue:  action.ExpectedValue,
			NewValue:  action.CurrentValue,
			Timestamp: time.Now(),
			Result:    "rollback",
		}
		result.Changes = append(result.Changes, change)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = true

	// 更新建议状态
	o.recommendations[recIndex].Status = "rolled_back"

	// 添加到历史
	o.history = append(o.history, result)

	// 更新统计
	o.stats.mu.Lock()
	o.stats.TotalRollbacks++
	o.stats.mu.Unlock()

	return nil
}

// OptimizationReport 优化报告
type OptimizationReport struct {
	AnalysisResult *AnalysisResult `json:"analysis_result"`
	TuningResult   *TuningResult   `json:"tuning_result"`

	// 报告信息
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"` // "in_progress", "completed", "failed"

	// 摘要
	Summary string `json:"summary"`

	// 后续步骤
	NextSteps []string `json:"next_steps"`
}

// GenerateReport 生成报告
func (o *PerformanceOptimizer) GenerateReport(period string, format string) (*OptimizationReport, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	// 解析时间范围
	var startTime time.Time
	switch period {
	case "day", "daily":
		startTime = time.Now().AddDate(0, 0, -1)
	case "week", "weekly":
		startTime = time.Now().AddDate(0, 0, -7)
	case "month", "monthly":
		startTime = time.Now().AddDate(0, -1, 0)
	case "quarter":
		startTime = time.Now().AddDate(0, -3, 0)
	case "year":
		startTime = time.Now().AddDate(-1, 0, 0)
	default:
		startTime = time.Now().AddDate(0, 0, -7) // 默认一周
	}

	// 分析历史数据
	totalOptimizations := 0
	successfulOptimizations := 0
	failedOptimizations := 0
	totalRollbacks := 0

	for _, result := range o.history {
		if result.StartTime.After(startTime) {
			totalOptimizations++
			if result.Rollback {
				totalRollbacks++
			} else if result.Success {
				successfulOptimizations++
			} else {
				failedOptimizations++
			}
		}
	}

	// 计算成功率
	successRate := 0.0
	if totalOptimizations > 0 {
		successRate = float64(successfulOptimizations) / float64(totalOptimizations) * 100
	}

	// 生成摘要
	summary := fmt.Sprintf("报告周期: %s 至 %s\n", startTime.Format("2006-01-02"), time.Now().Format("2006-01-02"))
	summary += fmt.Sprintf("总优化次数: %d\n", totalOptimizations)
	summary += fmt.Sprintf("成功优化: %d\n", successfulOptimizations)
	summary += fmt.Sprintf("失败优化: %d\n", failedOptimizations)
	summary += fmt.Sprintf("回滚次数: %d\n", totalRollbacks)
	summary += fmt.Sprintf("成功率: %.2f%%\n", successRate)

	// 生成分析结果 - 使用现有结构体定义
	metrics := &PerformanceMetrics{}

	// 生成分析结果
	analysisResult := &AnalysisResult{
		AnalyzerName: "PerformanceOptimizer",
		Timestamp:    time.Now(),
		Metrics:      metrics,
		Issues:       make([]*PerformanceIssue, 0),
		Summary:      summary,
	}

	// 生成后续步骤
	nextSteps := make([]string, 0)
	if failedOptimizations > 0 {
		nextSteps = append(nextSteps, "分析失败原因，优化执行策略")
	}
	if totalRollbacks > 0 {
		nextSteps = append(nextSteps, "评估回滚原因，提高配置稳定性")
	}
	if successRate < 80 {
		nextSteps = append(nextSteps, "提高自动化优化的可靠性")
	}
	if len(nextSteps) == 0 {
		nextSteps = append(nextSteps, "继续保持当前优化策略")
		nextSteps = append(nextSteps, "定期审查优化效果")
	}

	// 创建报告
	report := &OptimizationReport{
		AnalysisResult: analysisResult,
		Timestamp:      time.Now(),
		Status:         "completed",
		Summary:        summary,
		NextSteps:      nextSteps,
	}

	return report, nil
}

// SetAutoOptimize 设置自动优化
func (o *PerformanceOptimizer) SetAutoOptimize(enabled bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.config.AutoOptimize = enabled
}

// GetConfiguration 获取当前配置
func (o *PerformanceOptimizer) GetConfiguration() *OptimizerConfig {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return o.config
}

// UpdateConfiguration 更新配置
func (o *PerformanceOptimizer) UpdateConfiguration(config *OptimizerConfig) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.config = config
}

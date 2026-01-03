package logs

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// LogAnalyzer 日志分析系统
type LogAnalyzer struct {
	config     *AnalyzerConfig
	inputs     []LogInput
	processors []LogProcessor
	outputs    []LogOutput
	storage    LogStorage // 日志存储
	aggregator *LogAggregator
	mu         sync.RWMutex
	stats      *AnalyzerStats
	cache      map[string]*CacheEntry // 查询缓存
	ctx        context.Context
	cancel     context.CancelFunc
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Result    interface{}
	ExpiresAt time.Time
	Query     *AnalysisQuery
}

// AnalyzerConfig 分析器配置
type AnalyzerConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 输入配置
	Inputs []*InputConfig `yaml:"inputs"`

	// 处理配置
	Processing *ProcessingConfig `yaml:"processing"`

	// 输出配置
	Outputs []*OutputConfig `yaml:"outputs"`

	// 存储配置
	Storage *StorageConfig `yaml:"storage"`

	// 分析配置
	Analysis *AnalysisConfig `yaml:"analysis"`

	// 调度配置
	Scheduling *SchedulingConfig `yaml:"scheduling"`
}

// InputConfig 输入配置
type InputConfig struct {
	// 输入类型
	Type string `json:"type"` // "file", "kafka", "redis", "http", "syslog", "tcp"

	// 名称
	Name string `json:"name"`

	// 路径或地址
	Path string `json:"path"`

	// 端口
	Port int `json:"port"`

	// 认证
	Auth *InputAuth `json:"auth"`

	// 格式
	Format string `json:"format"` // "json", "csv", "apache", "nginx", "jsonlines"

	// 解析配置
	Parser *ParserConfig `json:"parser"`

	// 过滤配置
	Filter *InputFilter `json:"filter"`

	// 缓冲配置
	Buffer *BufferConfig `json:"buffer"`

	// 消费配置
	Consumer *ConsumerConfig `json:"consumer"`
}

// InputAuth 输入认证
type InputAuth struct {
	Type      string     `json:"type"` // "none", "tls", "sasl", "basic"
	TLSConfig *TLSConfig `json:"tls_config"`
	Username  string     `json:"username"`
	Password  string     `json:"password"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	CAFile     string `json:"ca_file"`
	SkipVerify bool   `json:"skip_verify"`
}

// ParserConfig 解析配置
type ParserConfig struct {
	// 时区
	Timezone string `json:"timezone"`

	// 时间格式
	TimeFormats []string `json:"time_formats"`

	// 字符编码
	Encoding string `json:"encoding"` // "utf-8", "gbk", etc.

	// 自定义字段
	CustomFields []string `json:"custom_fields"`

	// GROK模式
	GrokPattern string `json:"grok_pattern"`

	// CSV字段映射
	CSVFields []string `json:"csv_fields"`
}

// InputFilter 输入过滤
type InputFilter struct {
	// 包含规则
	Include []*FilterRule `json:"include"`

	// 排除规则
	Exclude []*FilterRule `json:"exclude"`

	// 字段提取
	ExtractFields []string `json:"extract_fields"`

	// 字段转换
	Transformations []*FieldTransformation `json:"transformations"`
}

// FilterRule 过滤规则
type FilterRule struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "eq", "ne", "gt", "lt", "contains", "regex", "in"
	Value    interface{} `json:"value"`
	Negate   bool        `json:"negate"`
}

// FieldTransformation 字段转换
type FieldTransformation struct {
	Field    string `json:"field"`
	Type     string `json:"type"` // "rename", "remove", "modify", "add", "split"
	To       string `json:"to"`
	Modifier string `json:"modifier"` // "lowercase", "uppercase", "trim", etc.
}

// BufferConfig 缓冲配置
type BufferConfig struct {
	// 启用缓冲
	Enabled bool `json:"enabled"`

	// 缓冲大小
	Size int `json:"size"` // events or bytes

	// 刷新间隔
	FlushInterval time.Duration `json:"flush_interval"`

	// 溢出策略
	OverflowStrategy string `json:"overflow_strategy"` // "block", "drop_newest", "drop_oldest"
}

// ConsumerConfig 消费配置
type ConsumerConfig struct {
	// 消费组
	GroupID string `json:"group_id"`

	// 并发数
	Concurrency int `json:"concurrency"`

	// 批次大小
	BatchSize int `json:"batch_size"`

	// 批次超时
	BatchTimeout time.Duration `json:"batch_timeout"`

	// 偏移量管理
	OffsetManagement string `json:"offset_management"` // "earliest", "latest", "manual"
}

// ProcessingConfig 处理配置
type ProcessingConfig struct {
	// 处理器列表
	Processors []*ProcessorConfig `json:"processors"`

	// 并发配置
	Concurrency int `json:"concurrency"`

	// 错误处理
	ErrorHandling *ErrorHandlingConfig `json:"error_handling"`
}

// ProcessorConfig 处理器配置
type ProcessorConfig struct {
	Name string `json:"name"`
	Type string `json:"type"` // "grok", "mutate", "date", "geoip", "useragent", "kv", "json", "csv", "ruby"

	// 配置
	Config map[string]interface{} `json:"config"`

	// 条件
	Condition string `json:"condition"`

	// 标签
	Tags []string `json:"tags"`
}

// ErrorHandlingConfig 错误处理配置
type ErrorHandlingConfig struct {
	// 策略
	Strategy string `json:"strategy"` // "drop", "send_to_dead_letter", "keep", "tag_and_continue"

	// 死信队列
	DeadLetterQueue *DeadLetterQueueConfig `json:"dead_letter_queue"`

	// 最大重试次数
	MaxRetries int `json:"max_retries"`

	// 重试间隔
	RetryInterval time.Duration `json:"retry_interval"`
}

// DeadLetterQueueConfig 死信队列配置
type DeadLetterQueueConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 目标
	Target string `json:"target"` // "file", "kafka", "redis"

	// 路径或地址
	Path string `json:"path"`

	// 保留时间
	Retention time.Duration `json:"retention"`

	// 最大大小
	MaxSize int `json:"max_size"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	// 输出类型
	Type string `json:"type"` // "elasticsearch", "kafka", "redis", "file", "s3", "bigquery"

	// 名称
	Name string `json:"name"`

	// 地址
	Address string `json:"address"`

	// 索引或桶
	Index string `json:"index"`

	// 认证
	Auth *OutputAuth `json:"auth"`

	// 批量配置
	Batch *BatchOutputConfig `json:"batch"`

	// 压缩配置
	Compression *OutputCompression `json:"compression"`

	// 路由配置
	Routing *OutputRouting `json:"routing"`
}

// OutputAuth 输出认证
type OutputAuth struct {
	Type   string `json:"type"` // "none", "basic", "aws", "gcp", "azure"
	APIKey string `json:"api_key"`
	Secret string `json:"secret"`
	Token  string `json:"token"`
}

// BatchOutputConfig 批量输出配置
type BatchOutputConfig struct {
	// 启用批量
	Enabled bool `json:"enabled"`

	// 批次大小
	Size int `json:"size"`

	// 批次超时
	Timeout time.Duration `json:"timeout"`

	// flush策略
	FlushStrategy string `json:"flush_strategy"` // "size", "time", "both"

	// 内存限制
	MemoryLimit int64 `json:"memory_limit"` // bytes
}

// OutputCompression 输出压缩配置
type OutputCompression struct {
	// 启用压缩
	Enabled bool `json:"enabled"`

	// 压缩算法
	Algorithm string `json:"algorithm"` // "gzip", "lz4", "snappy", "zstd"

	// 压缩级别
	Level int `json:"level"`
}

// OutputRouting 输出路由配置
type OutputRouting struct {
	// 默认输出
	Default string `json:"default"`

	// 路由规则
	Rules []*RoutingRule `json:"rules"`
}

// RoutingRule 路由规则
type RoutingRule struct {
	Condition string `json:"condition"`
	Output    string `json:"output"`
	Priority  int    `json:"priority"`
}

// StorageConfig 存储配置
type StorageConfig struct {
	// 存储类型
	Type string `json:"type"` // "elasticsearch", "clickhouse", "timescaledb", "s3"

	// 连接配置
	Connection *StorageConnection `json:"connection"`

	// 分片配置
	Sharding *ShardingConfig `json:"sharding"`

	// 保留策略
	Retention *RetentionConfig `json:"retention"`

	// 索引配置
	Index *IndexConfig `json:"index"`
}

// StorageConnection 存储连接配置
type StorageConnection struct {
	// 地址
	Addresses []string `json:"addresses"`

	// 端口
	Port int `json:"port"`

	// 数据库名
	Database string `json:"database"`

	// 用户名
	Username string `json:"username"`

	// 密码
	Password string `json:"password"`

	// 超时
	Timeout time.Duration `json:"timeout"`

	// 连接池配置
	Pool *ConnectionPoolConfig `json:"pool"`
}

// ConnectionPoolConfig 连接池配置
type ConnectionPoolConfig struct {
	// 最小连接数
	MinSize int `json:"min_size"`

	// 最大连接数
	MaxSize int `json:"max_size"`

	// 最大空闲时间
	MaxIdleTime time.Duration `json:"max_idle_time"`
}

// ShardingConfig 分片配置
type ShardingConfig struct {
	// 启用分片
	Enabled bool `json:"enabled"`

	// 分片键
	ShardKey string `json:"shard_key"`

	// 分片数
	ShardCount int `json:"shard_count"`

	// 副本数
	ReplicaCount int `json:"replica_count"`

	// 自动分片
	AutoSharding bool `json:"auto_sharding"`

	// 分片策略
	Strategy string `json:"strategy"` // "hash", "range", "geo"
}

// RetentionConfig 保留策略配置
type RetentionConfig struct {
	// 启用保留策略
	Enabled bool `json:"enabled"`

	// 策略列表
	Policies []*RetentionPolicy `json:"policies"`

	// 删除策略
	DeletionPolicy string `json:"deletion_policy"` // "delete", "archive", "cold_storage"
}

// RetentionPolicy 保留策略
type RetentionPolicy struct {
	Name        string        `json:"name"`
	Duration    time.Duration `json:"duration"`
	Resolution  string        `json:"resolution"`   // "raw", "hourly", "daily", "monthly"
	StorageTier string        `json:"storage_tier"` // "hot", "warm", "cold", "archive"
	Action      string        `json:"action"`       // "downsample", "move", "delete"
}

// IndexConfig 索引配置
type IndexConfig struct {
	// 索引命名
	Pattern string `json:"pattern"` // "logs-%{+YYYY.MM.dd}"

	// 别名
	Alias string `json:"alias"`

	// 映射
	Mapping *IndexMapping `json:"mapping"`

	// 设置
	Settings *IndexSettings `json:"settings"`
}

// IndexMapping 索引映射
type IndexMapping struct {
	// 字段映射
	Fields map[string]*FieldMapping `json:"fields"`

	// 动态映射
	DynamicMapping string `json:"dynamic_mapping"` // "strict", "true", "false"

	// 父-子映射
	ParentChild *ParentChildMapping `json:"parent_child"`
}

// FieldMapping 字段映射
type FieldMapping struct {
	Type string `json:"type"` // "keyword", "text", "date", "ip", "geo_point", "object"

	Format string `json:"format"`

	Index *FieldIndex `json:"index"`

	Analyzer string `json:"analyzer"`

	SearchAnalyzer string `json:"search_analyzer"`

	Fields map[string]*FieldMapping `json:"fields"`
}

// FieldIndex 字段索引配置
type FieldIndex struct {
	Enabled   bool `json:"enabled"`
	DocValues bool `json:"doc_values"`
	Norms     bool `json:"norms"`
	Store     bool `json:"store"`
}

// ParentChildMapping 父子映射
type ParentChildMapping struct {
	Enabled bool   `json:"enabled"`
	Parent  string `json:"parent"`
	Child   string `json:"child"`
}

// IndexSettings 索引设置
type IndexSettings struct {
	// 分片数
	NumberOfShards int `json:"number_of_shards"`

	// 副本数
	NumberOfReplicas int `json:"number_of_replicas"`

	// 刷新间隔
	RefreshInterval time.Duration `json:"refresh_interval"`

	// 合并配置
	Merges *MergeConfig `json:"merges"`

	// 路由配置
	Routing *IndexRouting `json:"routing"`
}

// MergeConfig 合并配置
type MergeConfig struct {
	// 启用自动合并
	Enabled bool `json:"enabled"`

	// 最大分片大小
	MaxShardSize string `json:"max_shard_size"`

	// 最大段数
	MaxSegments int `json:"max_segments"`
}

// IndexRouting 索引路由配置
type IndexRouting struct {
	Allocation *RoutingAllocation `json:"allocation"`
}

// RoutingAllocation 路由分配配置
type RoutingAllocation struct {
	Include *RoutingInclude `json:"include"`
	Exclude *RoutingExclude `json:"exclude"`
	Require *RoutingRequire `json:"require"`
}

// RoutingInclude 路由包含
type RoutingInclude struct {
	Attributes []string `json:"attributes"`
}

// RoutingExclude 路由排除
type RoutingExclude struct {
	Attributes []string `json:"attributes"`
}

// RoutingRequire 路由要求
type RoutingRequire struct {
	Attributes []string `json:"attributes"`
}

// AnalysisConfig 分析配置
type AnalysisConfig struct {
	// 分析任务
	Tasks []*AnalysisTask `json:"tasks"`

	// 实时分析
	Realtime *RealtimeAnalysis `json:"realtime"`

	// 离线分析
	Batch *BatchAnalysis `json:"batch"`

	// 机器学习分析
	ML *MLAnalysis `json:"ml"`
}

// AnalysisTask 分析任务
type AnalysisTask struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// 分析类型: count, frequency, trend, anomaly, aggregation
	AnalysisType string `json:"analysis_type"`

	// 分析字段
	AnalysisField string `json:"analysis_field"`

	// 查询
	Query *AnalysisQuery `json:"query"`

	// 聚合
	Aggregation *AnalysisAggregation `json:"aggregation"`

	// 分组
	GroupBy []string `json:"group_by"`

	// 时间范围
	TimeRange *TimeRange `json:"time_range"`

	// 调度配置
	Schedule *TaskSchedule `json:"schedule"`

	// 输出配置
	Output *TaskOutput `json:"output"`

	// 状态
	Enabled bool `json:"enabled"`

	// 分析日志 (运行时填充)
	Logs []*LogEntry `json:"logs"`
}

// AnalysisQuery 分析查询
type AnalysisQuery struct {
	// 查询类型
	Type string `json:"type"` // "match", "term", "range", "bool", "query_string"

	// 查询条件
	Query string `json:"query"`

	// 过滤条件
	Filters []*FilterRule `json:"filters"`

	// 字段选择
	Fields []string `json:"fields"`

	// 排序
	Sort []*SortConfig `json:"sort"`

	// 限制
	Limit int `json:"limit"`

	// 采样
	Sampling *SamplingConfig `json:"sampling"`
}

// SortConfig 排序配置
type SortConfig struct {
	Field string `json:"field"`
	Order string `json:"order"` // "asc", "desc"
}

// SamplingConfig 采样配置
type SamplingConfig struct {
	// 启用采样
	Enabled bool `json:"enabled"`

	// 采样率
	Rate float64 `json:"rate"` // 0-1

	// 种子
	Seed int64 `json:"seed"`
}

// AnalysisAggregation 分析聚合
type AnalysisAggregation struct {
	// 聚合类型
	Type string `json:"type"` // "count", "sum", "avg", "min", "max", "percentiles", "cardinality", "terms", "date_histogram", "histogram"

	// 聚合字段
	Field string `json:"field"`

	// 桶聚合配置
	Buckets *BucketAggregation `json:"buckets"`

	// 管道聚合
	Pipeline *PipelineAggregation `json:"pipeline"`
}

// BucketAggregation 桶聚合配置
type BucketAggregation struct {
	// 桶类型
	Type string `json:"type"` // "terms", "range", "date_range", "geo_distance", "filters"

	// 配置
	Config map[string]interface{} `json:"config"`

	// 子聚合
	SubAggregations []*AnalysisAggregation `json:"sub_aggregations"`

	// 大小限制
	Size int `json:"size"`

	// 最小文档数
	MinDocCount int `json:"min_doc_count"`

	// 扩展边界
	ExtendedBounds *ExtendedBounds `json:"extended_bounds"`
}

// ExtendedBounds 扩展边界
type ExtendedBounds struct {
	Min interface{} `json:"min"`
	Max interface{} `json:"max"`
}

// PipelineAggregation 管道聚合配置
type PipelineAggregation struct {
	// 类型
	Type string `json:"type"` // "derivative", "cumulative_sum", "moving_avg", "bucket_script", "serial_diff"

	// 源聚合
	Source string `json:"source"`

	// 配置
	Config map[string]interface{} `json:"config"`
}

// TimeRange 时间范围
type TimeRange struct {
	Field    string `json:"field"`
	From     string `json:"from"` // "now-1h", "2024-01-01"
	To       string `json:"to"`   // "now", "2024-01-02"
	Timezone string `json:"timezone"`
}

// TaskSchedule 任务调度
type TaskSchedule struct {
	// 类型
	Type string `json:"type"` // "interval", "cron"

	// 间隔
	Interval time.Duration `json:"interval"`

	// Cron表达式
	CronExpression string `json:"cron_expression"`

	// 时区
	Timezone string `json:"timezone"`

	// 有效时间
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}

// TaskOutput 任务输出
type TaskOutput struct {
	// 输出类型
	Type string `json:"type"` // "index", "email", "webhook", "file"

	// 输出配置
	Config map[string]interface{} `json:"config"`

	// 格式化
	Formatting *OutputFormatting `json:"formatting"`

	// 条件
	Condition string `json:"condition"`
}

// OutputFormatting 输出格式化
type OutputFormatting struct {
	// 格式
	Format string `json:"format"` // "json", "csv", "table", "markdown", "html"

	// 模板
	Template string `json:"template"`

	// 包含字段
	IncludeFields []string `json:"include_fields"`

	// 排除字段
	ExcludeFields []string `json:"exclude_fields"`

	// 排序
	SortFields []string `json:"sort_fields"`

	// 限制
	Limit int `json:"limit"`
}

// RealtimeAnalysis 实时分析配置
type RealtimeAnalysis struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 窗口大小
	WindowSize time.Duration `json:"window_size"`

	// 滑动间隔
	SlideInterval time.Duration `json:"slide_interval"`

	// 触发器
	Triggers []*RealtimeTrigger `json:"triggers"`

	// 告警
	Alerts []*RealtimeAlert `json:"alerts"`
}

// RealtimeTrigger 实时触发器
type RealtimeTrigger struct {
	Name      string   `json:"name"`
	Condition string   `json:"condition"`
	Actions   []string `json:"actions"`
}

// RealtimeAlert 实时告警
type RealtimeAlert struct {
	Name      string        `json:"name"`
	Condition string        `json:"condition"`
	Severity  string        `json:"severity"`
	Actions   []string      `json:"actions"`
	Throttle  time.Duration `json:"throttle"`
}

// BatchAnalysis 离线分析配置
type BatchAnalysis struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 调度配置
	Schedule *BatchSchedule `json:"schedule"`

	// 任务配置
	Tasks []*BatchTask `json:"tasks"`

	// 资源限制
	Resources *BatchResources `json:"resources"`
}

// BatchSchedule 批量调度
type BatchSchedule struct {
	// 类型
	Type string `json:"type"` // "hourly", "daily", "weekly", "monthly"

	// 执行时间
	ExecutionTime string `json:"execution_time"` // "02:00"

	// 时区
	Timezone string `json:"timezone"`

	// 并发限制
	Concurrency int `json:"concurrency"`
}

// BatchTask 批量任务
type BatchTask struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Query       *AnalysisQuery       `json:"query"`
	Aggregation *AnalysisAggregation `json:"aggregation"`
	Output      *TaskOutput          `json:"output"`
}

// BatchResources 批量资源
type BatchResources struct {
	// CPU限制
	CPULimit float64 `json:"cpu_limit"` // cores

	// 内存限制
	MemoryLimit int64 `json:"memory_limit"` // bytes

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 并发限制
	Concurrency int `json:"concurrency"`
}

// MLAnalysis 机器学习分析配置
type MLAnalysis struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 任务配置
	Tasks []*MLTask `json:"tasks"`

	// 模型配置
	Models []*MLModelConfig `json:"models"`

	// 训练配置
	Training *MLTrainingConfig `json:"training"`

	// 推理配置
	Inference *MLInferenceConfig `json:"inference"`
}

// MLTask 机器学习任务
type MLTask struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"` // "anomaly_detection", "classification", "clustering", "forecasting"
	Algorithm   string         `json:"algorithm"`
	Query       *AnalysisQuery `json:"query"`
	Features    []string       `json:"features"`
	TargetField string         `json:"target_field"`
}

// MLModelConfig 机器学习模型配置
type MLModelConfig struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// MLTrainingConfig 机器学习训练配置
type MLTrainingConfig struct {
	Interval        time.Duration          `json:"interval"`
	DataSize        int                    `json:"data_size"`
	Features        []string               `json:"features"`
	Hyperparameters map[string]interface{} `json:"hyperparameters"`
	Validation      *MLValidation          `json:"validation"`
}

// MLValidation 机器学习验证
type MLValidation struct {
	Method  string   `json:"method"` // "kfold", "holdout", "cross"
	Split   float64  `json:"split"`
	Metrics []string `json:"metrics"`
}

// MLInferenceConfig 机器学习推理配置
type MLInferenceConfig struct {
	BatchSize int           `json:"batch_size"`
	Timeout   time.Duration `json:"timeout"`
	Threshold float64       `json:"threshold"`
}

// SchedulingConfig 调度配置
type SchedulingConfig struct {
	// 任务调度
	TaskScheduler *TaskSchedulerConfig `json:"task_scheduler"`

	// 资源调度
	ResourceScheduler *ResourceSchedulerConfig `json:"resource_scheduler"`

	// 优先级配置
	Priorities *PriorityConfig `json:"priorities"`
}

// TaskSchedulerConfig 任务调度配置
type TaskSchedulerConfig struct {
	// 调度器类型
	Type string `json:"type"` // "fifo", "priority", "fair_share"

	// 最大并发任务数
	MaxConcurrentTasks int `json:"max_concurrent_tasks"`

	// 任务超时
	TaskTimeout time.Duration `json:"task_timeout"`

	// 任务重试
	TaskRetry *TaskRetryConfig `json:"task_retry"`
}

// TaskRetryConfig 任务重试配置
type TaskRetryConfig struct {
	MaxRetries int           `json:"max_retries"`
	Interval   time.Duration `json:"interval"`
	Backoff    string        `json:"backoff"` // "fixed", "exponential"
}

// ResourceSchedulerConfig 资源调度配置
type ResourceSchedulerConfig struct {
	// CPU权重
	CPUWeights map[string]float64 `json:"cpu_weights"`

	// 内存权重
	MemoryWeights map[string]float64 `json:"memory_weights"`

	// I/O权重
	IOWeights map[string]float64 `json:"io_weights"`

	// 公平调度配置
	FairShare *FairShareConfig `json:"fair_share"`
}

// FairShareConfig 公平调度配置
type FairShareConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 权重计算
	WeightCalculation string `json:"weight_calculation"` // "demand", "share", "history"

	// 最小份额
	MinShares map[string]float64 `json:"min_shares"`

	// 最大份额
	MaxShares map[string]float64 `json:"max_shares"`
}

// PriorityConfig 优先级配置
type PriorityConfig struct {
	// 优先级范围
	MinPriority int `json:"min_priority"`
	MaxPriority int `json:"max_priority"`

	// 默认优先级
	DefaultPriority int `json:"default_priority"`

	// 优先级映射
	PriorityMapping map[string]int `json:"priority_mapping"`
}

// LogInput 日志输入接口
type LogInput interface {
	Start() error
	Stop() error
	Read() ([]*LogEntry, error)
	GetInputName() string
}

// LogProcessor 日志处理器接口
type LogProcessor interface {
	Process(ctx context.Context, entries []*LogEntry) ([]*LogEntry, error)
	GetProcessorName() string
}

// LogOutput 日志输出接口
type LogOutput interface {
	Write(ctx context.Context, entries []*LogEntry) error
	Flush() error
	Close() error
	GetOutputName() string
}

// LogEntry 日志条目
type LogEntry struct {
	// ID
	ID string `json:"id"`

	// 时间戳
	Timestamp time.Time `json:"timestamp"`

	// 原始数据
	RawData string `json:"raw_data"`

	// 解析后的字段
	Fields map[string]interface{} `json:"fields"`

	// 来源
	Source *LogSource `json:"source"`

	// 标签
	Tags []string `json:"tags"`

	// 元数据
	Metadata map[string]interface{} `json:"metadata"`

	// 状态
	Status string `json:"status"` // "parsed", "failed", "filtered"

	// 处理时间
	ProcessedAt time.Time `json:"processed_at"`
}

// LogSource 日志来源
type LogSource struct {
	// 类型
	Type string `json:"type"` // "file", "kafka", "redis", "http", "tcp"

	// 名称
	Name string `json:"name"`

	// 路径或地址
	Path string `json:"path"`

	// 主机
	Host string `json:"host"`

	// 端口
	Port int `json:"port"`

	// 文件偏移
	Offset int64 `json:"offset"`
}

// LogAggregator 日志聚合器
type LogAggregator struct {
	analyzer *LogAnalyzer // 引用分析器
	config   *AggregationConfig
	metrics  *AggregatedMetrics
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// AggregationConfig 聚合配置
type AggregationConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
	Window   time.Duration `json:"window"`
}

// AggregatedMetrics 聚合指标
type AggregatedMetrics struct {
	// 时间戳
	Timestamp time.Time `json:"timestamp"`
	// 总日志数
	TotalLogs int64 `json:"total_logs"`

	// 解析成功数
	ParsedLogs int64 `json:"parsed_logs"`

	// 解析失败数
	FailedLogs int64 `json:"failed_logs"`

	// 过滤日志数
	FilteredLogs int64 `json:"filtered_logs"`

	// 输出日志数
	OutputLogs int64 `json:"output_logs"`

	// 按类型统计
	LogsByType map[string]int64 `json:"logs_by_type"`

	// 按来源统计
	LogsBySource map[string]int64 `json:"logs_by_source"`

	// 按级别统计
	LogsByLevel map[string]int64 `json:"logs_by_level"`

	// 吞吐量
	Throughput float64 `json:"throughput"` // logs per second

	// 平均处理时间
	AverageProcessingTime time.Duration `json:"average_processing_time"`

	// 延迟统计
	LatencyP50 time.Duration `json:"latency_p50"`
	LatencyP90 time.Duration `json:"latency_p90"`
	LatencyP99 time.Duration `json:"latency_p99"`

	mu sync.RWMutex
}

// AnalyzerStats 分析器统计
type AnalyzerStats struct {
	// 输入统计
	InputStats map[string]*InputStats `json:"input_stats"`

	// 处理统计
	ProcessingStats *ProcessingStats `json:"processing_stats"`

	// 输出统计
	OutputStats map[string]*OutputStats `json:"output_stats"`

	// 聚合指标
	AggregatedMetrics *AggregatedMetrics `json:"aggregated_metrics"`

	// 任务统计
	TaskStats map[string]*TaskStats `json:"task_stats"`

	mu sync.RWMutex
}

// InputStats 输入统计
type InputStats struct {
	Name string `json:"name"`
	Type string `json:"type"`

	// 读取日志数
	LogsRead int64 `json:"logs_read"`

	// 读取速率
	ReadRate float64 `json:"read_rate"` // logs per second

	// 字节数
	BytesRead int64 `json:"bytes_read"`

	// 字节速率
	ByteRate float64 `json:"byte_rate"` // bytes per second

	// 错误数
	Errors int64 `json:"errors"`

	// 最后读取时间
	LastRead time.Time `json:"last_read"`

	// 总接收数
	TotalReceived int64 `json:"total_received"`

	// 总解析数
	TotalParsed int64 `json:"total_parsed"`

	// 总失败数
	TotalFailed int64 `json:"total_failed"`

	mu sync.RWMutex
}

// ProcessingStats 处理统计
type ProcessingStats struct {
	// 处理日志数
	LogsProcessed int64 `json:"logs_processed"`

	// 成功数
	Success int64 `json:"success"`

	// 失败数
	Failures int64 `json:"failures"`

	// 过滤数
	Filtered int64 `json:"filtered"`

	// 吞吐量
	Throughput float64 `json:"throughput"`

	// 平均处理时间
	AverageTime time.Duration `json:"average_time"`

	// 并发数
	Concurrency int `json:"concurrency"`

	// 队列长度
	QueueLength int `json:"queue_length"`

	// 查询统计
	TotalQueries       int64         `json:"total_queries"`
	TotalQueryDuration time.Duration `json:"total_query_duration"`

	mu sync.RWMutex
}

// OutputStats 输出统计
type OutputStats struct {
	Name string `json:"name"`
	Type string `json:"type"`

	// 写入日志数
	LogsWritten int64 `json:"logs_written"`

	// 写入速率
	WriteRate float64 `json:"write_rate"`

	// 字节数
	BytesWritten int64 `json:"bytes_written"`

	// 错误数
	Errors int64 `json:"errors"`

	// 最后写入时间
	LastWrite time.Time `json:"last_write"`

	mu sync.RWMutex
}

// TaskStats 任务统计
type TaskStats struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`

	// 执行次数
	Executions int64 `json:"executions"`

	// 成功次数
	Success int64 `json:"success"`

	// 失败次数
	Failures int64 `json:"failures"`

	// 总执行时间
	TotalTime time.Duration `json:"total_time"`

	// 平均执行时间
	AverageTime time.Duration `json:"average_time"`

	// 最后执行时间
	LastExecution time.Time `json:"last_execution"`

	mu sync.RWMutex
}

// NewLogAnalyzer 创建日志分析系统
func NewLogAnalyzer(config *AnalyzerConfig) *LogAnalyzer {
	if config == nil {
		config = &AnalyzerConfig{
			Enabled: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &LogAnalyzer{
		config:     config,
		inputs:     make([]LogInput, 0),
		processors: make([]LogProcessor, 0),
		outputs:    make([]LogOutput, 0),
		aggregator: &LogAggregator{
			metrics: &AggregatedMetrics{
				LogsByType:   make(map[string]int64),
				LogsBySource: make(map[string]int64),
				LogsByLevel:  make(map[string]int64),
			},
			ctx:    ctx,
			cancel: cancel,
		},
		stats: &AnalyzerStats{
			InputStats:  make(map[string]*InputStats),
			OutputStats: make(map[string]*OutputStats),
			TaskStats:   make(map[string]*TaskStats),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// RegisterInput 注册输入
func (a *LogAnalyzer) RegisterInput(input LogInput) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.inputs = append(a.inputs, input)
}

// RegisterProcessor 注册处理器
func (a *LogAnalyzer) RegisterProcessor(processor LogProcessor) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.processors = append(a.processors, processor)
}

// RegisterOutput 注册输出
func (a *LogAnalyzer) RegisterOutput(output LogOutput) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.outputs = append(a.outputs, output)
}

// Start 启动分析系统
func (a *LogAnalyzer) Start() error {
	// 启动所有输入
	for _, input := range a.inputs {
		if err := input.Start(); err != nil {
			return fmt.Errorf("启动输入失败: %w", err)
		}
	}

	// 启动聚合器
	go a.aggregator.runAggregation()

	return nil
}

// Stop 停止分析系统
func (a *LogAnalyzer) Stop() error {
	a.cancel()

	// 停止所有输入
	for _, input := range a.inputs {
		input.Stop()
	}

	// 刷新所有输出
	for _, output := range a.outputs {
		output.Flush()
		output.Close()
	}

	return nil
}

// Process 处理日志
func (a *LogAnalyzer) Process(ctx context.Context, entries []*LogEntry) ([]*LogEntry, error) {
	var err error
	processed := entries

	for _, processor := range a.processors {
		processed, err = processor.Process(ctx, processed)
		if err != nil {
			return processed, err
		}
	}

	// 更新聚合指标
	a.aggregator.mu.Lock()
	a.aggregator.metrics.TotalLogs += int64(len(entries))
	a.aggregator.metrics.ParsedLogs += int64(len(processed))
	a.aggregator.metrics.Throughput = float64(a.aggregator.metrics.TotalLogs) / time.Since(a.aggregator.metrics.Timestamp).Seconds()
	a.aggregator.mu.Unlock()

	return processed, nil
}

// Output 输出日志
func (a *LogAnalyzer) Output(ctx context.Context, entries []*LogEntry) error {
	for _, output := range a.outputs {
		if err := output.Write(ctx, entries); err != nil {
			continue
		}

		// 更新输出统计
		a.stats.mu.Lock()
		if a.stats.OutputStats[output.GetOutputName()] == nil {
			a.stats.OutputStats[output.GetOutputName()] = &OutputStats{
				Name: output.GetOutputName(),
				Type: "unknown",
			}
		}
		a.stats.OutputStats[output.GetOutputName()].LogsWritten += int64(len(entries))
		a.stats.OutputStats[output.GetOutputName()].LastWrite = time.Now()
		a.stats.mu.Unlock()
	}

	// 更新聚合指标
	a.aggregator.mu.Lock()
	a.aggregator.metrics.OutputLogs += int64(len(entries))
	a.aggregator.mu.Unlock()

	return nil
}

// GetStats 获取统计
func (a *LogAnalyzer) GetStats() *AnalyzerStats {
	a.stats.mu.RLock()
	defer a.stats.mu.RUnlock()

	return a.stats
}

// GetAggregatedMetrics 获取聚合指标
func (a *LogAnalyzer) GetAggregatedMetrics() *AggregatedMetrics {
	a.aggregator.metrics.mu.RLock()
	defer a.aggregator.metrics.mu.RUnlock()

	return a.aggregator.metrics
}

// runAggregation 运行聚合
func (a *LogAggregator) runAggregation() {
	ticker := time.NewTicker(a.config.Interval)
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

// aggregate 聚合
func (a *LogAggregator) aggregate() {
	a.metrics.mu.Lock()
	defer a.metrics.mu.Unlock()

	// 更新聚合时间戳
	a.metrics.Timestamp = time.Now()

	// 重置计数器用于新周期
	prevTotal := a.metrics.TotalLogs
	a.metrics.TotalLogs = 0
	a.metrics.ParsedLogs = 0
	a.metrics.FailedLogs = 0
	a.metrics.FilteredLogs = 0
	a.metrics.OutputLogs = 0

	// 从分析器获取统计数据
	a.analyzer.mu.RLock()
	for _, input := range a.analyzer.inputs {
		inputName := input.GetInputName()
		if inputStats, ok := a.analyzer.stats.InputStats[inputName]; ok {
			a.metrics.TotalLogs += inputStats.TotalReceived
			a.metrics.ParsedLogs += inputStats.TotalParsed
			a.metrics.FailedLogs += inputStats.TotalFailed
		}
	}
	a.analyzer.mu.RUnlock()

	// 计算吞吐量 (logs/second)
	elapsed := time.Since(a.metrics.Timestamp)
	if elapsed > 0 && a.metrics.TotalLogs > 0 {
		a.metrics.Throughput = float64(a.metrics.TotalLogs) / elapsed.Seconds()
	}

	// 如果有前一周期的数据，计算增量
	deltaLogs := a.metrics.TotalLogs - prevTotal
	if deltaLogs > 0 {
		// 更新各类型统计
		if a.metrics.LogsByType == nil {
			a.metrics.LogsByType = make(map[string]int64)
		}
		a.metrics.LogsByType["total"] += deltaLogs

		if a.metrics.LogsBySource == nil {
			a.metrics.LogsBySource = make(map[string]int64)
		}
		a.metrics.LogsBySource["default"] += deltaLogs

		if a.metrics.LogsByLevel == nil {
			a.metrics.LogsByLevel = make(map[string]int64)
		}
		a.metrics.LogsByLevel["info"] += deltaLogs
	}

	// 估算延迟百分位 (简化实现)
	a.metrics.LatencyP50 = a.metrics.AverageProcessingTime * 50 / 100
	a.metrics.LatencyP90 = a.metrics.AverageProcessingTime * 90 / 100
	a.metrics.LatencyP99 = a.metrics.AverageProcessingTime * 99 / 100
}

// GetAggregatedMetrics 获取聚合指标
func (a *LogAggregator) GetAggregatedMetrics() *AggregatedMetrics {
	a.metrics.mu.RLock()
	defer a.metrics.mu.RUnlock()

	// 返回新实例以避免复制锁
	return &AggregatedMetrics{
		Timestamp:             a.metrics.Timestamp,
		TotalLogs:             a.metrics.TotalLogs,
		ParsedLogs:            a.metrics.ParsedLogs,
		FailedLogs:            a.metrics.FailedLogs,
		FilteredLogs:          a.metrics.FilteredLogs,
		OutputLogs:            a.metrics.OutputLogs,
		LogsByType:            copyMap(a.metrics.LogsByType),
		LogsBySource:          copyMap(a.metrics.LogsBySource),
		LogsByLevel:           copyMap(a.metrics.LogsByLevel),
		Throughput:            a.metrics.Throughput,
		AverageProcessingTime: a.metrics.AverageProcessingTime,
		LatencyP50:            a.metrics.LatencyP50,
		LatencyP90:            a.metrics.LatencyP90,
		LatencyP99:            a.metrics.LatencyP99,
	}
}

// copyMap 复制map
func copyMap(src map[string]int64) map[string]int64 {
	if src == nil {
		return nil
	}
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Query 查询日志
func (a *LogAnalyzer) Query(ctx context.Context, query *AnalysisQuery) ([]*LogEntry, error) {
	startTime := time.Now()

	// 检查缓存
	cacheKey := a.generateCacheKey(query)
	a.mu.RLock()
	if entry, ok := a.cache[cacheKey]; ok && entry.ExpiresAt.After(time.Now()) {
		result := entry.Result.([]*LogEntry)
		a.mu.RUnlock()
		return result, nil
	}
	a.mu.RUnlock()

	// 如果有存储后端，使用存储查询
	if a.storage != nil {
		logs, err := a.queryFromStorage(ctx, query)
		if err == nil {
			// 缓存结果
			a.cacheResult(cacheKey, query, logs, 5*time.Minute)
			return logs, nil
		}
		// 如果存储查询失败，继续使用内存查询
	}

	// 内存查询 (从所有输入源收集日志)
	result := make([]*LogEntry, 0, query.Limit)

	// 应用过滤和查询条件
	for _, input := range a.inputs {
		if query.Limit > 0 && len(result) >= query.Limit {
			break
		}

		// 获取输入日志 (这里简化处理，实际应该从输入收集)
		logs := a.collectLogsFromInput(input, query)
		for _, log := range logs {
			if a.matchesQuery(log, query) {
				result = append(result, log)
				if query.Limit > 0 && len(result) >= query.Limit {
					break
				}
			}
		}
	}

	// 更新统计
	a.mu.Lock()
	a.stats.ProcessingStats.TotalQueries++
	a.stats.ProcessingStats.TotalQueryDuration += time.Since(startTime)
	a.mu.Unlock()

	// 缓存结果
	a.cacheResult(cacheKey, query, result, 5*time.Minute)

	return result, nil
}

// queryFromStorage 从存储查询
func (a *LogAnalyzer) queryFromStorage(ctx context.Context, query *AnalysisQuery) ([]*LogEntry, error) {
	// 转换查询条件
	logQuery := &LogQuery{
		StartTime: time.Now().Add(-24 * time.Hour), // 默认最近24小时
		EndTime:   time.Now(),
		Limit:     query.Limit,
	}

	// 添加过滤条件
	for _, filter := range query.Filters {
		logQuery.Filters = append(logQuery.Filters, &FilterRule{
			Field:    filter.Field,
			Operator: filter.Operator,
			Value:    filter.Value,
			Negate:   filter.Negate,
		})
	}

	// 执行存储查询
	logs, err := a.storage.Query(logQuery)
	if err != nil {
		return nil, err
	}

	// 转换为LogEntry
	result := make([]*LogEntry, len(logs))
	for i, log := range logs {
		result[i] = &LogEntry{
			ID:        log.ID,
			Timestamp: log.Timestamp,
			RawData:   fmt.Sprintf("%s %s %d", log.RequestID, log.ClientIP, log.StatusCode),
			Fields: map[string]interface{}{
				"method":   log.Method,
				"path":     log.Path,
				"status":   log.StatusCode,
				"clientIP": log.ClientIP,
			},
			Status: "parsed",
		}
	}

	return result, nil
}

// collectLogsFromInput 从输入收集日志
func (a *LogAnalyzer) collectLogsFromInput(input LogInput, query *AnalysisQuery) []*LogEntry {
	// 简化实现：返回空数组
	// 实际实现应该从输入源收集日志
	return make([]*LogEntry, 0)
}

// matchesQuery 检查日志是否匹配查询条件
func (a *LogAnalyzer) matchesQuery(log *LogEntry, query *AnalysisQuery) bool {
	// 检查查询字符串
	if query.Query != "" {
		match := false
		if strings.Contains(strings.ToLower(log.RawData), strings.ToLower(query.Query)) {
			match = true
		}
		for _, field := range query.Fields {
			if val, ok := log.Fields[field]; ok {
				if strings.Contains(strings.ToLower(fmt.Sprintf("%v", val)), strings.ToLower(query.Query)) {
					match = true
					break
				}
			}
		}
		if !match {
			return false
		}
	}

	// 检查过滤条件
	for _, filter := range query.Filters {
		if !matchesFilter(log, filter) {
			return false
		}
	}

	return true
}

// matchesFilter 检查日志是否匹配过滤规则
func matchesFilter(log *LogEntry, filter *FilterRule) bool {
	fieldVal := getFieldValue(log, filter.Field)
	if fieldVal == nil {
		return false
	}

	switch filter.Operator {
	case "eq":
		return fieldVal == filter.Value
	case "ne":
		return fieldVal != filter.Value
	case "gt":
		return compareValues(fieldVal, filter.Value) > 0
	case "lt":
		return compareValues(fieldVal, filter.Value) < 0
	case "contains":
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", fieldVal)), strings.ToLower(fmt.Sprintf("%v", filter.Value)))
	case "regex":
		// 简化实现：使用字符串匹配
		return strings.Contains(fmt.Sprintf("%v", fieldVal), fmt.Sprintf("%v", filter.Value))
	case "in":
		if vals, ok := filter.Value.([]interface{}); ok {
			for _, v := range vals {
				if fieldVal == v {
					return true
				}
			}
			return false
		}
		return false
	}

	return false
}

// getFieldValue 获取字段值
func getFieldValue(log *LogEntry, field string) interface{} {
	if field == "raw_data" || field == "raw" {
		return log.RawData
	}
	if field == "id" {
		return log.ID
	}
	if field == "timestamp" {
		return log.Timestamp
	}
	if field == "status" {
		return log.Status
	}
	if val, ok := log.Fields[field]; ok {
		return val
	}
	return nil
}

// compareValues 比较两个值
func compareValues(a, b interface{}) int {
	aVal := fmt.Sprintf("%v", a)
	bVal := fmt.Sprintf("%v", b)

	// 尝试转换为数字比较
	var aNum, bNum float64
	if _, err := fmt.Sscanf(aVal, "%f", &aNum); err == nil {
		if _, err := fmt.Sscanf(bVal, "%f", &bNum); err == nil {
			if aNum < bNum {
				return -1
			} else if aNum > bNum {
				return 1
			}
			return 0
		}
	}

	if aVal < bVal {
		return -1
	} else if aVal > bVal {
		return 1
	}
	return 0
}

// generateCacheKey 生成缓存键
func (a *LogAnalyzer) generateCacheKey(query *AnalysisQuery) string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// cacheResult 缓存查询结果
func (a *LogAnalyzer) cacheResult(key string, query *AnalysisQuery, result interface{}, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cache == nil {
		a.cache = make(map[string]*CacheEntry)
	}

	a.cache[key] = &CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(ttl),
		Query:     query,
	}

	// 清理过期缓存
	if len(a.cache) > 1000 {
		for k, entry := range a.cache {
			if entry.ExpiresAt.Before(time.Now()) {
				delete(a.cache, k)
			}
		}
	}
}

// Analyze 执行分析任务
func (a *LogAnalyzer) Analyze(ctx context.Context, task *AnalysisTask) (*AnalysisResult, error) {
	startTime := time.Now()

	// 创建结果
	result := &AnalysisResult{
		TaskID:      task.ID,
		Status:      "running",
		GeneratedAt: startTime,
	}

	// 根据分析类型执行分析
	var data interface{}
	var err error

	switch task.AnalysisType {
	case "count":
		data, err = a.analyzeCount(ctx, task)
	case "frequency":
		data, err = a.analyzeFrequency(ctx, task)
	case "trend":
		data, err = a.analyzeTrend(ctx, task)
	case "anomaly":
		data, err = a.analyzeAnomaly(ctx, task)
	case "aggregation":
		data, err = a.analyzeAggregation(ctx, task)
	default:
		data, err = a.analyzeAggregation(ctx, task)
	}

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result, err
	}

	// 更新结果
	result.Status = "completed"
	result.Data = data
	result.ExecutionTime = time.Since(startTime)
	result.Stats = &AnalysisResultStats{
		TotalHits:    int64(len(task.Logs)),
		ReturnedHits: int64(len(task.Logs)),
		Duration:     result.ExecutionTime,
	}

	return result, nil
}

// analyzeCount 计数分析
func (a *LogAnalyzer) analyzeCount(ctx context.Context, task *AnalysisTask) (interface{}, error) {
	count := len(task.Logs)
	return map[string]interface{}{
		"count": count,
		"field": task.AnalysisField,
	}, nil
}

// analyzeFrequency 频率分析
func (a *LogAnalyzer) analyzeFrequency(ctx context.Context, task *AnalysisTask) (interface{}, error) {
	freq := make(map[string]int)
	for _, log := range task.Logs {
		if val := getFieldValue(log, task.AnalysisField); val != nil {
			key := fmt.Sprintf("%v", val)
			freq[key]++
		}
	}
	return map[string]interface{}{
		"frequency": freq,
		"field":     task.AnalysisField,
	}, nil
}

// analyzeTrend 趋势分析
func (a *LogAnalyzer) analyzeTrend(ctx context.Context, task *AnalysisTask) (interface{}, error) {
	// 按时间分组统计
	trends := make(map[string]int64)
	for _, log := range task.Logs {
		// 按小时分组
		hour := log.Timestamp.Format("2006-01-02 15")
		trends[hour]++
	}
	return map[string]interface{}{
		"trend": trends,
		"field": task.AnalysisField,
	}, nil
}

// analyzeAnomaly 异常检测
func (a *LogAnalyzer) analyzeAnomaly(ctx context.Context, task *AnalysisTask) (interface{}, error) {
	anomalies := make([]*AnomalyResult, 0)

	// 简单异常检测：基于频率
	fieldFreq := make(map[string]int)
	for _, log := range task.Logs {
		if val := getFieldValue(log, task.AnalysisField); val != nil {
			key := fmt.Sprintf("%v", val)
			fieldFreq[key]++
		}
	}

	// 找出异常值 (频率低于平均值的50%或高于平均值的3倍)
	var total int
	for _, count := range fieldFreq {
		total += count
	}
	avg := float64(total) / float64(len(fieldFreq))

	for key, count := range fieldFreq {
		if float64(count) < avg*0.5 || float64(count) > avg*3 {
			anomalies = append(anomalies, &AnomalyResult{
				Field:       task.AnalysisField,
				Value:       key,
				ActualCount: int64(count),
				ExpectedAvg: avg,
				Severity:    "medium",
			})
		}
	}

	return map[string]interface{}{
		"anomalies":   anomalies,
		"total_found": len(anomalies),
	}, nil
}

// analyzeAggregation 聚合分析
func (a *LogAnalyzer) analyzeAggregation(ctx context.Context, task *AnalysisTask) (interface{}, error) {
	aggregations := make(map[string]interface{})

	// 数值字段聚合
	numericFields := []string{"latency", "status_code", "bytes"}
	for _, field := range numericFields {
		values := make([]float64, 0)
		for _, log := range task.Logs {
			if val := getFieldValue(log, field); val != nil {
				if fval, ok := val.(float64); ok {
					values = append(values, fval)
				}
			}
		}
		if len(values) > 0 {
			sum := 0.0
			for _, v := range values {
				sum += v
			}
			aggregations[field] = map[string]interface{}{
				"count": len(values),
				"sum":   sum,
				"avg":   sum / float64(len(values)),
				"min":   values[0],
				"max":   values[0],
			}
		}
	}

	return aggregations, nil
}

// AnomalyResult 异常结果
type AnomalyResult struct {
	Field       string  `json:"field"`
	Value       string  `json:"value"`
	ActualCount int64   `json:"actual_count"`
	ExpectedAvg float64 `json:"expected_avg"`
	Severity    string  `json:"severity"`
}

// AnalysisResult 分析结果
type AnalysisResult struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"` // "running", "completed", "failed"

	// 结果数据
	Data interface{} `json:"data"`

	// 聚合结果
	Aggregations map[string]interface{} `json:"aggregations"`

	// 统计信息
	Stats *AnalysisResultStats `json:"stats"`

	// 执行时间
	ExecutionTime time.Duration `json:"execution_time"`

	// 错误
	Error string `json:"error"`

	// 生成时间
	GeneratedAt time.Time `json:"generated_at"`
}

// AnalysisResultStats 分析结果统计
type AnalysisResultStats struct {
	TotalHits    int64         `json:"total_hits"`
	ReturnedHits int64         `json:"returned_hits"`
	Duration     time.Duration `json:"duration"`
}

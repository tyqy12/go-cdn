package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ActiveDefense 主动防御系统
type ActiveDefense struct {
	config     *DefenseConfig
	detectors  []AttackDetector
	preventors []AttackPreventor
	alerters   []DefenseAlerter
	threats    []*Threat
	mu         sync.RWMutex
	stats      *DefenseStats
	ctx        context.Context
	cancel     context.CancelFunc
}

// DefenseConfig 防御配置
type DefenseConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 检测配置
	Detection *DetectionConfig `yaml:"detection"`

	// 预防配置
	Prevention *PreventionConfig `yaml:"prevention"`

	// 告警配置
	Alerting *DefenseAlertingConfig `yaml:"alerting"`

	// 自动响应配置
	AutoResponse *AutoResponseConfig `yaml:"auto_response"`

	// 机器学习配置
	MLConfig *MLDefenseConfig `yaml:"ml_config"`

	// 威胁情报配置
	ThreatIntel *ThreatIntelConfig `yaml:"threat_intel"`
}

// DetectionConfig 检测配置
type DetectionConfig struct {
	// 启用检测
	Enabled bool `yaml:"enabled"`

	// 检测模式
	Mode string `yaml:"mode"` // "realtime", "batch", "hybrid"

	// 检测类型
	Types []string `yaml:"types"` // "ddos", "cc", "sql_injection", "xss", "bot", "scanner", "vulnerability"

	// 检测阈值
	Thresholds map[string]*ThresholdConfig `yaml:"thresholds"`

	// 行为分析配置
	BehaviorAnalysis *BehaviorAnalysisConfig `yaml:"behavior_analysis"`

	// 签名配置
	Signatures *SignatureConfig `yaml:"signatures"`

	// 异常检测配置
	AnomalyDetection *AnomalyDetectionConfig `yaml:"anomaly_detection"`
}

// ThresholdConfig 阈值配置
type ThresholdConfig struct {
	// 阈值
	Value float64 `json:"value"`

	// 窗口大小
	Window time.Duration `json:"window"`

	// 持续时间
	Duration time.Duration `json:"duration"`

	// 严重程度
	Severity string `json:"severity"` // "low", "medium", "high", "critical"
}

// BehaviorAnalysisConfig 行为分析配置
type BehaviorAnalysisConfig struct {
	// 启用行为分析
	Enabled bool `yaml:"enabled"`

	// 分析窗口
	Window time.Duration `yaml:"window"`

	// 基准建立时间
	BaselinePeriod time.Duration `yaml:"baseline_period"`

	// 异常阈值
	AnomalyThreshold float64 `yaml:"anomaly_threshold"`

	// 行为模型
	Models []*BehaviorModel `yaml:"models"`
}

// BehaviorModel 行为模型
type BehaviorModel struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"type"` // "pattern", "sequence", "frequency", "timing"
	Parameters   map[string]interface{} `json:"parameters"`
	TrainingData string                 `json:"training_data"`
}

// SignatureConfig 签名配置
type SignatureConfig struct {
	// 启用签名检测
	Enabled bool `yaml:"enabled"`

	// 签名库
	Library string `yaml:"library"` // "owasp", "custom", "mixed"

	// 自定义签名
	CustomSignatures []*CustomSignature `yaml:"custom_signatures"`

	// 签名更新配置
	UpdateConfig *SignatureUpdateConfig `yaml:"update_config"`
}

// CustomSignature 自定义签名
type CustomSignature struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"` // "injection", "xss", "csrf", "file_inclusion", etc.
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"` // "regex", "string", "byte"
	Severity    string `json:"severity"`
	Action      string `json:"action"` // "block", "log", "challenge"
	Description string `json:"description"`
}

// SignatureUpdateConfig 签名更新配置
type SignatureUpdateConfig struct {
	// 启用自动更新
	Enabled bool `yaml:"enabled"`

	// 更新间隔
	Interval time.Duration `yaml:"interval"`

	// 更新源
	Sources []string `json:"sources"`

	// 验证配置
	Verification *SignatureVerification `json:"verification"`
}

// SignatureVerification 签名验证
type SignatureVerification struct {
	// 启用验证
	Enabled bool `json:"enabled"`

	// 验证方法
	Method string `json:"method"` // "checksum", "signature", "both"

	// 信任存储
	TrustStore string `json:"trust_store"`
}

// AnomalyDetectionConfig 异常检测配置
type AnomalyDetectionConfig struct {
	// 启用异常检测
	Enabled bool `yaml:"enabled"`

	// 检测方法
	Method string `yaml:"method"` // "statistical", "ml", "hybrid"

	// 敏感度
	Sensitivity float64 `json:"sensitivity"` // 0-1

	// 最小样本数
	MinSamples int `json:"min_samples"`

	// 更新周期
	UpdatePeriod time.Duration `json:"update_period"`

	// 排除规则
	Exclusions []*AnomalyExclusion `json:"exclusions"`
}

// AnomalyExclusion 异常排除规则
type AnomalyExclusion struct {
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"` // "ip", "user_agent", "path"
	Description string `json:"description"`
}

// PreventionConfig 预防配置
type PreventionConfig struct {
	// 启用预防
	Enabled bool `yaml:"enabled"`

	// 预防措施
	Measures []*PreventionMeasure `json:"measures"`

	// 速率限制配置
	RateLimit *RateLimitConfig `yaml:"rate_limit"`

	// 访问控制配置
	AccessControl *AccessControlConfig `yaml:"access_control"`

	// 挑战配置
	Challenge *ChallengeConfig `yaml:"challenge"`
}

// PreventionMeasure 预防措施
type PreventionMeasure struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`   // "rate_limit", "captcha", "block", "redirect", "challenge"
	Target      string        `json:"target"` // "ip", "user", "session", "global"
	Condition   string        `json:"condition"`
	Action      string        `json:"action"`
	Duration    time.Duration `json:"duration"`
	Priority    int           `json:"priority"`
	Description string        `json:"description"`
}

// RateLimitConfig 速率限制配置
type RateLimitConfig struct {
	// 全局限速
	Global *RateLimitRule `yaml:"global"`

	// 每IP限速
	PerIP *RateLimitRule `yaml:"per_ip"`

	// 每用户限速
	PerUser *RateLimitRule `yaml:"per_user"`

	// 每路径限速
	PerPath *RateLimitRule `yaml:"per_path"`

	// 滑动窗口配置
	SlidingWindow *SlidingWindowConfig `yaml:"sliding_window"`
}

// RateLimitRule 速率限制规则
type RateLimitRule struct {
	Enabled  bool          `yaml:"enabled"`
	Limit    int64         `yaml:"limit"`
	Burst    int64         `yaml:"burst"`
	Interval time.Duration `yaml:"interval"`
}

// SlidingWindowConfig 滑动窗口配置
type SlidingWindowConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 窗口大小
	WindowSize time.Duration `yaml:"window_size"`

	// 子窗口数
	SubWindows int `yaml:"sub_windows"`
}

// AccessControlConfig 访问控制配置
type AccessControlConfig struct {
	// IP黑名单
	IPBlacklist []string `json:"ip_blacklist"`

	// IP白名单
	IPWhitelist []string `json:"ip_whitelist"`

	// 国家过滤
	CountryFilter *CountryFilterConfig `json:"country_filter"`

	// ASN过滤
	ASNFilter *ASNFilterConfig `json:"asn_filter"`

	// User-Agent过滤
	UserAgentFilter *UserAgentFilterConfig `json:"user_agent_filter"`
}

// CountryFilterConfig 国家过滤配置
type CountryFilterConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 允许的国家
	Allow []string `yaml:"allow"`

	// 阻止的国家
	Block []string `yaml:"block"`

	// 默认策略
	DefaultAction string `yaml:"default_action"` // "allow", "block", "challenge"

	// 阻止页面
	BlockPage string `json:"block_page"`
}

// ASNFilterConfig ASN过滤配置
type ASNFilterConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 允许的ASN
	Allow []string `json:"allow"`

	// 阻止的ASN
	Block []string `json:"block"`

	// 默认策略
	DefaultAction string `yaml:"default_action"`
}

// UserAgentFilterConfig User-Agent过滤配置
type UserAgentFilterConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 阻止的User-Agent
	Block []string `json:"block"`

	// 阻止的正则
	BlockRegex []string `json:"block_regex"`

	// 机器人检测
	BotDetection *BotDetectionConfig `json:"bot_detection"`
}

// BotDetectionConfig 机器人检测配置
type BotDetectionConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 检测方法
	Methods []string `json:"methods"` // "java_script", "behavior", "headless", "signature"

	// 响应策略
	Response string `json:"response"` // "challenge", "block", "log"

	// 白名单
	Whitelist []string `json:"whitelist"`
}

// ChallengeConfig 挑战配置
type ChallengeConfig struct {
	// 启用挑战
	Enabled bool `yaml:"enabled"`

	// 挑战类型
	Types []string `json:"types"` // "captcha", "js_challenge", "honey_pot", "rate_challenge"

	// JavaScript挑战
	JSChallenge *JSChallengeConfig `json:"js_challenge"`

	// CAPTCHA挑战
	CAPTCHA *CAPTCHAConfig `json:"captcha"`

	// 蜂蜜陷阱
	HoneyPot *HoneyPotConfig `json:"honey_pot"`

	// 速率挑战
	RateChallenge *RateChallengeConfig `json:"rate_challenge"`
}

// JSChallengeConfig JavaScript挑战配置
type JSChallengeConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 难度
	Difficulty int `json:"difficulty"` // 1-10

	// 有效期
	ValidDuration time.Duration `json:"valid_duration"`

	// 失败后重试次数
	MaxRetries int `json:"max_retries"`

	// 自定义脚本
	CustomScript string `json:"custom_script"`
}

// CAPTCHAConfig CAPTCHA配置
type CAPTCHAConfig struct {
	// 提供商
	Provider string `json:"provider"` // "recaptcha", "hcaptcha", "custom"

	// 站点密钥
	SiteKey string `json:"site_key"`

	// 密钥
	SecretKey string `json:"secret_key"`

	// 难度
	Difficulty string `json:"difficulty"` // "easy", "medium", "hard"

	// 有效期
	ValidDuration time.Duration `json:"valid_duration"`

	// 主题
	Theme string `json:"theme"` // "light", "dark"
}

// HoneyPotConfig 蜂蜜陷阱配置
type HoneyPotConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 陷阱路径
	Path string `json:"path"`

	// 陷阱链接
	Links []string `json:"links"`

	// 陷阱Cookie
	CookieName string `json:"cookie_name"`

	// 响应动作
	Action string `json:"action"` // "block", "log", "challenge"
}

// RateChallengeConfig 速率挑战配置
type RateChallengeConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 触发阈值
	Threshold int64 `json:"threshold"`

	// 挑战时间
	ChallengeTime time.Duration `json:"challenge_time"`

	// 冷却时间
	CooldownTime time.Duration `json:"cooldown_time"`
}

// DefenseAlertingConfig 防御告警配置
type DefenseAlertingConfig struct {
	// 启用告警
	Enabled bool `yaml:"enabled"`

	// 告警规则
	Rules []*DefenseAlertRule `yaml:"rules"`

	// 告警通道
	Channels []string `yaml:"channels"`

	// 告警聚合
	Aggregation *DefenseAlertAggregation `yaml:"aggregation"`

	// 静默配置
	Silence *SilenceConfig `json:"silence"`
}

// SilenceConfig 告警静默配置
type SilenceConfig struct {
	Enabled  bool          `json:"enabled"`
	Duration time.Duration `json:"duration"`
	Reason   string        `json:"reason"`
}

// DefenseAlertRule 防御告警规则
type DefenseAlertRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// 触发条件
	Condition *AlertCondition `json:"condition"`

	// 标签
	Labels map[string]string `json:"labels"`

	// 注释
	Annotations map[string]string `json:"annotations"`

	// 状态
	Enabled bool `json:"enabled"`

	// 严重程度
	Severity string `json:"severity"`
}

// AlertCondition 告警条件
type AlertCondition struct {
	Metric    string        `json:"metric"`
	Operator  string        `json:"operator"` // "gt", "lt", "eq"
	Threshold float64       `json:"threshold"`
	Window    time.Duration `json:"window"`
}

// DefenseAlertAggregation 防御告警聚合
type DefenseAlertAggregation struct {
	// 启用聚合
	Enabled bool `json:"enabled"`

	// 聚合窗口
	Window time.Duration `json:"window"`

	// 聚合字段
	Fields []string `json:"fields"`

	// 聚合策略
	Strategy string `json:"strategy"`

	// 阈值
	Threshold int `json:"threshold"`
}

// AutoResponseConfig 自动响应配置
type AutoResponseConfig struct {
	// 启用自动响应
	Enabled bool `yaml:"enabled"`

	// 响应规则
	Rules []*AutoResponseRule `yaml:"rules"`

	// 执行模式
	Mode string `yaml:"mode"` // "immediate", "delayed", "approver_required"

	// 审批配置
	Approval *ApprovalConfig `yaml:"approval"`

	// 回滚配置
	Rollback *RollbackConfig `yaml:"rollback"`
}

// AutoResponseRule 自动响应规则
type AutoResponseRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// 触发条件
	Trigger *TriggerCondition `json:"trigger"`

	// 响应动作
	Actions []*ResponseAction `json:"actions"`

	// 执行条件
	Conditions []*ExecutionCondition `json:"conditions"`

	// 优先级
	Priority int `json:"priority"`

	// 启用状态
	Enabled bool `json:"enabled"`

	// 描述
	Description string `json:"description"`
}

// TriggerCondition 触发条件
type TriggerCondition struct {
	Type     string        `json:"type"`     // "threat_level", "attack_type", "volume", "duration"
	Operator string        `json:"operator"` // "gt", "lt", "eq", "gte", "lte"
	Value    interface{}   `json:"value"`
	Duration time.Duration `json:"duration"`
}

// ResponseAction 响应动作
type ResponseAction struct {
	Type   string                 `json:"type"`   // "block_ip", "rate_limit", "challenge", "notify", "isolate"
	Target string                 `json:"target"` // "ip", "user", "session", "asn", "country"
	Config map[string]interface{} `json:"config"`
	Delay  time.Duration          `json:"delay"`
}

// ExecutionCondition 执行条件
type ExecutionCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// ApprovalConfig 审批配置
type ApprovalConfig struct {
	// 启用审批
	Enabled bool `json:"enabled"`

	// 审批人
	Approvers []string `json:"approvers"`

	// 审批超时
	Timeout time.Duration `json:"timeout"`

	// 自动批准条件
	AutoApproveConditions []*AutoApproveCondition `json:"auto_approve_conditions"`
}

// AutoApproveCondition 自动批准条件
type AutoApproveCondition struct {
	ThreatLevel string        `json:"threat_level"`
	MaxDuration time.Duration `json:"max_duration"`
}

// RollbackConfig 回滚配置
type RollbackConfig struct {
	// 启用回滚
	Enabled bool `json:"enabled"`

	// 回滚条件
	Conditions []*RollbackCondition `json:"conditions"`

	// 回滚时间
	After time.Duration `json:"after"`

	// 最大回滚次数
	MaxRollbacks int `json:"max_rollbacks"`
}

// RollbackCondition 回滚条件
type RollbackCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// MLDefenseConfig 机器学习防御配置
type MLDefenseConfig struct {
	// 启用ML
	Enabled bool `yaml:"enabled"`

	// 模型配置
	Models []*MLModelConfig `yaml:"models"`

	// 训练配置
	Training *TrainingConfig `yaml:"training"`

	// 推理配置
	Inference *InferenceConfig `json:"inference"`

	// 模型管理
	ModelManagement *ModelManagementConfig `yaml:"model_management"`
}

// MLModelConfig 机器学习模型配置
type MLModelConfig struct {
	Name    string `json:"name"`
	Type    string `json:"type"`    // "isolation_forest", "lstm", "autoencoder", "xgboost", "random_forest"
	Purpose string `json:"purpose"` // "anomaly_detection", "classification", "clustering"
	Version string `json:"version"`
	Path    string `json:"path"`
}

// TrainingConfig 训练配置
type TrainingConfig struct {
	// 训练间隔
	Interval time.Duration `json:"interval"`

	// 训练数据量
	DataSize int `json:"data_size"`

	// 特征选择
	Features []string `json:"features"`

	// 验证方法
	Validation string `json:"validation"` // "kfold", "holdout", "cross"

	// 评估指标
	Metrics []string `json:"metrics"` // "accuracy", "precision", "recall", "f1"
}

// InferenceConfig 推理配置
type InferenceConfig struct {
	// 批量大小
	BatchSize int `json:"batch_size"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 置信度阈值
	ConfidenceThreshold float64 `json:"confidence_threshold"`

	// 硬件加速
	HardwareAcceleration bool `json:"hardware_acceleration"`
}

// ModelManagementConfig 模型管理配置
type ModelManagementConfig struct {
	// 版本控制
	Versioning bool `json:"versioning"`

	// 自动更新
	AutoUpdate bool `json:"auto_update"`

	// 回滚策略
	RollbackStrategy string `json:"rollback_strategy"` // "previous", "best", "manual"

	// A/B测试
	ABTesting *ABTestingConfig `json:"ab_testing"`
}

// ABTestingConfig A/B测试配置
type ABTestingConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 测试组
	Groups []*TestGroup `json:"groups"`

	// 流量分配
	TrafficSplit map[string]float64 `json:"traffic_split"`

	// 测试指标
	Metrics []string `json:"metrics"`

	// 持续时间
	Duration time.Duration `json:"duration"`
}

// TestGroup 测试组
type TestGroup struct {
	Name   string  `json:"name"`
	Model  string  `json:"model"`
	Weight float64 `json:"weight"`
}

// ThreatIntelConfig 威胁情报配置
type ThreatIntelConfig struct {
	// 启用威胁情报
	Enabled bool `yaml:"enabled"`

	// 数据源
	Sources []*ThreatSource `yaml:"sources"`

	// 更新配置
	UpdateConfig *ThreatUpdateConfig `yaml:"update_config"`

	// 匹配配置
	Matching *ThreatMatchingConfig `yaml:"matching"`

	// 情报等级
	IntelligenceLevels []*IntelligenceLevel `json:"intelligence_levels"`
}

// ThreatSource 威胁源
type ThreatSource struct {
	Name string `json:"name"`
	Type string `json:"type"` // "feed", "api", "stix", "misp", "custom"

	// URL或路径
	URL string `json:"url"`

	// 认证
	Auth *ThreatAuth `json:"auth"`

	// 更新间隔
	UpdateInterval time.Duration `json:"update_interval"`

	// 格式
	Format string `json:"format"` // "stix", "json", "csv", "txt"

	// 优先级
	Priority int `json:"priority"`
}

// ThreatAuth 威胁源认证
type ThreatAuth struct {
	Type   string `json:"type"` // "none", "api_key", "oauth", "basic"
	APIKey string `json:"api_key"`
	Secret string `json:"secret"`
}

// ThreatUpdateConfig 威胁更新配置
type ThreatUpdateConfig struct {
	// 自动更新
	AutoUpdate bool `json:"auto_update"`

	// 更新间隔
	Interval time.Duration `json:"interval"`

	// 验证配置
	Verification *ThreatVerification `json:"verification"`

	// 回滚配置
	Rollback bool `json:"rollback"`
}

// ThreatVerification 威胁验证
type ThreatVerification struct {
	// 启用验证
	Enabled bool `json:"enabled"`

	// 验证方法
	Method string `json:"method"` // "signature", "heuristic", "cross_reference"

	// 信任阈值
	TrustThreshold float64 `json:"trust_threshold"`
}

// ThreatMatchingConfig 威胁匹配配置
type ThreatMatchingConfig struct {
	// 匹配类型
	Types []string `json:"types"` // "ip", "domain", "url", "hash", "email"

	// 匹配策略
	Strategy string `json:"strategy"` // "exact", "partial", "fuzzy", "cidr"

	// 缓存配置
	Cache *ThreatCacheConfig `json:"cache"`
}

// ThreatCacheConfig 威胁缓存配置
type ThreatCacheConfig struct {
	// 启用缓存
	Enabled bool `json:"enabled"`

	// 缓存大小
	Size int `json:"size"`

	// TTL
	TTL time.Duration `json:"ttl"`

	// 过期策略
	ExpirationPolicy string `json:"expiration_policy"` // "ttl", "lru", "lfu"
}

// IntelligenceLevel 情报等级
type IntelligenceLevel struct {
	Level       string   `json:"level"`
	Name        string   `json:"name"`
	TrustScore  float64  `json:"trust_score"` // 0-1
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
}

// AttackDetector 攻击检测器接口
type AttackDetector interface {
	Detect(ctx context.Context, data *DetectionData) (*DetectionResult, error)
	GetDetectorType() string
}

// AttackPreventor 攻击预防器接口
type AttackPreventor interface {
	Prevent(ctx context.Context, threat *Threat) (*PreventionResult, error)
	GetPreventorType() string
}

// DefenseAlerter 防御告警器接口
type DefenseAlerter interface {
	Send(ctx context.Context, alert *DefenseAlert) error
	GetAlerterType() string
}

// DetectionData 检测数据
type DetectionData struct {
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// DetectionResult 检测结果
type DetectionResult struct {
	Detected bool `json:"detected"`

	// 威胁信息
	Threat *Threat `json:"threat"`

	// 置信度
	Confidence float64 `json:"confidence"` // 0-1

	// 检测方法
	Method string `json:"method"`

	// 匹配签名
	MatchedSignatures []string `json:"matched_signatures"`

	// 异常分数
	AnomalyScore float64 `json:"anomaly_score"`

	// 建议动作
	RecommendedAction string `json:"recommended_action"`

	// 详情
	Details map[string]interface{} `json:"details"`
}

// Threat 威胁
type Threat struct {
	ID   string `json:"id"`
	Type string `json:"type"` // "ddos", "cc", "injection", "xss", "bot", etc.

	// 威胁级别
	Level string `json:"level"` // "low", "medium", "high", "critical"

	// 来源
	Source *ThreatSourceInfo `json:"source"`

	// 目标
	Target *ThreatTarget `json:"target"`

	// 攻击详情
	Details *ThreatDetails `json:"details"`

	// 时间
	DetectedAt time.Time `json:"detected_at"`

	// 状态
	Status string `json:"status"` // "detected", "prevented", "mitigated", "escalated"

	// 标签
	Labels map[string]string `json:"labels"`

	// 指纹
	Fingerprint string `json:"fingerprint"`

	// 关联威胁
	RelatedThreats []string `json:"related_threats"`
}

// ThreatSourceInfo 威胁来源信息
type ThreatSourceInfo struct {
	IP        string `json:"ip"`
	IPRange   string `json:"ip_range"`
	Country   string `json:"country"`
	Region    string `json:"region"`
	City      string `json:"city"`
	ISP       string `json:"isp"`
	ASN       string `json:"asn"`
	UserAgent string `json:"user_agent"`
	Referer   string `json:"referer"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
}

// ThreatTarget 威胁目标
type ThreatTarget struct {
	Type string `json:"type"` // "domain", "ip", "path", "api"
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ThreatDetails 威胁详情
type ThreatDetails struct {
	// 攻击向量
	Vector string `json:"vector"`

	// 攻击模式
	Pattern string `json:"pattern"`

	// 攻击payload
	Payload string `json:"payload"`

	// 攻击频率
	Frequency float64 `json:"frequency"`

	// 持续时间
	Duration time.Duration `json:"duration"`

	// 影响范围
	Impact string `json:"impact"`

	// 恶意指标
	Indicators []*Indicator `json:"indicators"`
}

// Indicator 指标
type Indicator struct {
	Type    string `json:"type"` // "ioc", "ioa", "ttp"
	Value   string `json:"value"`
	Context string `json:"context"`
}

// PreventionResult 预防结果
type PreventionResult struct {
	Success bool `json:"success"`

	// 采取的动作
	Actions []string `json:"actions"`

	// 阻止的请求数
	BlockedRequests int64 `json:"blocked_requests"`

	// 消耗的带宽
	BandwidthSaved int64 `json:"bandwidth_saved"` // bytes

	// 响应时间
	ResponseTime time.Duration `json:"response_time"`

	// 效果评估
	Effectiveness float64 `json:"effectiveness"` // 0-1

	// 副作用
	SideEffects []string `json:"side_effects"`

	// 建议
	Recommendations []string `json:"recommendations"`
}

// DefenseAlert 防御告警
type DefenseAlert struct {
	ID string `json:"id"`

	// 告警级别
	Severity string `json:"severity"` // "critical", "warning", "info"

	// 告警标题
	Title string `json:"title"`

	// 告警内容
	Content string `json:"content"`

	// 关联威胁
	ThreatID string `json:"threat_id"`

	// 触发条件
	Condition string `json:"condition"`

	// 状态
	Status string `json:"status"` // "firing", "resolved", "acknowledged"

	// 时间
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at"`

	// 确认信息
	AcknowledgedBy string     `json:"acknowledged_by"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`

	// 标签
	Labels map[string]string `json:"labels"`

	// 注释
	Annotations map[string]string `json:"annotations"`

	// 发送次数
	FiringCount int `json:"firing_count"`

	// 最后发送时间
	LastNotifiedAt *time.Time `json:"last_notified_at"`

	// 升级信息
	Escalation *EscalationInfo `json:"escalation"`
}

// EscalationInfo 升级信息
type EscalationInfo struct {
	Level       int       `json:"level"`
	EscalatedAt time.Time `json:"escalated_at"`
	EscalatedTo string    `json:"escalated_to"`
	Reason      string    `json:"reason"`
}

// DefenseStats 防御统计
type DefenseStats struct {
	TotalThreats     int64 `json:"total_threats"`
	DetectedThreats  int64 `json:"detected_threats"`
	PreventedThreats int64 `json:"prevented_threats"`
	MitigatedThreats int64 `json:"mitigated_threats"`
	EscalatedThreats int64 `json:"escalated_threats"`

	// 按类型统计
	ThreatsByType map[string]int64 `json:"threats_by_type"`

	// 按级别统计
	ThreatsByLevel map[string]int64 `json:"threats_by_level"`

	// 防御效果
	PreventionRate float64 `json:"prevention_rate"`
	MitigationRate float64 `json:"mitigation_rate"`

	// 性能影响
	AverageLatencyIncrease time.Duration `json:"average_latency_increase"`

	// 误报统计
	FalsePositives int64 `json:"false_positives"`

	// 漏报统计
	FalseNegatives int64 `json:"false_negatives"`

	mu sync.RWMutex
}

// NewActiveDefense 创建主动防御系统
func NewActiveDefense(config *DefenseConfig) *ActiveDefense {
	if config == nil {
		config = &DefenseConfig{
			Enabled: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ActiveDefense{
		config:     config,
		detectors:  make([]AttackDetector, 0),
		preventors: make([]AttackPreventor, 0),
		alerters:   make([]DefenseAlerter, 0),
		threats:    make([]*Threat, 0),
		stats: &DefenseStats{
			ThreatsByType:  make(map[string]int64),
			ThreatsByLevel: make(map[string]int64),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// RegisterDetector 注册检测器
func (d *ActiveDefense) RegisterDetector(detector AttackDetector) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.detectors = append(d.detectors, detector)
}

// RegisterPreventor 注册预防器
func (d *ActiveDefense) RegisterPreventor(preventor AttackPreventor) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.preventors = append(d.preventors, preventor)
}

// RegisterAlerter 注册告警器
func (d *ActiveDefense) RegisterAlerter(alerter DefenseAlerter) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.alerters = append(d.alerters, alerter)
}

// Detect 检测威胁
func (d *ActiveDefense) Detect(ctx context.Context, data *DetectionData) (*DetectionResult, error) {
	var result *DetectionResult

	for _, detector := range d.detectors {
		detection, err := detector.Detect(ctx, data)
		if err != nil {
			continue
		}

		if detection.Detected {
			result = detection
			break
		}
	}

	// 更新统计
	d.stats.mu.Lock()
	d.stats.TotalThreats++
	if result != nil && result.Threat != nil {
		d.stats.DetectedThreats++
		d.stats.ThreatsByType[result.Threat.Type]++
		d.stats.ThreatsByLevel[result.Threat.Level]++
	}
	d.stats.mu.Unlock()

	if result != nil && result.Threat != nil {
		d.recordThreat(result.Threat)
	}

	return result, nil
}

// Prevent 预防威胁
func (d *ActiveDefense) Prevent(ctx context.Context, threat *Threat) (*PreventionResult, error) {
	var result *PreventionResult

	for _, preventor := range d.preventors {
		prevention, err := preventor.Prevent(ctx, threat)
		if err != nil {
			continue
		}

		result = prevention
		break
	}

	if result == nil {
		result = &PreventionResult{Success: false}
	}

	// 更新统计
	d.stats.mu.Lock()
	if result.Success {
		d.stats.PreventedThreats++
	} else {
		d.stats.MitigatedThreats++
	}
	d.stats.mu.Unlock()

	return result, nil
}

// SendAlert 发送告警
func (d *ActiveDefense) SendAlert(ctx context.Context, alert *DefenseAlert) error {
	for _, alerter := range d.alerters {
		if err := alerter.Send(ctx, alert); err != nil {
			continue
		}
	}

	return nil
}

// ProcessThreat 处理威胁（检测+预防+告警）
func (d *ActiveDefense) ProcessThreat(ctx context.Context, data *DetectionData) (*ProcessingResult, error) {
	result := &ProcessingResult{
		StartTime: time.Now(),
	}

	// 检测威胁
	detection, err := d.Detect(ctx, data)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Detection = detection

	if detection == nil {
		result.EndTime = time.Now()
		result.Success = true
		return result, nil
	}

	if detection.Detected {
		if detection.Threat == nil {
			result.Error = "检测结果缺少威胁信息"
			return result, fmt.Errorf("%s", result.Error)
		}

		// 预防威胁
		prevention, err := d.Prevent(ctx, detection.Threat)
		if err != nil {
			result.PreventionError = err.Error()
		} else {
			result.Prevention = prevention
		}

		if detection.Threat != nil {
			if result.Prevention != nil && result.Prevention.Success {
				detection.Threat.Status = "prevented"
			} else if detection.Threat.Status == "" || detection.Threat.Status == "detected" {
				detection.Threat.Status = "mitigated"
			}
		}

		// 发送告警
		alert := &DefenseAlert{
			ID:          fmt.Sprintf("alert_%d", time.Now().UnixNano()),
			Severity:    detection.Threat.Level,
			Title:       fmt.Sprintf("检测到%s威胁", detection.Threat.Type),
			Content:     detection.Threat.Details.Pattern,
			ThreatID:    detection.Threat.ID,
			Condition:   detection.RecommendedAction,
			Status:      "firing",
			StartedAt:   time.Now(),
			FiringCount: 1,
		}

		d.SendAlert(ctx, alert)
	}

	result.EndTime = time.Now()
	result.Success = detection.Detected

	return result, nil
}

// ProcessingResult 处理结果
type ProcessingResult struct {
	Success bool `json:"success"`

	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	Detection  *DetectionResult  `json:"detection"`
	Prevention *PreventionResult `json:"prevention"`

	Error           string `json:"error"`
	PreventionError string `json:"prevention_error"`
}

// GetStats 获取统计
func (d *ActiveDefense) GetStats() *DefenseStats {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	// 计算防御率
	if d.stats.DetectedThreats > 0 {
		d.stats.PreventionRate = float64(d.stats.PreventedThreats) / float64(d.stats.DetectedThreats) * 100
	}

	return d.stats
}

func (d *ActiveDefense) recordThreat(threat *Threat) {
	if threat == nil {
		return
	}

	now := time.Now()
	if threat.ID == "" {
		threat.ID = fmt.Sprintf("threat_%d", now.UnixNano())
	}
	if threat.DetectedAt.IsZero() {
		threat.DetectedAt = now
	}
	if threat.Status == "" {
		threat.Status = "detected"
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.threats = append(d.threats, threat)
	if len(d.threats) > 5000 {
		d.threats = d.threats[len(d.threats)-5000:]
	}
}

// GetThreats 获取威胁列表
func (d *ActiveDefense) GetThreats(threatType string, level string, status string, limit int) []*Threat {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*Threat
	for i := len(d.threats) - 1; i >= 0; i-- {
		threat := d.threats[i]
		if threat == nil {
			continue
		}
		if threatType != "" && !strings.EqualFold(threat.Type, threatType) {
			continue
		}
		if level != "" && !strings.EqualFold(threat.Level, level) {
			continue
		}
		if status != "" && !strings.EqualFold(threat.Status, status) {
			continue
		}
		result = append(result, threat)
		if limit > 0 && len(result) >= limit {
			break
		}
	}

	return result
}

// GetThreatTimeline 获取威胁时间线
func (d *ActiveDefense) GetThreatTimeline(start, end time.Time, interval time.Duration) []*TimelineEntry {
	d.mu.RLock()
	threats := append([]*Threat(nil), d.threats...)
	d.mu.RUnlock()

	if len(threats) == 0 {
		return make([]*TimelineEntry, 0)
	}

	if interval <= 0 {
		interval = time.Minute
	}
	if start.IsZero() {
		for _, threat := range threats {
			if threat != nil && !threat.DetectedAt.IsZero() {
				if start.IsZero() || threat.DetectedAt.Before(start) {
					start = threat.DetectedAt
				}
			}
		}
	}
	if end.IsZero() {
		end = time.Now()
	}
	if start.IsZero() {
		start = end.Add(-interval)
	}
	if end.Before(start) {
		start, end = end, start
	}

	bucketCount := int(end.Sub(start)/interval) + 1
	if bucketCount <= 0 {
		return make([]*TimelineEntry, 0)
	}

	type bucketKey struct {
		Type  string
		Level string
	}
	counts := make([]map[bucketKey]int64, bucketCount)
	for i := 0; i < bucketCount; i++ {
		counts[i] = make(map[bucketKey]int64)
	}

	for _, threat := range threats {
		if threat == nil {
			continue
		}
		ts := threat.DetectedAt
		if ts.IsZero() {
			continue
		}
		if ts.Before(start) || ts.After(end) {
			continue
		}
		index := int(ts.Sub(start) / interval)
		if index < 0 || index >= bucketCount {
			continue
		}
		key := bucketKey{
			Type:  threat.Type,
			Level: threat.Level,
		}
		if key.Type == "" {
			key.Type = "unknown"
		}
		if key.Level == "" {
			key.Level = "unknown"
		}
		counts[index][key]++
	}

	entries := make([]*TimelineEntry, 0)
	for i := 0; i < bucketCount; i++ {
		if len(counts[i]) == 0 {
			continue
		}
		bucketTime := start.Add(time.Duration(i) * interval)
		for key, count := range counts[i] {
			entries = append(entries, &TimelineEntry{
				Timestamp: bucketTime,
				Threats:   count,
				Type:      key.Type,
				Level:     key.Level,
			})
		}
	}

	return entries
}

// TimelineEntry 时间线条目
type TimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Threats   int64     `json:"threats"`
	Type      string    `json:"type"`
	Level     string    `json:"level"`
}

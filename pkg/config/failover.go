package config

import (
	"fmt"
	"time"
)

// FailoverConfig 故障切换配置
type FailoverConfig struct {
	// 启用故障切换
	Enabled bool `yaml:"enabled"`

	// 检测配置
	Detection *FailoverDetection `yaml:"detection"`

	// 切换策略
	Switch *FailoverSwitch `yaml:"switch"`

	// 回切策略
	Rollback *FailoverRollback `yaml:"rollback"`

	// 健康检查
	HealthCheck *FailoverHealthCheck `yaml:"health_check"`

	// 告警配置
	Alert *FailoverAlert `yaml:"alert"`

	// BGP切换配置
	BGPConfig *BGPFailoverConfig `yaml:"bgp_config"`

	// 负载均衡器切换配置
	LoadBalancerConfig *LoadBalancerFailoverConfig `yaml:"loadbalancer_config"`

	// 路由表切换配置
	RouteTableConfig *RouteTableFailoverConfig `yaml:"route_table_config"`
}

// FailoverDetection 故障检测配置
type FailoverDetection struct {
	// 检测间隔
	Interval time.Duration `yaml:"interval"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 失败阈值
	FailureThreshold int `yaml:"failure_threshold"`

	// 成功阈值
	SuccessThreshold int `yaml:"success_threshold"`

	// 检测类型
	Types []string `yaml:"types"` // ["http", "tcp", "icmp", "dns"]
}

// FailoverSwitch 切换策略
type FailoverSwitch struct {
	// 切换模式
	Mode string `yaml:"mode"` // "auto", "manual"

	// 切换延迟（防止抖动）
	SwitchDelay time.Duration `yaml:"switch_delay"`

	// 最大切换次数
	MaxSwitches int `yaml:"max_switches"`

	// 切换窗口（时间）
	WindowStart string `yaml:"window_start"` // "02:00"
	WindowEnd   string `yaml:"window_end"`   // "06:00"

	// 禁止切换窗口
	ForbidSwitchWindow bool `yaml:"forbid_switch_window"`
}

// FailoverRollback 回切策略
type FailoverRollback struct {
	// 启用自动回切
	Enabled bool `yaml:"enabled"`

	// 稳定窗口
	StableWindow time.Duration `yaml:"stable_window"`

	// 抖动保护
	JitterProtection time.Duration `yaml:"jitter_protection"`

	// 最小故障时间
	MinFailureTime time.Duration `yaml:"min_failure_time"`

	// 回切延迟
	RollbackDelay time.Duration `yaml:"rollback_delay"`

	// 手动回切
	ManualRollback bool `yaml:"manual_rollback"`
}

// FailoverHealthCheck 健康检查配置
type FailoverHealthCheck struct {
	// 检查URL
	CheckURL string `yaml:"check_url"`

	// 检查方法
	Method string `yaml:"method"` // "GET", "HEAD"

	// 期望状态码
	ExpectedStatusCode int `yaml:"expected_status_code"`

	// 响应内容检查
	ResponseBody string `yaml:"response_body"`

	// 检查间隔
	Interval time.Duration `yaml:"interval"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 并发检查数
	Concurrency int `yaml:"concurrency"`

	// 健康阈值
	HealthyThreshold int `yaml:"healthy_threshold"`

	// 不健康阈值
	UnhealthyThreshold int `yaml:"unhealthy_threshold"`
}

// FailoverAlert 告警配置
type FailoverAlert struct {
	// 启用告警
	Enabled bool `yaml:"enabled"`

	// 切换告警
	SwitchAlert *SwitchAlertConfig `yaml:"switch_alert"`

	// 回切告警
	RollbackAlert *RollbackAlertConfig `yaml:"rollback_alert"`

	// 持续故障告警
	ContinuedFailureAlert *ContinuedFailureAlertConfig `yaml:"continued_failure_alert"`

	// 通知渠道
	Channels []*AlertChannel `yaml:"channels"`
}

// SwitchAlertConfig 切换告警配置
type SwitchAlertConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Message     string   `yaml:"message"`
	IncludeInfo []string `yaml:"include_info"` // ["timestamp", "reason", "old_target", "new_target"]
}

// RollbackAlertConfig 回切告警配置
type RollbackAlertConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Message     string   `yaml:"message"`
	IncludeInfo []string `yaml:"include_info"`
}

// ContinuedFailureAlertConfig 持续故障告警配置
type ContinuedFailureAlertConfig struct {
	Enabled               bool          `yaml:"enabled"`
	Interval              time.Duration `yaml:"interval"`
	FailureCountThreshold int           `yaml:"failure_count_threshold"`
}

// AlertChannel 告警渠道
type AlertChannel struct {
	Type     string `yaml:"type"` // "email", "sms", "webhook", "slack", "dingtalk"
	Endpoint string `yaml:"endpoint"`
	Token    string `yaml:"token"`
	Enabled  bool   `yaml:"enabled"`
}

// Validate 验证故障切换配置
func (c *FailoverConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// 验证检测配置
	if c.Detection == nil {
		return fmt.Errorf("检测配置不能为空")
	}
	if err := c.Detection.Validate(); err != nil {
		return err
	}

	// 验证切换策略
	if c.Switch == nil {
		return fmt.Errorf("切换策略不能为空")
	}
	if err := c.Switch.Validate(); err != nil {
		return err
	}

	// 验证回切策略
	if c.Rollback == nil {
		return fmt.Errorf("回切策略不能为空")
	}
	if err := c.Rollback.Validate(); err != nil {
		return err
	}

	// 验证健康检查配置
	if c.HealthCheck == nil {
		return fmt.Errorf("健康检查配置不能为空")
	}
	if err := c.HealthCheck.Validate(); err != nil {
		return err
	}

	// 验证告警配置
	if c.Alert == nil {
		return fmt.Errorf("告警配置不能为空")
	}

	return nil
}

// Validate 验证检测配置
func (c *FailoverDetection) Validate() error {
	if c.Interval == 0 {
		return fmt.Errorf("检测间隔不能为空")
	}

	if c.Timeout == 0 {
		return fmt.Errorf("超时时间不能为空")
	}

	if c.FailureThreshold == 0 {
		return fmt.Errorf("失败阈值不能为空")
	}

	if c.SuccessThreshold == 0 {
		return fmt.Errorf("成功阈值不能为空")
	}

	return nil
}

// Validate 验证切换策略
func (c *FailoverSwitch) Validate() error {
	if c.Mode == "" {
		return fmt.Errorf("切换模式不能为空")
	}

	validModes := map[string]bool{"auto": true, "manual": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("无效的切换模式: %s", c.Mode)
	}

	if c.MaxSwitches == 0 {
		c.MaxSwitches = 10
	}

	return nil
}

// Validate 验证回切策略
func (c *FailoverRollback) Validate() error {
	if c.StableWindow == 0 {
		c.StableWindow = 5 * time.Minute
	}

	if c.MinFailureTime == 0 {
		c.MinFailureTime = 1 * time.Minute
	}

	return nil
}

// Validate 验证健康检查配置
func (c *FailoverHealthCheck) Validate() error {
	if c.CheckURL == "" {
		return fmt.Errorf("检查URL不能为空")
	}

	if c.Method == "" {
		c.Method = "GET"
	}

	if c.Interval == 0 {
		c.Interval = 10 * time.Second
	}

	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}

	if c.ExpectedStatusCode == 0 {
		c.ExpectedStatusCode = 200
	}

	return nil
}

// BGPFailoverConfig BGP故障切换配置
type BGPFailoverConfig struct {
	// 本地ASN
	LocalASN int `yaml:"local_asn"`

	// 邻居ASN
	NeighborASN int `yaml:"neighbor_asn"`

	// 邻居IP
	NeighborIP string `yaml:"neighbor_ip"`

	// 正常前缀
	NormalPrefixes []string `yaml:"normal_prefixes"`

	// 牵引前缀
	SteeringPrefixes []string `yaml:"steering_prefixes"`

	// 公告优先级
	LocalPref int `yaml:"local_pref"`
}

// LoadBalancerFailoverConfig 负载均衡器故障切换配置
type LoadBalancerFailoverConfig struct {
	// 负载均衡器类型
	Type string `yaml:"type"` // "nginx", "haproxy", "envoy", "cloud"

	// API端点
	APIEndpoint string `yaml:"api_endpoint"`

	// API密钥
	APIToken string `yaml:"api_token"`

	// 主后端
	PrimaryBackend string `yaml:"primary_backend"`

	// 备后端
	SecondaryBackend string `yaml:"secondary_backend"`

	// 权重配置
	PrimaryWeight   int `yaml:"primary_weight"`
	SecondaryWeight int `yaml:"secondary_weight"`
}

// RouteTableFailoverConfig 路由表故障切换配置
type RouteTableFailoverConfig struct {
	// 目标网络
	Destination string `yaml:"destination"`

	// 下一跳
	Gateway string `yaml:"gateway"`

	// 接口
	Interface string `yaml:"interface"`

	// 路由表ID（云平台）
	TableID string `yaml:"table_id"`
}

package config

import (
	"fmt"
	"time"
)

// SteeringConfig 牵引配置
type SteeringConfig struct {
	// 启用牵引
	Enabled bool `yaml:"enabled"`

	// 牵引模式
	Mode string `yaml:"mode"` // "dns", "bgp", "anycast"

	// DNS牵引配置
	DNS *DNSSConfig `yaml:"dns"`

	// BGP牵引配置
	BGP *BGPConfig `yaml:"bgp"`

	// Anycast配置
	Anycast *AnycastConfig `yaml:"anycast"`

	// 触发策略
	Trigger *SteeringTriggerConfig `yaml:"trigger"`

	// 回切策略
	allback *SteeringFallbackConfig `yaml:"fallback"`

	// 牵引记录
	Records []*SteeringRecord `yaml:"records"`
}

// DNSSConfig DNS牵引配置
type DNSSConfig struct {
	// DNS服务器地址
	Provider string `yaml:"provider"` // "aliyun", "cloudflare", "route53", "dnspod"

	// Access Key/Secret
	AccessKey    string `yaml:"access_key"`
	AccessSecret string `yaml:"access_secret"`

	// 主域名
	Domain string `yaml:"domain"`

	// 正常解析记录（A记录）
	NormalRecord string `yaml:"normal_record"`

	// 牵引IP（高防IP）
	SteeringIP string `yaml:"steering_ip"`

	// TTL
	TTL int `yaml:"ttl"`

	// 记录类型
	RecordType string `yaml:"record_type"` // "A", "CNAME"
}

// BGPConfig BGP牵引配置
type BGPConfig struct {
	// 本地ASN
	LocalASN int `yaml:"local_asn"`

	// 邻居ASN
	NeighborASN int `yaml:"neighbor_asn"`

	// 邻居IP
	NeighborIP string `yaml:"neighbor_ip"`

	// 公告前缀
	Prefixes []string `yaml:"prefixes"`

	// 正常路由
	NormalPrefixes []string `yaml:"normal_prefixes"`

	// 牵引路由
	SteeringPrefixes []string `yaml:"steering_prefixes"`

	// 路由策略
	Policy string `yaml:"policy"` // "prepend", "withdraw", "community"
}

// AnycastConfig Anycast配置
type AnycastConfig struct {
	// Anycast IP
	AnycastIP string `yaml:"anycast_ip"`

	// 各个POP节点
	Pops []*AnycastPOP `yaml:"pops"`

	// 健康检查
	HealthCheck *AnycastHealthCheck `yaml:"health_check"`
}

// AnycastPOP Anycast POP节点
type AnycastPOP struct {
	Name   string `yaml:"name"`
	IP     string `yaml:"ip"`
	Weight int    `yaml:"weight"`
	Region string `yaml:"region"`
	Active bool   `yaml:"active"`
}

// AnycastHealthCheck Anycast健康检查
type AnycastHealthCheck struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

// SteeringTriggerConfig 牵引触发配置
type SteeringTriggerConfig struct {
	// 启用自动牵引
	AutoSteer bool `yaml:"auto_steer"`

	// 触发条件
	Conditions []*SteeringCondition `yaml:"conditions"`

	// 冷却时间
	Cooldown time.Duration `yaml:"cooldown"`

	// 手动牵引覆盖
	ManualOverride bool `yaml:"manual_override"`
}

// SteeringCondition 牵引触发条件
type SteeringCondition struct {
	// 条件类型
	Type string `yaml:"type"` // "bandwidth", "pps", "syn_ratio", "qps", "error_rate"

	// 阈值
	Threshold float64 `yaml:"threshold"`

	// 持续时间
	Duration time.Duration `yaml:"duration"`

	// 操作
	Action string `yaml:"action"` // "steer", "alert"

	// 优先级
	Priority int `yaml:"priority"`
}

// SteeringFallbackConfig 回切配置
type SteeringFallbackConfig struct {
	// 回切策略
	Strategy string `yaml:"strategy"` // "auto", "manual"

	// 稳定窗口
	StableWindow time.Duration `yaml:"stable_window"`

	// 抖动保护
	JitterProtection time.Duration `yaml:"jitter_protection"`

	// 最小牵引时间
	MinSteeringTime time.Duration `yaml:"min_steering_time"`

	// 自动回切
	AutoFallback bool `yaml:"auto_fallback"`

	// 回切条件
	Conditions []*SteeringCondition `yaml:"conditions"`
}

// SteeringRecord 牵引记录
type SteeringRecord struct {
	ID           string     `yaml:"id"`
	StartTime    time.Time  `yaml:"start_time"`
	EndTime      *time.Time `yaml:"end_time"`
	Mode         string     `yaml:"mode"`
	TriggerType  string     `yaml:"trigger_type"`
	TriggerValue float64    `yaml:"trigger_value"`
	Reason       string     `yaml:"reason"`
	Status       string     `yaml:"status"` // "active", "recovered", "cancelled"
}

// Validate 验证牵引配置
func (c *SteeringConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Mode == "" {
		return fmt.Errorf("牵引模式不能为空")
	}

	validModes := map[string]bool{"dns": true, "bgp": true, "anycast": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("无效的牵引模式: %s", c.Mode)
	}

	// 验证对应模式的配置
	switch c.Mode {
	case "dns":
		if c.DNS == nil {
			return fmt.Errorf("DNS牵引配置不能为空")
		}
		if err := c.DNS.Validate(); err != nil {
			return err
		}
	case "bgp":
		if c.BGP == nil {
			return fmt.Errorf("BGP牵引配置不能为空")
		}
		if err := c.BGP.Validate(); err != nil {
			return err
		}
	case "anycast":
		if c.Anycast == nil {
			return fmt.Errorf("Anycast配置不能为空")
		}
		if err := c.Anycast.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate 验证DNS配置
func (c *DNSSConfig) Validate() error {
	if c.Provider == "" {
		return fmt.Errorf("DNS服务提供商不能为空")
	}

	if c.Domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	if c.NormalRecord == "" {
		return fmt.Errorf("正常解析记录不能为空")
	}

	if c.SteeringIP == "" {
		return fmt.Errorf("牵引IP不能为空")
	}

	return nil
}

// Validate 验证BGP配置
func (c *BGPConfig) Validate() error {
	if c.LocalASN == 0 {
		return fmt.Errorf("本地ASN不能为空")
	}

	if c.NeighborASN == 0 {
		return fmt.Errorf("邻居ASN不能为空")
	}

	if c.NeighborIP == "" {
		return fmt.Errorf("邻居IP不能为空")
	}

	if len(c.Prefixes) == 0 {
		return fmt.Errorf("公告前缀不能为空")
	}

	return nil
}

// Validate 验证Anycast配置
func (c *AnycastConfig) Validate() error {
	if c.AnycastIP == "" {
		return fmt.Errorf("Anycast IP不能为空")
	}

	if len(c.Pops) == 0 {
		return fmt.Errorf("POP节点列表不能为空")
	}

	return nil
}

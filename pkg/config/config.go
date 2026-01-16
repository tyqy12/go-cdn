package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 主配置
type Config struct {
	// 服务配置
	Service *ServiceConfig `yaml:"service"`

	// 数据面配置
	DataPlane *DataPlaneConfig `yaml:"data_plane"`

	// 牵引配置
	Steering *SteeringConfig `yaml:"steering"`

	// 回注配置
	Reinjection *ReInjectionConfig `yaml:"reinjection"`

	// 源站保护配置
	OriginProtection *OriginProtectionConfig `yaml:"origin_protection"`

	// 故障切换配置
	Failover *FailoverConfig `yaml:"failover"`

	// 防护配置
	Security *SecurityConfig `yaml:"security"`

	// 监控配置
	Monitoring *MonitoringConfig `yaml:"monitoring"`
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	// 服务模式：edge, core, master
	Mode string `yaml:"mode"`

	// 节点信息
	NodeID   string `yaml:"node_id"`
	NodeName string `yaml:"node_name"`
	Region   string `yaml:"region"`

	// 监听地址
	HTTPAddr  string `yaml:"http_addr"`
	HTTPSPort int    `yaml:"https_port"`

	// Master连接（Agent模式）
	MasterAddr string `yaml:"master_addr"`
	MasterPort int    `yaml:"master_port"`
	Token      string `yaml:"token"`
}

// DataPlaneConfig 数据面配置
type DataPlaneConfig struct {
	// TLS终止模式
	TLSTerminationMode string `yaml:"tls_termination_mode"` // "edge", "pass_through"

	// 支持的协议
	SupportedProtocols []string `yaml:"supported_protocols"` // ["http1.1", "http2", "websocket", "sse"]

	// 转发模式
	ForwardMode string `yaml:"forward_mode"` // "l7_proxy", "l4_forward"

	// 挑战验证路径
	ChallengePaths *ChallengePathsConfig `yaml:"challenge_paths"`
}

// ChallengePathsConfig 挑战验证路径配置
type ChallengePathsConfig struct {
	// 启用挑战的路径（仅Web）
	EnabledPaths []string `yaml:"enabled_paths"` // ["/*.html", "/static/*"]

	// 排除挑战的路径（API、SDK等）
	ExcludedPaths []string `yaml:"excluded_paths"` // ["/api/*", "/v1/chat/*"]

	// 默认策略
	DefaultAction string `yaml:"default_action"` // "allow", "challenge", "block"
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	// Prometheus
	Prometheus *PrometheusConfig `yaml:"prometheus"`

	// 告警
	Alert *AlertConfig `yaml:"alert"`
}

// PrometheusConfig Prometheus配置
type PrometheusConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Addr     string        `yaml:"addr"`
	Port     int           `yaml:"port"`
	Path     string        `yaml:"path"`
	Interval time.Duration `yaml:"interval"`
}

// AlertConfig 告警配置
type AlertConfig struct {
	Enabled   bool            `yaml:"enabled"`
	Webhook   string          `yaml:"webhook"`
	Email     string          `yaml:"email"`
	SMTP      *SMTPConfig     `yaml:"smtp"`
	Threshold *AlertThreshold `yaml:"threshold"`
}

// SMTPConfig SMTP配置
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

// AlertThreshold 告警阈值
type AlertThreshold struct {
	BandwidthMbps  float64 `yaml:"bandwidth_mbps"`
	QPS            int     `yaml:"qps"`
	ErrorRate      float64 `yaml:"error_rate"`
	ResponseTimeMs int     `yaml:"response_time_ms"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	// JWT
	JWTSecret  string        `yaml:"jwt_secret"`
	Expiration time.Duration `yaml:"expiration"`

	// TLS
	TLS *TLSConfig `yaml:"tls"`

	// 限流
	RateLimit *RateLimitConfig `yaml:"rate_limit"`

	// 防火墙
	Firewall *FirewallConfig `yaml:"firewall"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	Enabled     bool   `yaml:"enabled"`
	CertFile    string `yaml:"cert_file"`
	KeyFile     string `yaml:"key_file"`
	MinVersion  string `yaml:"min_version"` // "TLS1.2", "TLS1.3"
	AutoGenCert bool   `yaml:"auto_gen_cert"`
	Domain      string `yaml:"domain"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxRequests int64         `yaml:"max_requests"`
	Window      time.Duration `yaml:"window"`
	Burst       int64         `yaml:"burst"`
}

// FirewallConfig 防火墙配置
type FirewallConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Blacklist    []string `yaml:"blacklist"`
	Whitelist    []string `yaml:"whitelist"`
	MaxConn      int      `yaml:"max_connections"`
	MaxConnPerIP int      `yaml:"max_connections_per_ip"`
}

// Load 加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	config := &Config{
		DataPlane: &DataPlaneConfig{
			TLSTerminationMode: "edge",
			SupportedProtocols: []string{"http1.1", "http2", "websocket", "sse"},
			ForwardMode:        "l7_proxy",
			ChallengePaths: &ChallengePathsConfig{
				EnabledPaths:  []string{"/*.html", "/static/*"},
				ExcludedPaths: []string{"/api/*", "/v1/chat/*", "/api/health"},
				DefaultAction: "allow",
			},
		},
		Service: &ServiceConfig{
			HTTPAddr:   "0.0.0.0",
			HTTPSPort:  443,
			MasterPort: 50051,
		},
		Monitoring: &MonitoringConfig{
			Prometheus: &PrometheusConfig{
				Enabled:  true,
				Addr:     "0.0.0.0",
				Port:     9090,
				Path:     "/metrics",
				Interval: 15 * time.Second,
			},
		},
		Security: &SecurityConfig{
			Expiration: 24 * time.Hour,
		},
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值
	setDefaults(config)

	return config, nil
}

// setDefaults 设置默认值
func setDefaults(config *Config) {
	if config.DataPlane.TLSTerminationMode == "" {
		config.DataPlane.TLSTerminationMode = "edge"
	}

	if len(config.DataPlane.SupportedProtocols) == 0 {
		config.DataPlane.SupportedProtocols = []string{"http1.1", "http2", "websocket", "sse"}
	}

	if config.DataPlane.ForwardMode == "" {
		config.DataPlane.ForwardMode = "l7_proxy"
	}

	if config.DataPlane.ChallengePaths == nil {
		config.DataPlane.ChallengePaths = &ChallengePathsConfig{
			EnabledPaths:  []string{"/*.html", "/static/*"},
			ExcludedPaths: []string{"/api/*", "/v1/chat/*"},
			DefaultAction: "allow",
		}
	}

	if config.Security == nil {
		config.Security = &SecurityConfig{
			Expiration: 24 * time.Hour,
		}
	}

	if config.Monitoring == nil {
		config.Monitoring = &MonitoringConfig{
			Prometheus: &PrometheusConfig{
				Enabled:  true,
				Addr:     "0.0.0.0",
				Port:     9090,
				Path:     "/metrics",
				Interval: 15 * time.Second,
			},
		}
	}
}

// Save 保存配置
func Save(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	return nil
}

// Validate 验证配置
func (c *Config) Validate() error {
	// 验证服务模式
	if c.Service.Mode == "" {
		return fmt.Errorf("服务模式不能为空")
	}

	validModes := map[string]bool{"edge": true, "core": true, "master": true}
	if !validModes[c.Service.Mode] {
		return fmt.Errorf("无效的服务模式: %s", c.Service.Mode)
	}

	// 验证数据面配置
	validTerminationModes := map[string]bool{"edge": true, "pass_through": true}
	if !validTerminationModes[c.DataPlane.TLSTerminationMode] {
		return fmt.Errorf("无效的TLS终止模式: %s", c.DataPlane.TLSTerminationMode)
	}

	// 验证牵引配置（如果启用）
	if c.Steering != nil && c.Steering.Enabled {
		if err := c.Steering.Validate(); err != nil {
			return err
		}
	}

	// 验证回注配置（如果启用）
	if c.Reinjection != nil && c.Reinjection.Enabled {
		if err := c.Reinjection.Validate(); err != nil {
			return err
		}
	}

	// 验证源站保护配置（如果启用）
	if c.OriginProtection != nil && c.OriginProtection.Enabled {
		if err := c.OriginProtection.Validate(); err != nil {
			return err
		}
	}

	// 验证故障切换配置（如果启用）
	if c.Failover != nil && c.Failover.Enabled {
		if err := c.Failover.Validate(); err != nil {
			return err
		}
	}

	return nil
}

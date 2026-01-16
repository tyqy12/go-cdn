package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config Agent完整配置
type Config struct {
	// 节点配置
	Node NodeConfig `yaml:"node"`

	// Master配置
	Master MasterConfig `yaml:"master"`

	// CDN配置
	CDN CDNConfig `yaml:"cdn"`

	// GOST配置（可选，用于隧道模式）
	GostConfigPath string              `yaml:"gost_config_path"`
	Services       []GOSTServiceConfig `yaml:"services"`
}

// NodeConfig 节点配置
type NodeConfig struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Type    string `yaml:"type"` // edge, core
	Region  string `yaml:"region"`
	IP      string `yaml:"ip"`
	Version string `yaml:"version"`
	Token   string `yaml:"token"`
}

// MasterConfig Master配置
type MasterConfig struct {
	Addr        string        `yaml:"addr"`
	TLSEnabled  bool          `yaml:"tls_enabled"`
	TLSCertFile string        `yaml:"tls_cert_file"`
	TLSKeyFile  string        `yaml:"tls_key_file"`
	TLSCAFile   string        `yaml:"tls_ca_file"`
	Insecure    bool          `yaml:"insecure"`
	Timeout     time.Duration `yaml:"timeout"`
}

// CDNConfig CDN配置
type CDNConfig struct {
	// 服务配置
	Server ServerConfig `yaml:"server"`

	// 上游配置
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	// 负载均衡配置
	LoadBalance LoadBalanceConfig `yaml:"load_balance"`

	// 健康检查配置
	HealthCheck HealthCheckConfig `yaml:"health_check"`

	// 故障转移配置
	Failover FailoverConfig `yaml:"failover"`

	// 安全防护配置
	Security SecurityConfig `yaml:"security"`

	// 路由配置
	Routes []RouteConfig `yaml:"routes"`

	// 监控配置
	Monitoring MonitoringConfig `yaml:"monitoring"`
}

// ServerConfig 服务配置
type ServerConfig struct {
	HTTPAddr    string `yaml:"http_addr"`
	HTTPSAddr   string `yaml:"https_addr"`
	Mode        string `yaml:"mode"` // debug, release
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	TLSDomain   string `yaml:"tls_domain"`
	TLSAutoGen  bool   `yaml:"tls_auto_gen"`
}

// UpstreamConfig 上游配置
type UpstreamConfig struct {
	Name       string `yaml:"name"`
	Addr       string `yaml:"addr"`
	Port       int    `yaml:"port"`
	Weight     int    `yaml:"weight"`
	Enabled    bool   `yaml:"enabled"`
	PathPrefix string `yaml:"path_prefix"`
}

// LoadBalanceConfig 负载均衡配置
type LoadBalanceConfig struct {
	Strategy      string `yaml:"strategy"` // round_robin, least_conn, ip_hash, weighted, random
	Sticky        bool   `yaml:"sticky"`
	StickyMode    string `yaml:"sticky_mode"`   // cookie, ip_hash
	StickyCookie  string `yaml:"sticky_cookie"` // GOCDN_STICKY
	StickyTimeout int    `yaml:"sticky_timeout"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Interval           int    `yaml:"interval"` // 秒
	Timeout            int    `yaml:"timeout"`  // 秒
	UnhealthyThreshold int    `yaml:"unhealthy_threshold"`
	HealthyThreshold   int    `yaml:"healthy_threshold"`
	CheckPath          string `yaml:"check_path"`
	CheckMethod        string `yaml:"check_method"`
	ExpectedCodes      []int  `yaml:"expected_codes"`
}

// FailoverConfig 故障转移配置
type FailoverConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Strategy      string `yaml:"strategy"` // primary, active_active, active_standby, weighted
	MaxRetries    int    `yaml:"max_retries"`
	SwitchTimeout int    `yaml:"switch_timeout"` // 秒
	AutoFallback  bool   `yaml:"auto_fallback"`
	StableWindow  int    `yaml:"stable_window"` // 秒
}

// SecurityConfig 安全防护配置
type SecurityConfig struct {
	// 连接保护
	GlobalMaxConnections    int `yaml:"global_max_connections"`
	GlobalMaxConnRate       int `yaml:"global_max_conn_rate"` // 每秒
	PerClientMaxConnections int `yaml:"per_client_max_connections"`
	PerClientMaxRate        int `yaml:"per_client_max_rate"`

	// 慢连接防护
	SlowConnectionThreshold int `yaml:"slow_connection_threshold"` // 秒
	SlowReadThreshold       int `yaml:"slow_read_threshold"`       // 秒
	SlowWriteThreshold      int `yaml:"slow_write_threshold"`      // 秒

	// 请求限制
	MaxHeaderSize      int64 `yaml:"max_header_size"` // 字节
	MaxHeadersCount    int   `yaml:"max_headers_count"`
	MaxRequestBodySize int64 `yaml:"max_request_body_size"` // 字节

	// 速率限制
	RateLimits []RateLimitRule `yaml:"rate_limits"`

	// IP黑白名单
	IPWhitelist []string `yaml:"ip_whitelist"`
	IPBlacklist []string `yaml:"ip_blacklist"`

	// CC防护
	CCProtection CCProtectionConfig `yaml:"cc_protection"`
}

// RateLimitRule 速率限制规则
type RateLimitRule struct {
	Name        string `yaml:"name"`
	PathPattern string `yaml:"path_pattern"`
	Threshold   int    `yaml:"threshold"` // 请求数
	Window      int    `yaml:"window"`    // 秒
	Action      string `yaml:"action"`    // limit, block
}

// CCProtectionConfig CC防护配置
type CCProtectionConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Threshold     int    `yaml:"threshold"` // QPS
	Burst         int    `yaml:"burst"`
	Action        string `yaml:"action"`         // limit, challenge, block
	ChallengeType string `yaml:"challenge_type"` // js, captcha
}

// RouteConfig 路由配置
type RouteConfig struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	MatchType   string `yaml:"match_type"` // prefix, regex, exact
	TargetPool  string `yaml:"target_pool"`
	Action      string `yaml:"action"` // allow, block, redirect
	RedirectURL string `yaml:"redirect_url"`
	Priority    int    `yaml:"priority"`
	Enabled     bool   `yaml:"enabled"`
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	Enabled         bool   `yaml:"enabled"`
	PrometheusAddr  string `yaml:"prometheus_addr"`
	PrometheusPath  string `yaml:"prometheus_path"`
	MetricsInterval int    `yaml:"metrics_interval"` // 秒
}

// GOSTServiceConfig gost 服务配置（用于隧道模式）
type GOSTServiceConfig struct {
	Name        string            `yaml:"name"`
	Network     string            `yaml:"network"` // tcp, udp
	Addr        string            `yaml:"addr"`    // 监听地址
	Type        string            `yaml:"type"`    // http, https, socks5, forward, etc.
	ForwardIP   string            `yaml:"forward_ip"`
	ForwardPort int               `yaml:"forward_port"`
	Users       map[string]string `yaml:"users"`
	TLSCert     string            `yaml:"tls_cert"`
	TLSKey      string            `yaml:"tls_key"`
	Enabled     bool              `yaml:"enabled"`
}

// Load 加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// 返回默认配置
		return DefaultConfig(), nil
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return DefaultConfig(), nil
	}

	// 设置默认值
	setDefaults(&config)

	return &config, nil
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	config := &Config{
		Node: NodeConfig{
			Type:    "edge",
			Region:  "default",
			Version: "2.0.0",
		},
		Master: MasterConfig{
			Addr:    "localhost:50051",
			Timeout: 30 * time.Second,
		},
		CDN: CDNConfig{
			Server: ServerConfig{
				HTTPAddr:  ":8080",
				HTTPSAddr: ":8443",
				Mode:      "release",
			},
			LoadBalance: LoadBalanceConfig{
				Strategy: "round_robin",
			},
			HealthCheck: HealthCheckConfig{
				Enabled:            true,
				Interval:           10,
				Timeout:            5,
				UnhealthyThreshold: 3,
				HealthyThreshold:   2,
			},
			Failover: FailoverConfig{
				Enabled:       true,
				Strategy:      "primary",
				MaxRetries:    3,
				SwitchTimeout: 30,
				AutoFallback:  true,
				StableWindow:  300,
			},
			Security: SecurityConfig{
				GlobalMaxConnections:    100000,
				GlobalMaxConnRate:       10000,
				PerClientMaxConnections: 100,
				PerClientMaxRate:        100,
				SlowConnectionThreshold: 5,
				SlowReadThreshold:       10,
				SlowWriteThreshold:      10,
				MaxHeaderSize:           8192,
				MaxHeadersCount:         100,
				MaxRequestBodySize:      10485760, // 10MB
			},
			Monitoring: MonitoringConfig{
				Enabled:         true,
				PrometheusAddr:  "0.0.0.0:9090",
				PrometheusPath:  "/metrics",
				MetricsInterval: 15,
			},
		},
	}

	setDefaults(config)
	return config
}

// setDefaults 设置默认值
func setDefaults(config *Config) {
	if config.Node.Type == "" {
		config.Node.Type = "edge"
	}
	if config.Node.Region == "" {
		config.Node.Region = "default"
	}
	if config.Node.Version == "" {
		config.Node.Version = "2.0.0"
	}

	if config.Master.Addr == "" {
		config.Master.Addr = "localhost:50051"
	}
	if config.Master.Timeout == 0 {
		config.Master.Timeout = 30 * time.Second
	}

	if config.CDN.Server.HTTPAddr == "" {
		config.CDN.Server.HTTPAddr = ":8080"
	}
	if config.CDN.Server.HTTPSAddr == "" {
		config.CDN.Server.HTTPSAddr = ":8443"
	}
	if config.CDN.Server.Mode == "" {
		config.CDN.Server.Mode = "release"
	}

	if config.CDN.LoadBalance.Strategy == "" {
		config.CDN.LoadBalance.Strategy = "round_robin"
	}
	if config.CDN.LoadBalance.StickyCookie == "" {
		config.CDN.LoadBalance.StickyCookie = "GOCDN_STICKY"
	}
	if config.CDN.LoadBalance.StickyTimeout == 0 {
		config.CDN.LoadBalance.StickyTimeout = 1800
	}

	if config.CDN.HealthCheck.Interval == 0 {
		config.CDN.HealthCheck.Interval = 10
	}
	if config.CDN.HealthCheck.Timeout == 0 {
		config.CDN.HealthCheck.Timeout = 5
	}

	if config.CDN.Failover.Strategy == "" {
		config.CDN.Failover.Strategy = "primary"
	}
	if config.CDN.Failover.SwitchTimeout == 0 {
		config.CDN.Failover.SwitchTimeout = 30
	}
	if config.CDN.Failover.StableWindow == 0 {
		config.CDN.Failover.StableWindow = 300
	}

	if config.CDN.Security.GlobalMaxConnections == 0 {
		config.CDN.Security.GlobalMaxConnections = 100000
	}
	if config.CDN.Security.GlobalMaxConnRate == 0 {
		config.CDN.Security.GlobalMaxConnRate = 10000
	}
	if config.CDN.Security.SlowConnectionThreshold == 0 {
		config.CDN.Security.SlowConnectionThreshold = 5
	}
	if config.CDN.Security.MaxHeaderSize == 0 {
		config.CDN.Security.MaxHeaderSize = 8192
	}
	if config.CDN.Security.MaxRequestBodySize == 0 {
		config.CDN.Security.MaxRequestBodySize = 10485760
	}

	if config.CDN.Monitoring.PrometheusAddr == "" {
		config.CDN.Monitoring.PrometheusAddr = "0.0.0.0:9090"
	}
	if config.CDN.Monitoring.PrometheusPath == "" {
		config.CDN.Monitoring.PrometheusPath = "/metrics"
	}
	if config.CDN.Monitoring.MetricsInterval == 0 {
		config.CDN.Monitoring.MetricsInterval = 15
	}
}

// GetGOSTServices 获取 gost 服务列表
func (c *Config) GetGOSTServices() []GOSTServiceConfig {
	services := make([]GOSTServiceConfig, 0)
	for _, svc := range c.Services {
		if svc.Enabled {
			services = append(services, svc)
		}
	}
	return services
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.Node.ID == "" {
		return fmt.Errorf("node.id is required")
	}
	if c.Node.Type != "edge" && c.Node.Type != "core" {
		return fmt.Errorf("invalid node.type: %s", c.Node.Type)
	}
	if c.Master.Addr == "" {
		return fmt.Errorf("master.addr is required")
	}
	if len(c.CDN.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	return nil
}

// ToProto 转换为proto配置
func (c *Config) ToProto() []byte {
	data, _ := yaml.Marshal(c)
	return data
}

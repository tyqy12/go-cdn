package agent

// ========== 请求响应定义 ==========

// RegisterRequest 节点注册请求
type RegisterRequest struct {
	NodeId   string            `json:"node_id"`
	NodeName string            `json:"node_name"`
	NodeType string            `json:"node_type"` // edge, core
	Region   string            `json:"region"`
	Ip       string            `json:"ip"`
	Metadata map[string]string `json:"metadata"`
	Version  string            `json:"version"` // 可选
}

// RegisterResponse 节点注册响应
type RegisterResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	MasterVersion string `json:"master_version"`
	NodeToken     string `json:"node_token"`
}

// HeartbeatRequest 心跳请求
type HeartbeatRequest struct {
	NodeId     string            `json:"node_id"`
	Timestamp  int64             `json:"timestamp"`
	Status     string            `json:"status"` // online, offline, degraded
	Attributes map[string]string `json:"attributes"`
	TLSInfo    *TLSInfo          `json:"tls_info"`
}

// HeartbeatResponse 心跳响应
type HeartbeatResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	Status       string `json:"status"`
	MasterStatus string `json:"master_status"`
}

// TLSInfo TLS信息
type TLSInfo struct {
	Version         string `json:"version"`
	Cipher          string `json:"cipher"`
	CertFingerprint string `json:"cert_fingerprint"`
}

// PushConfigRequest 配置推送请求
type PushConfigRequest struct {
	NodeId     string `json:"node_id"`
	ConfigType string `json:"config_type"` // cdn, gost, tls, security
	ConfigData []byte `json:"config_data"` // JSON/YAML数据
	Version    int64  `json:"version"`
	Checksum   string `json:"checksum"`
}

// PushConfigResponse 配置推送响应
type PushConfigResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	AppliedVersion int64  `json:"applied_version"`
}

// ConfigWatchRequest 配置监听请求
type ConfigWatchRequest struct {
	NodeId      string `json:"node_id"`
	LastVersion int64  `json:"last_version"`
	NodeType    string `json:"node_type"`
}

// ConfigWatchResponse 配置监听响应
type ConfigWatchResponse struct {
	Version     int64  `json:"version"`
	ConfigType  string `json:"config_type"`
	ConfigData  []byte `json:"config_data"`
	Checksum    string `json:"checksum"`
	Timestamp   int64  `json:"timestamp"`
	ForceReload bool   `json:"force_reload"`
	Message     string `json:"message"`
}

// CommandRequest 命令请求
type CommandRequest struct {
	CommandId string            `json:"command_id"`
	NodeId    string            `json:"node_id"`
	Command   string            `json:"command"` // reload, restart, stop, status, logs
	Params    map[string]string `json:"params"`
}

// CommandResponse 命令响应
type CommandResponse struct {
	CommandId string `json:"command_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error"`
	Timestamp int64  `json:"timestamp"`
}

// StatusRequest 状态请求
type StatusRequest struct {
	NodeId  string      `json:"node_id"`
	AgentId string      `json:"agent_id"`
	Status  *StatusData `json:"status,omitempty"` // 可选的状态数据
}

// StatusResponse 状态响应
type StatusResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Status  string      `json:"status"`         // online, offline, degraded
	Data    *StatusData `json:"data,omitempty"` // 详细数据（可选）
}

// StatusData 状态数据
type StatusData struct {
	NodeId    string `json:"node_id"`
	Status    string `json:"status"` // online, offline, degraded
	Timestamp int64  `json:"timestamp"`

	// 系统资源
	System *SystemMetrics `json:"system,omitempty"`

	// 网络指标
	Network *NetworkMetrics `json:"network,omitempty"`

	// CDN指标
	CDN *CDNMetrics `json:"cdn,omitempty"`

	// 连接指标
	Connections *ConnectionMetrics `json:"connections,omitempty"`

	// 安全指标
	Security *SecurityMetrics `json:"security,omitempty"`
}

// StatusReport 状态报告（用于节点上报）
type StatusReport struct {
	NodeId    string         `json:"node_id"`
	Timestamp int64          `json:"timestamp"`
	System    *SystemMetrics `json:"system,omitempty"`
	Network   *NetworkMetrics `json:"network,omitempty"`
	CDN       *CDNMetrics `json:"cdn,omitempty"`
	Connections *ConnectionMetrics `json:"connections,omitempty"`
	Security  *SecurityMetrics `json:"security,omitempty"`
}

// ========== 指标定义 ==========

// SystemMetrics 系统指标
type SystemMetrics struct {
	CpuUsage   float64 `json:"cpu_usage"`
	MemUsage   float64 `json:"memory_usage"`
	DiskUsage  float64 `json:"disk_usage"`
	Goroutines int     `json:"goroutines"`
	Uptime     int64   `json:"uptime"`
}

// NetworkMetrics 网络指标
type NetworkMetrics struct {
	BandwidthIn  float64 `json:"bandwidth_in"`  // Mbps
	BandwidthOut float64 `json:"bandwidth_out"` // Mbps
	BytesIn      int64   `json:"bytes_in"`
	BytesOut     int64   `json:"bytes_out"`
}

// CDNMetrics CDN指标
type CDNMetrics struct {
	Qps             float64 `json:"qps"`
	TotalRequests   int64   `json:"total_requests"`
	SuccessRequests int64   `json:"success_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	P50Latency      float64 `json:"p50_latency"` // 毫秒
	P95Latency      float64 `json:"p95_latency"`
	P99Latency      float64 `json:"p99_latency"`
}

// ConnectionMetrics 连接指标
type ConnectionMetrics struct {
	ActiveConnections int64 `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`
	ClosedConnections int64 `json:"closed_connections"`
	IdleConnections   int64 `json:"idle_connections"`
}

// SecurityMetrics 安全指标
type SecurityMetrics struct {
	BlockedConnections  int64 `json:"blocked_connections"`
	SlowConnections     int64 `json:"slow_connections"`
	RateLimitedRequests int64 `json:"rate_limited_requests"`
	CCBlocked           int64 `json:"cc_blocked"`
}

// ========== CDN配置定义 ==========

// CDNConfig CDN完整配置
type CDNConfig struct {
	// 服务配置
	Server *ServerConfig `json:"server,omitempty"`

	// 上游配置
	Upstreams []*UpstreamConfig `json:"upstreams,omitempty"`

	// 负载均衡配置
	LoadBalance *LoadBalanceConfig `json:"load_balance,omitempty"`

	// 健康检查配置
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`

	// 故障转移配置
	Failover *FailoverConfig `json:"failover,omitempty"`

	// 安全防护配置
	Security *SecurityConfig `json:"security,omitempty"`

	// 路由配置
	Routes []*RouteConfig `json:"routes,omitempty"`
}

// ServerConfig 服务配置
type ServerConfig struct {
	HttpAddr    string `json:"http_addr"`
	HttpsAddr   string `json:"https_addr"`
	Mode        string `json:"mode"` // debug, release
	TlsCertFile string `json:"tls_cert_file"`
	TlsKeyFile  string `json:"tls_key_file"`
	TlsDomain   string `json:"tls_domain"`
	TlsAutoGen  bool   `json:"tls_auto_gen"`
}

// UpstreamConfig 上游配置
type UpstreamConfig struct {
	Name       string `json:"name"`
	Addr       string `json:"addr"`
	Port       int    `json:"port"`
	Weight     int    `json:"weight"`
	Enabled    bool   `json:"enabled"`
	PathPrefix string `json:"path_prefix"`
}

// LoadBalanceConfig 负载均衡配置
type LoadBalanceConfig struct {
	Strategy      string `json:"strategy"` // round_robin, least_conn, ip_hash, weighted, random
	Sticky        bool   `json:"sticky"`
	StickyMode    string `json:"sticky_mode"`   // cookie, ip_hash
	StickyCookie  string `json:"sticky_cookie"` // GOCDN_STICKY
	StickyTimeout int    `json:"sticky_timeout"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Enabled            bool   `json:"enabled"`
	Interval           int    `json:"interval"` // 秒
	Timeout            int    `json:"timeout"`  // 秒
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	CheckPath          string `json:"check_path"`
	CheckMethod        string `json:"check_method"`
	ExpectedCodes      []int  `json:"expected_codes"`
}

// FailoverConfig 故障转移配置
type FailoverConfig struct {
	Enabled       bool   `json:"enabled"`
	Strategy      string `json:"strategy"` // primary, active_active, active_standby, weighted
	MaxRetries    int    `json:"max_retries"`
	SwitchTimeout int    `json:"switch_timeout"` // 秒
	AutoFallback  bool   `json:"auto_fallback"`
	StableWindow  int    `json:"stable_window"` // 秒
}

// SecurityConfig 安全防护配置
type SecurityConfig struct {
	// 连接保护
	GlobalMaxConnections    int `json:"global_max_connections"`
	GlobalMaxConnRate       int `json:"global_max_conn_rate"` // 每秒
	PerClientMaxConnections int `json:"per_client_max_connections"`
	PerClientMaxRate        int `json:"per_client_max_rate"`

	// 慢连接防护
	SlowConnectionThreshold int `json:"slow_connection_threshold"` // 秒
	SlowReadThreshold       int `json:"slow_read_threshold"`       // 秒
	SlowWriteThreshold      int `json:"slow_write_threshold"`      // 秒

	// 请求限制
	MaxHeaderSize      int64 `json:"max_header_size"` // 字节
	MaxHeadersCount    int   `json:"max_headers_count"`
	MaxRequestBodySize int64 `json:"max_request_body_size"` // 字节

	// 速率限制
	RateLimits []*RateLimitRule `json:"rate_limits,omitempty"`

	// IP黑白名单
	IpWhitelist []string `json:"ip_whitelist,omitempty"`
	IpBlacklist []string `json:"ip_blacklist,omitempty"`

	// CC防护
	CCProtection *CCProtectionConfig `json:"cc_protection,omitempty"`
}

// RateLimitRule 速率限制规则
type RateLimitRule struct {
	Name        string `json:"name"`
	PathPattern string `json:"path_pattern"`
	Threshold   int    `json:"threshold"` // 请求数
	Window      int    `json:"window"`    // 秒
	Action      string `json:"action"`    // limit, block
}

// CCProtectionConfig CC防护配置
type CCProtectionConfig struct {
	Enabled       bool   `json:"enabled"`
	Threshold     int    `json:"threshold"` // QPS
	Burst         int    `json:"burst"`
	Action        string `json:"action"`         // limit, challenge, block
	ChallengeType string `json:"challenge_type"` // js, captcha
}

// RouteConfig 路由配置
type RouteConfig struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	MatchType   string `json:"match_type"` // prefix, regex, exact
	TargetPool  string `json:"target_pool"`
	Action      string `json:"action"` // allow, block, redirect
	RedirectUrl string `json:"redirect_url"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

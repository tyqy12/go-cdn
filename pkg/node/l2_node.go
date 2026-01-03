package node

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// L2NodeManager L2节点管理
type L2NodeManager struct {
	config    *L2Config
	nodes     map[string]*L2Node
	clusters  map[string]*NodeCluster
	upstreams map[string]*Upstream
	health    *HealthChecker
	mu        sync.RWMutex
	stats     *L2Stats
	ctx       context.Context
	cancel    context.CancelFunc
}

// L2Config L2节点配置
type L2Config struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 默认配置
	DefaultConfig *NodeConfig `yaml:"default_config"`

	// 集群配置
	ClusterConfig *ClusterConfig `yaml:"cluster_config"`

	// 健康检查配置
	HealthCheckConfig *HealthCheckConfig `yaml:"health_check_config"`

	// 负载均衡配置
	LoadBalanceConfig *LoadBalanceConfig `yaml:"load_balance_config"`

	// 自动扩缩容配置
	AutoScaleConfig *AutoScaleConfig `yaml:"auto_scale_config"`

	// 故障转移配置
	FailoverConfig *FailoverConfig `yaml:"failover_config"`
}

// LoadBalanceConfig 负载均衡配置
type LoadBalanceConfig struct {
	Enabled  bool   `json:"enabled"`
	Strategy string `json:"strategy"` // "round_robin", "least_conn", "weighted"
}

// AutoScaleConfig 自动扩缩容配置
type AutoScaleConfig struct {
	UpperThreshold float64 `json:"upper_threshold"`
	LowerThreshold float64 `json:"lower_threshold"`
}

// FailoverConfig 故障转移配置
type FailoverConfig struct {
	Enabled          bool          `json:"enabled"`
	CheckInterval    time.Duration `json:"check_interval"`
	FailureThreshold int           `json:"failure_threshold"`
}

// NodeConfig 节点配置
type NodeConfig struct {
	// 资源限制
	CPU       *ResourceLimit  `yaml:"cpu"`
	Memory    *ResourceLimit  `yaml:"memory"`
	Disk      *ResourceLimit  `yaml:"disk"`
	Bandwidth *BandwidthLimit `yaml:"bandwidth"`

	// 网络配置
	Network *NetworkConfig `yaml:"network"`

	// 缓存配置
	Cache *CacheConfig `yaml:"cache"`

	// 安全配置
	Security *SecurityConfig `yaml:"security"`

	// 日志配置
	Logging *LoggingConfig `yaml:"logging"`
}

// ResourceLimit 资源限制
type ResourceLimit struct {
	// 最小值
	Min int `json:"min"`

	// 最大值
	Max int `json:"max"`

	// 预留
	Reserved int `json:"reserved"`

	// 单位
	Unit string `json:"unit"` // "core", "MB", "GB"
}

// BandwidthLimit 带宽限制
type BandwidthLimit struct {
	// 最大带宽 (Mbps)
	Max int `json:"max"`

	// 突发带宽 (Mbps)
	Burst int `json:"burst"`

	// 共享
	Shared bool `json:"shared"`
}

// NetworkConfig 网络配置
type NetworkConfig struct {
	// 监听地址
	ListenAddr string `json:"listen_addr"`

	// 监听端口
	Ports []int `json:"ports"`

	// 连接配置
	Connection *ConnectionConfig `json:"connection"`

	// TLS配置
	TLS *TLSConfig `json:"tls"`
}

// ConnectionConfig 连接配置
type ConnectionConfig struct {
	// 最大连接数
	MaxConnections int `json:"max_connections"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 空闲超时
	IdleTimeout time.Duration `json:"idle_timeout"`

	// 保持连接
	KeepAlive bool `json:"keep_alive"`

	// 保持连接间隔
	KeepAliveInterval time.Duration `json:"keep_alive_interval"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	// 证书路径
	CertFile string `json:"cert_file"`

	// 密钥路径
	KeyFile string `json:"key_file"`

	// CA证书
	CAFile string `json:"ca_file"`

	// 协议版本
	MinVersion string `json:"min_version"`
	MaxVersion string `json:"max_version"`

	// 密码套件
	CipherSuites []string `json:"cipher_suites"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	// 启用缓存
	Enabled bool `json:"enabled"`

	// 缓存大小 (GB)
	Size int `json:"size"`

	// 缓存路径
	Path string `json:"path"`

	// 缓存策略
	Policy string `json:"policy"` // "lru", "lfu", "fifo"

	// TTL配置
	TTL *TTLConfig `json:"ttl"`
}

// TTLConfig TTL配置
type TTLConfig struct {
	Default time.Duration `json:"default"`
	Max     time.Duration `json:"max"`
	Min     time.Duration `json:"min"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	// IP限制
	IPLimit *IPLimitConfig `json:"ip_limit"`

	// DDoS防护
	DDoS *DDoSConfig `json:"ddos"`

	// WAF配置
	WAF *WAFConfig `json:"waf"`
}

// IPLimitConfig IP限制配置
type IPLimitConfig struct {
	// 最大连接数
	MaxConnections int `json:"max_connections"`

	// 请求频率限制
	RequestRate int `json:"request_rate"`

	// 时间窗口
	Window time.Duration `json:"window"`
}

// DDoSConfig DDoS配置
type DDoSConfig struct {
	// 启用防护
	Enabled bool `json:"enabled"`

	// 清洗阈值
	CleaningThreshold int `json:"cleaning_threshold"`

	// 黑洞阈值
	BlackholeThreshold int `json:"blackhole_threshold"`
}

// WAFConfig WAF配置
type WAFConfig struct {
	// 启用WAF
	Enabled bool `json:"enabled"`

	// 规则集
	RuleSet string `json:"rule_set"`

	// 检测模式
	DetectionMode string `json:"detection_mode"` // "block", "log"
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	// 日志级别
	Level string `json:"level"`

	// 日志格式
	Format string `json:"format"` // "json", "text"

	// 输出
	Output string `json:"output"` // "file", "stdout", "syslog"

	// 日志路径
	Path string `json:"path"`

	// 保留天数
	RetentionDays int `json:"retention_days"`
}

// ClusterConfig 集群配置
type ClusterConfig struct {
	// 集群名称
	Name string `json:"name"`

	// 集群类型
	Type string `json:"type"` // "edge", "core", "l2"

	// 节点选择器
	NodeSelector map[string]string `json:"node_selector"`

	// 亲和性配置
	Affinity *AffinityConfig `json:"affinity"`

	// 拓扑配置
	Topology *TopologyConfig `json:"topology"`

	// 自动扩缩容配置
	AutoscaleConfig *AutoScaleConfig `json:"autoscale_config"`
}

// AffinityConfig 亲和性配置
type AffinityConfig struct {
	// 节点亲和性
	NodeAffinity *NodeAffinity `json:"node_affinity"`

	// Pod亲和性
	PodAffinity *PodAffinity `json:"pod_affinity"`

	// 反亲和性
	AntiAffinity *AntiAffinity `json:"anti_affinity"`
}

// NodeAffinity 节点亲和性
type NodeAffinity struct {
	// 必需
	Required []*LabelSelector `json:"required"`

	// 偏好
	Preferred []*PreferredScheduling `json:"preferred"`
}

// LabelSelector 标签选择器
type LabelSelector struct {
	MatchLabels      map[string]string  `json:"match_labels"`
	MatchExpressions []LabelRequirement `json:"match_expressions"`
}

// LabelRequirement 标签要求
type LabelRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"` // "In", "NotIn", "Exists", "DoesNotExist"
	Values   []string `json:"values"`
}

// PreferredScheduling 首选调度
type PreferredScheduling struct {
	Weight   int            `json:"weight"`
	Selector *LabelSelector `json:"selector"`
}

// PodAffinity Pod亲和性
type PodAffinity struct {
	Required  []*LabelSelector       `json:"required"`
	Preferred []*PreferredScheduling `json:"preferred"`
}

// AntiAffinity 反亲和性
type AntiAffinity struct {
	Required  []*LabelSelector       `json:"required"`
	Preferred []*PreferredScheduling `json:"preferred"`
}

// TopologyConfig 拓扑配置
type TopologyConfig struct {
	// 可用区
	AvailabilityZones []string `json:"availability_zones"`

	// 区域配置
	RegionConfig map[string]*RegionInfo `json:"region_config"`

	// 跨区域配置
	CrossRegion *CrossRegionConfig `json:"cross_region"`
}

// RegionInfo 区域信息
type RegionInfo struct {
	Name           string        `json:"name"`
	Code           string        `json:"code"`
	Endpoint       string        `json:"endpoint"`
	BackupEndpoint string        `json:"backup_endpoint"`
	Latency        time.Duration `json:"latency"`
}

// CrossRegionConfig 跨区域配置
type CrossRegionConfig struct {
	// 启用跨区域
	Enabled bool `json:"enabled"`

	// 主区域
	PrimaryRegion string `json:"primary_region"`

	// 备用区域
	BackupRegions []string `json:"backup_regions"`

	// 复制策略
	ReplicationStrategy string `json:"replication_strategy"` // "sync", "async"
}

// L2Node L2节点
type L2Node struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ClusterID string `json:"cluster_id"`

	// 状态
	Status string `json:"status"` // "online", "offline", "maintenance", "deploying"

	// 配置
	Config *NodeConfig `json:"config"`

	// 资源使用
	Resources *NodeResources `json:"resources"`

	// 指标
	Metrics *NodeMetrics `json:"metrics"`

	// 健康状态
	Health *NodeHealth `json:"health"`

	// 上游连接
	Upstreams []*UpstreamConnection `json:"upstreams"`

	// 位置
	Location *NodeLocation `json:"location"`

	// 标签
	Labels map[string]string `json:"labels"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// NodeResources 节点资源
type NodeResources struct {
	// CPU
	CPUCores int     `json:"cpu_cores"`
	CPUUsage float64 `json:"cpu_usage"`
	CPULimit float64 `json:"cpu_limit"`

	// 内存
	MemoryTotal int64 `json:"memory_total"`
	MemoryUsed  int64 `json:"memory_used"`
	MemoryLimit int64 `json:"memory_limit"`

	// 磁盘
	DiskTotal int64 `json:"disk_total"`
	DiskUsed  int64 `json:"disk_used"`
	DiskLimit int64 `json:"disk_limit"`

	// 带宽
	BandwidthIn    float64 `json:"bandwidth_in"`
	BandwidthOut   float64 `json:"bandwidth_out"`
	BandwidthLimit float64 `json:"bandwidth_limit"`

	// 连接数
	Connections      int64 `json:"connections"`
	ConnectionsLimit int64 `json:"connections_limit"`

	mu sync.RWMutex
}

// NodeMetrics 节点指标
type NodeMetrics struct {
	// QPS
	CurrentQPS float64 `json:"current_qps"`
	PeakQPS    float64 `json:"peak_qps"`

	// 延迟
	LatencyAvg float64 `json:"latency_avg"`
	LatencyP50 float64 `json:"latency_p50"`
	LatencyP99 float64 `json:"latency_p99"`

	// 错误率
	ErrorRate float64 `json:"error_rate"`

	// 命中率
	CacheHitRate float64 `json:"cache_hit_rate"`

	// 吞吐量
	Throughput float64 `json:"throughput"` // Mbps

	// 请求统计
	RequestsTotal   int64 `json:"requests_total"`
	RequestsSuccess int64 `json:"requests_success"`
	RequestsFailed  int64 `json:"requests_failed"`

	mu sync.RWMutex
}

// NodeHealth 节点健康
type NodeHealth struct {
	// 健康状态
	Status string `json:"status"` // "healthy", "degraded", "unhealthy"

	// 检查项
	Checks []*HealthCheck `json:"checks"`

	// 最后检查时间
	LastCheck time.Time `json:"last_check"`

	// 上线时间
	Uptime time.Duration `json:"uptime"`

	// 连续失败次数
	ConsecutiveFailures int `json:"consecutive_failures"`
}

// HealthCheck 健康检查
type HealthCheck struct {
	Name      string                 `json:"name"`
	Status    string                 `json:"status"` // "pass", "fail", "warn"
	Message   string                 `json:"message"`
	LastCheck time.Time              `json:"last_check"`
	Details   map[string]interface{} `json:"details"`
}

// NodeLocation 节点位置
type NodeLocation struct {
	// 区域
	Region string `json:"region"`

	// 可用区
	AvailabilityZone string `json:"availability_zone"`

	// 国家
	Country string `json:"country"`

	// 城市
	City string `json:"city"`

	// 经纬度
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	// ISP
	ISP string `json:"isp"`
}

// UpstreamConnection 上游连接
type UpstreamConnection struct {
	ID       string        `json:"id"`
	Target   string        `json:"target"`
	Port     int           `json:"port"`
	Weight   int           `json:"weight"`
	Status   string        `json:"status"` // "active", "backup", "down"
	Latency  time.Duration `json:"latency"`
	Requests int64         `json:"requests"`
	Failures int64         `json:"failures"`
}

// NodeCluster 节点集群
type NodeCluster struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // "edge", "core", "l2"

	// 配置
	Config *ClusterConfig `json:"config"`

	// 节点列表
	Nodes []*L2Node `json:"nodes"`

	// 负载均衡策略
	LoadBalanceStrategy string `json:"load_balance_strategy"`

	// 健康检查配置
	HealthCheck *HealthCheckConfig `json:"health_check"`

	// 状态
	Status string `json:"status"` // "active", "inactive", "maintenance"

	// 统计
	Stats *ClusterStats `json:"stats"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ClusterStats 集群统计
type ClusterStats struct {
	TotalNodes   int `json:"total_nodes"`
	OnlineNodes  int `json:"online_nodes"`
	OfflineNodes int `json:"offline_nodes"`

	TotalQPS       float64 `json:"total_qps"`
	TotalBandwidth float64 `json:"total_bandwidth"`
	TotalRequests  int64   `json:"total_requests"`

	AverageLatency   float64 `json:"average_latency"`
	AverageErrorRate float64 `json:"average_error_rate"`

	mu sync.RWMutex
}

// Upstream 上游配置
type Upstream struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Servers []*UpstreamServer `json:"servers"`

	// 健康检查
	HealthCheck *UpstreamHealthCheck `json:"health_check"`

	// 负载均衡
	LoadBalance *UpstreamLoadBalance `json:"load_balance"`

	// 连接池
	ConnectionPool *ConnectionPool `json:"connection_pool"`

	// 状态
	Status string `json:"status"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpstreamServer 上游服务器
type UpstreamServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	Status  string `json:"status"` // "up", "down", "backup"

	// 健康检查
	Health *ServerHealth `json:"health"`

	// 统计
	Stats *ServerStats `json:"stats"`
}

// ServerHealth 服务器健康
type ServerHealth struct {
	Status    string    `json:"status"`
	Fails     int       `json:"fails"`
	Unhealthy int       `json:"unhealthy"`
	LastCheck time.Time `json:"last_check"`
}

// ServerStats 服务器统计
type ServerStats struct {
	Requests  int64         `json:"requests"`
	Responses int64         `json:"responses"`
	Errors    int64         `json:"errors"`
	Latency   time.Duration `json:"latency"`
}

// UpstreamHealthCheck 上游健康检查
type UpstreamHealthCheck struct {
	Enabled  bool          `json:"enabled"`
	Type     string        `json:"type"` // "http", "tcp", "grpc"
	Path     string        `json:"path"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Retries  int           `json:"retries"`
}

// UpstreamLoadBalance 上游负载均衡
type UpstreamLoadBalance struct {
	Method string `json:"method"` // "round_robin", "least_conn", "ip_hash", "weighted"
	Hash   string `json:"hash"`   // "source_ip", "uri"
}

// ConnectionPool 连接池
type ConnectionPool struct {
	// 连接池大小
	Size int `json:"size"`

	// 最大连接数
	MaxSize int `json:"max_size"`

	// 空闲连接超时
	IdleTimeout time.Duration `json:"idle_timeout"`

	// 连接超时
	ConnectTimeout time.Duration `json:"connect_timeout"`

	// 最大请求数
	MaxRequests int `json:"max_requests"`

	// 最大重试次数
	MaxRetries int `json:"max_retries"`
}

// HealthChecker 健康检查器
type HealthChecker struct {
	config *HealthCheckConfig
	mu     sync.RWMutex
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 检查类型
	Type string `json:"type"` // "http", "tcp", "grpc", "icmp"

	// 检查路径
	Path string `json:"path"`

	// 检查端口
	Port int `json:"port"`

	// 检查间隔
	Interval time.Duration `json:"interval"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 不健康阈值
	UnhealthyThreshold int `json:"unhealthy_threshold"`

	// 健康阈值
	HealthyThreshold int `json:"healthy_threshold"`

	// 响应期望
	ExpectedStatus int    `json:"expected_status"`
	ExpectedBody   string `json:"expected_body"`
}

// L2Stats L2节点统计
type L2Stats struct {
	TotalNodes       int `json:"total_nodes"`
	OnlineNodes      int `json:"online_nodes"`
	OfflineNodes     int `json:"offline_nodes"`
	MaintenanceNodes int `json:"maintenance_nodes"`

	TotalClusters  int `json:"total_clusters"`
	ActiveClusters int `json:"active_clusters"`

	TotalUpstreams int `json:"total_upstreams"`

	TotalRequests int64   `json:"total_requests"`
	TotalQPS      float64 `json:"total_qps"`

	AverageLatency float64 `json:"average_latency"`

	mu sync.RWMutex
}

// NewL2NodeManager 创建L2节点管理器
func NewL2NodeManager(config *L2Config) *L2NodeManager {
	if config == nil {
		config = &L2Config{
			Enabled: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &L2NodeManager{
		config:    config,
		nodes:     make(map[string]*L2Node),
		clusters:  make(map[string]*NodeCluster),
		upstreams: make(map[string]*Upstream),
		health:    &HealthChecker{},
		stats:     &L2Stats{},
		ctx:       ctx,
		cancel:    cancel,
	}
}

// AddNode 添加节点
func (m *L2NodeManager) AddNode(node *L2Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if node == nil || node.ID == "" {
		return fmt.Errorf("节点信息不能为空")
	}
	if _, exists := m.nodes[node.ID]; exists {
		return fmt.Errorf("节点已存在: %s", node.ID)
	}

	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()
	if node.LastSeen.IsZero() {
		node.LastSeen = node.UpdatedAt
	}
	if node.Status == "" {
		node.Status = "online"
	}
	if node.Config == nil && m.config.DefaultConfig != nil {
		node.Config = m.config.DefaultConfig
	}

	m.nodes[node.ID] = node

	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()
	m.stats.TotalNodes++
	switch node.Status {
	case "online":
		m.stats.OnlineNodes++
	case "offline":
		m.stats.OfflineNodes++
	case "maintenance":
		m.stats.MaintenanceNodes++
	}

	return nil
}

// GetNode 获取节点
func (m *L2NodeManager) GetNode(nodeID string) (*L2Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("节点不存在: %s", nodeID)
	}

	return node, nil
}

// ListNodes 列出节点
func (m *L2NodeManager) ListNodes(clusterID string, status string) []*L2Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodes []*L2Node
	for _, node := range m.nodes {
		if clusterID != "" && node.ClusterID != clusterID {
			continue
		}
		if status != "" && node.Status != status {
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes
}

// UpdateNodeStatus 更新节点状态
func (m *L2NodeManager) UpdateNodeStatus(nodeID string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		return fmt.Errorf("节点不存在: %s", nodeID)
	}

	if status == "" {
		return fmt.Errorf("节点状态不能为空")
	}

	prevStatus := node.Status
	node.Status = status
	node.UpdatedAt = time.Now()
	node.LastSeen = time.Now()

	// 更新统计
	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()
	m.adjustStatusCounters(prevStatus, status)

	if node.ClusterID != "" {
		if cluster, exists := m.clusters[node.ClusterID]; exists && cluster.Stats != nil {
			cluster.Stats.mu.Lock()
			defer cluster.Stats.mu.Unlock()
			adjustClusterStatusCounters(cluster.Stats, prevStatus, status)
		}
	}

	return nil
}

func (m *L2NodeManager) adjustStatusCounters(prevStatus, status string) {
	if prevStatus == status {
		return
	}

	switch prevStatus {
	case "online":
		if m.stats.OnlineNodes > 0 {
			m.stats.OnlineNodes--
		}
	case "offline":
		if m.stats.OfflineNodes > 0 {
			m.stats.OfflineNodes--
		}
	case "maintenance":
		if m.stats.MaintenanceNodes > 0 {
			m.stats.MaintenanceNodes--
		}
	}

	switch status {
	case "online":
		m.stats.OnlineNodes++
	case "offline":
		m.stats.OfflineNodes++
	case "maintenance":
		m.stats.MaintenanceNodes++
	}
}

func adjustClusterStatusCounters(stats *ClusterStats, prevStatus, status string) {
	if stats == nil || prevStatus == status {
		return
	}

	switch prevStatus {
	case "online":
		if stats.OnlineNodes > 0 {
			stats.OnlineNodes--
		}
	case "offline":
		if stats.OfflineNodes > 0 {
			stats.OfflineNodes--
		}
	}

	switch status {
	case "online":
		stats.OnlineNodes++
	case "offline":
		stats.OfflineNodes++
	}
}

// UpdateNodeMetrics 更新节点指标
func (m *L2NodeManager) UpdateNodeMetrics(nodeID string, metrics *NodeMetrics) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, ok := m.nodes[nodeID]

	if !ok {
		return fmt.Errorf("节点不存在: %s", nodeID)
	}

	node.Metrics = metrics
	node.LastSeen = time.Now()

	return nil
}

// CreateCluster 创建集群
func (m *L2NodeManager) CreateCluster(cluster *NodeCluster) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cluster == nil || cluster.ID == "" {
		return fmt.Errorf("集群信息不能为空")
	}
	if _, exists := m.clusters[cluster.ID]; exists {
		return fmt.Errorf("集群已存在: %s", cluster.ID)
	}

	cluster.CreatedAt = time.Now()
	cluster.UpdatedAt = time.Now()
	cluster.Stats = &ClusterStats{}

	m.clusters[cluster.ID] = cluster

	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()
	m.stats.TotalClusters++
	m.stats.ActiveClusters++

	return nil
}

// AddNodeToCluster 将节点添加到集群
func (m *L2NodeManager) AddNodeToCluster(clusterID, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cluster, ok := m.clusters[clusterID]
	if !ok {
		return fmt.Errorf("集群不存在: %s", clusterID)
	}

	node, ok := m.nodes[nodeID]
	if !ok {
		return fmt.Errorf("节点不存在: %s", nodeID)
	}

	for _, existing := range cluster.Nodes {
		if existing != nil && existing.ID == nodeID {
			return fmt.Errorf("节点已在集群中: %s", nodeID)
		}
	}

	node.ClusterID = clusterID
	cluster.Nodes = append(cluster.Nodes, node)

	if cluster.Stats == nil {
		cluster.Stats = &ClusterStats{}
	}
	cluster.Stats.mu.Lock()
	defer cluster.Stats.mu.Unlock()
	cluster.Stats.TotalNodes++
	switch node.Status {
	case "online":
		cluster.Stats.OnlineNodes++
	case "offline":
		cluster.Stats.OfflineNodes++
	}

	return nil
}

// GetCluster 获取集群
func (m *L2NodeManager) GetCluster(clusterID string) (*NodeCluster, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cluster, ok := m.clusters[clusterID]
	if !ok {
		return nil, fmt.Errorf("集群不存在: %s", clusterID)
	}

	return cluster, nil
}

// ListClusters 列出集群
func (m *L2NodeManager) ListClusters(status string) []*NodeCluster {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var clusters []*NodeCluster
	for _, cluster := range m.clusters {
		if status != "" && cluster.Status != status {
			continue
		}
		clusters = append(clusters, cluster)
	}

	return clusters
}

// CreateUpstream 创建上游配置
func (m *L2NodeManager) CreateUpstream(upstream *Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if upstream == nil || upstream.ID == "" {
		return fmt.Errorf("上游配置不能为空")
	}
	if _, exists := m.upstreams[upstream.ID]; exists {
		return fmt.Errorf("上游配置已存在: %s", upstream.ID)
	}

	upstream.CreatedAt = time.Now()
	upstream.UpdatedAt = time.Now()

	m.upstreams[upstream.ID] = upstream

	m.stats.mu.Lock()
	defer m.stats.mu.Unlock()
	m.stats.TotalUpstreams++

	return nil
}

// GetUpstream 获取上游配置
func (m *L2NodeManager) GetUpstream(upstreamID string) (*Upstream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	upstream, ok := m.upstreams[upstreamID]
	if !ok {
		return nil, fmt.Errorf("上游配置不存在: %s", upstreamID)
	}

	return upstream, nil
}

// GetStats 获取统计
func (m *L2NodeManager) GetStats() *L2Stats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return m.stats
}

// HealthCheckNode 健康检查节点
func (m *L2NodeManager) HealthCheckNode(nodeID string) *HealthCheckResult {
	m.mu.Lock()
	node, ok := m.nodes[nodeID]
	if !ok {
		m.mu.Unlock()
		return &HealthCheckResult{
			Success: false,
			Error:   fmt.Sprintf("节点不存在: %s", nodeID),
		}
	}

	now := time.Now()
	checks := make([]*HealthCheck, 0)
	hasFailure := false
	hasWarning := false

	statusCheck := &HealthCheck{
		Name:      "status",
		LastCheck: now,
	}
	if node.Status == "online" {
		statusCheck.Status = "pass"
	} else {
		statusCheck.Status = "fail"
		statusCheck.Message = fmt.Sprintf("节点状态异常: %s", node.Status)
		hasFailure = true
	}
	checks = append(checks, statusCheck)

	timeout := 30 * time.Second
	if m.config != nil && m.config.HealthCheckConfig != nil && m.config.HealthCheckConfig.Timeout > 0 {
		timeout = m.config.HealthCheckConfig.Timeout
	}
	if !node.LastSeen.IsZero() && time.Since(node.LastSeen) > timeout {
		checks = append(checks, &HealthCheck{
			Name:      "heartbeat",
			Status:    "fail",
			Message:   "节点心跳超时",
			LastCheck: now,
			Details: map[string]interface{}{
				"last_seen": node.LastSeen,
			},
		})
		hasFailure = true
	} else {
		checks = append(checks, &HealthCheck{
			Name:      "heartbeat",
			Status:    "pass",
			LastCheck: now,
		})
	}

	if node.Metrics != nil {
		metricsCheck := &HealthCheck{
			Name:      "metrics",
			Status:    "pass",
			LastCheck: now,
		}
		if node.Metrics.ErrorRate >= 0.2 {
			metricsCheck.Status = "fail"
			metricsCheck.Message = "错误率过高"
			hasFailure = true
		} else if node.Metrics.ErrorRate >= 0.1 {
			metricsCheck.Status = "warn"
			metricsCheck.Message = "错误率偏高"
			hasWarning = true
		}
		if node.Metrics.LatencyAvg >= 500 {
			metricsCheck.Status = "fail"
			metricsCheck.Message = "平均延迟过高"
			hasFailure = true
		} else if node.Metrics.LatencyAvg >= 200 {
			metricsCheck.Status = "warn"
			metricsCheck.Message = "平均延迟偏高"
			hasWarning = true
		}
		checks = append(checks, metricsCheck)
	}

	if node.Resources != nil {
		resourceCheck := &HealthCheck{
			Name:      "resources",
			Status:    "pass",
			LastCheck: now,
		}
		if node.Resources.CPULimit > 0 && node.Resources.CPUUsage > node.Resources.CPULimit {
			resourceCheck.Status = "fail"
			resourceCheck.Message = "CPU超过限制"
			hasFailure = true
		} else if node.Resources.CPUUsage >= 0.9 {
			resourceCheck.Status = "warn"
			resourceCheck.Message = "CPU使用率偏高"
			hasWarning = true
		}
		checks = append(checks, resourceCheck)
	}

	if node.Health == nil {
		node.Health = &NodeHealth{}
	}
	node.Health.Checks = checks
	node.Health.LastCheck = now
	if node.CreatedAt.IsZero() {
		node.Health.Uptime = 0
	} else {
		node.Health.Uptime = now.Sub(node.CreatedAt)
	}

	if hasFailure {
		node.Health.Status = "unhealthy"
		node.Health.ConsecutiveFailures++
	} else if hasWarning {
		node.Health.Status = "degraded"
		node.Health.ConsecutiveFailures = 0
	} else {
		node.Health.Status = "healthy"
		node.Health.ConsecutiveFailures = 0
	}
	node.LastSeen = now
	m.mu.Unlock()

	return &HealthCheckResult{
		Success: !hasFailure,
		Checks:  checks,
	}
}

// HealthCheckResult 健康检查结果
type HealthCheckResult struct {
	Success bool           `json:"success"`
	Error   string         `json:"error"`
	Checks  []*HealthCheck `json:"checks"`
}

// AutoScale 自动扩缩容
func (m *L2NodeManager) AutoScale(clusterID string) error {
	cluster, err := m.GetCluster(clusterID)
	if err != nil {
		return err
	}

	if m.config.AutoScaleConfig == nil {
		return nil
	}
	if cluster.Config == nil || cluster.Config.AutoscaleConfig == nil {
		return nil
	}

	// 检查是否需要扩容
	if cluster.Stats.TotalQPS > cluster.Config.AutoscaleConfig.UpperThreshold {
		// 扩容
		return m.ScaleOut(clusterID, 1)
	}

	// 检查是否需要缩容
	if cluster.Stats.TotalQPS < cluster.Config.AutoscaleConfig.LowerThreshold {
		// 缩容
		return m.ScaleIn(clusterID, 1)
	}

	return nil
}

// ScaleOut 扩容
func (m *L2NodeManager) ScaleOut(clusterID string, count int) error {
	if count <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cluster, ok := m.clusters[clusterID]
	if !ok {
		return fmt.Errorf("集群不存在: %s", clusterID)
	}

	now := time.Now()
	for i := 0; i < count; i++ {
		nodeID := fmt.Sprintf("%s-%d-%d", clusterID, now.UnixNano(), i)
		for {
			if _, exists := m.nodes[nodeID]; !exists {
				break
			}
			nodeID = fmt.Sprintf("%s-%d-%d", clusterID, time.Now().UnixNano(), i)
		}

		node := &L2Node{
			ID:        nodeID,
			Name:      nodeID,
			ClusterID: clusterID,
			Status:    "online",
			Config:    m.config.DefaultConfig,
			Health: &NodeHealth{
				Status:    "healthy",
				LastCheck: now,
			},
			CreatedAt: now,
			UpdatedAt: now,
			LastSeen:  now,
		}

		m.nodes[nodeID] = node
		cluster.Nodes = append(cluster.Nodes, node)

		m.stats.mu.Lock()
		m.stats.TotalNodes++
		m.stats.OnlineNodes++
		m.stats.mu.Unlock()

		if cluster.Stats != nil {
			cluster.Stats.mu.Lock()
			cluster.Stats.TotalNodes++
			cluster.Stats.OnlineNodes++
			cluster.Stats.mu.Unlock()
		}
	}

	return nil
}

// ScaleIn 缩容
func (m *L2NodeManager) ScaleIn(clusterID string, count int) error {
	if count <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cluster, ok := m.clusters[clusterID]
	if !ok {
		return fmt.Errorf("集群不存在: %s", clusterID)
	}

	candidates := selectScaleInCandidates(cluster.Nodes, count)
	if len(candidates) == 0 {
		return nil
	}

	for _, node := range candidates {
		if node == nil {
			continue
		}
		delete(m.nodes, node.ID)
		cluster.Nodes = removeNodeFromCluster(cluster.Nodes, node.ID)

		m.stats.mu.Lock()
		m.stats.TotalNodes--
		switch node.Status {
		case "online":
			if m.stats.OnlineNodes > 0 {
				m.stats.OnlineNodes--
			}
		case "offline":
			if m.stats.OfflineNodes > 0 {
				m.stats.OfflineNodes--
			}
		case "maintenance":
			if m.stats.MaintenanceNodes > 0 {
				m.stats.MaintenanceNodes--
			}
		}
		m.stats.mu.Unlock()

		if cluster.Stats != nil {
			cluster.Stats.mu.Lock()
			cluster.Stats.TotalNodes--
			switch node.Status {
			case "online":
				if cluster.Stats.OnlineNodes > 0 {
					cluster.Stats.OnlineNodes--
				}
			case "offline":
				if cluster.Stats.OfflineNodes > 0 {
					cluster.Stats.OfflineNodes--
				}
			}
			cluster.Stats.mu.Unlock()
		}
	}

	return nil
}

// Failover 故障转移
func (m *L2NodeManager) Failover(nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		return fmt.Errorf("节点不存在: %s", nodeID)
	}
	if node.ClusterID == "" {
		return fmt.Errorf("节点未绑定集群: %s", nodeID)
	}

	cluster, ok := m.clusters[node.ClusterID]
	if !ok {
		return fmt.Errorf("集群不存在: %s", node.ClusterID)
	}

	target := selectFailoverTarget(cluster.Nodes, nodeID)
	if target == nil {
		return fmt.Errorf("未找到可用故障转移节点")
	}

	prevStatus := node.Status
	node.Status = "offline"
	node.UpdatedAt = time.Now()
	node.LastSeen = time.Now()
	if node.Health != nil {
		node.Health.Status = "unhealthy"
	}

	targetPrev := target.Status
	target.Status = "online"
	target.UpdatedAt = time.Now()
	target.LastSeen = time.Now()

	m.stats.mu.Lock()
	m.adjustStatusCounters(prevStatus, node.Status)
	m.adjustStatusCounters(targetPrev, target.Status)
	m.stats.mu.Unlock()

	if cluster.Stats != nil {
		cluster.Stats.mu.Lock()
		adjustClusterStatusCounters(cluster.Stats, prevStatus, node.Status)
		adjustClusterStatusCounters(cluster.Stats, targetPrev, target.Status)
		cluster.Stats.mu.Unlock()
	}

	return nil
}

func selectScaleInCandidates(nodes []*L2Node, count int) []*L2Node {
	if count <= 0 || len(nodes) == 0 {
		return nil
	}

	selected := make([]*L2Node, 0, count)
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Status == "offline" || node.Status == "maintenance" {
			selected = append(selected, node)
			if len(selected) >= count {
				return selected
			}
		}
	}

	for len(selected) < count {
		var candidate *L2Node
		var candidateLoad float64 = -1
		for _, node := range nodes {
			if node == nil || containsNode(selected, node.ID) {
				continue
			}
			load := 0.0
			if node.Metrics != nil {
				load = node.Metrics.CurrentQPS
			}
			if candidate == nil || load < candidateLoad || candidateLoad < 0 {
				candidate = node
				candidateLoad = load
			}
		}
		if candidate == nil {
			break
		}
		selected = append(selected, candidate)
	}

	return selected
}

func selectFailoverTarget(nodes []*L2Node, sourceID string) *L2Node {
	var target *L2Node
	bestScore := -1.0

	for _, node := range nodes {
		if node == nil || node.ID == sourceID {
			continue
		}
		if node.Status != "online" {
			continue
		}
		score := 1.0
		if node.Metrics != nil {
			score = (1 - node.Metrics.ErrorRate)
			if node.Metrics.LatencyAvg > 0 {
				score -= node.Metrics.LatencyAvg / 1000.0
			}
		}
		if score > bestScore {
			bestScore = score
			target = node
		}
	}

	return target
}

func removeNodeFromCluster(nodes []*L2Node, nodeID string) []*L2Node {
	if len(nodes) == 0 {
		return nodes
	}
	out := nodes[:0]
	for _, node := range nodes {
		if node == nil || node.ID == nodeID {
			continue
		}
		out = append(out, node)
	}
	return out
}

func containsNode(nodes []*L2Node, nodeID string) bool {
	for _, node := range nodes {
		if node != nil && node.ID == nodeID {
			return true
		}
	}
	return false
}

// GetClusterMetrics 获取集群指标
func (m *L2NodeManager) GetClusterMetrics(clusterID string) *ClusterMetrics {
	cluster, err := m.GetCluster(clusterID)
	if err != nil {
		return nil
	}
	if cluster.Stats == nil {
		return &ClusterMetrics{
			TotalNodes:  0,
			OnlineNodes: 0,
			TotalQPS:    0,
			Latency:     0,
			ErrorRate:   0,
		}
	}

	return &ClusterMetrics{
		TotalNodes:  cluster.Stats.TotalNodes,
		OnlineNodes: cluster.Stats.OnlineNodes,
		TotalQPS:    cluster.Stats.TotalQPS,
		Latency:     cluster.Stats.AverageLatency,
		ErrorRate:   cluster.Stats.AverageErrorRate,
	}
}

// ClusterMetrics 集群指标
type ClusterMetrics struct {
	TotalNodes  int     `json:"total_nodes"`
	OnlineNodes int     `json:"online_nodes"`
	TotalQPS    float64 `json:"total_qps"`
	Latency     float64 `json:"latency"`
	ErrorRate   float64 `json:"error_rate"`
}

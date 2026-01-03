package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// SmartDNS 智能DNS系统 - 独立DNS服务
type SmartDNS struct {
	config    *SmartDNSConfig
	zones     map[string]*DNSZone
	records   map[string][]*SmartDNSRecord
	resolvers []DNSResolver
	scheduler *NodeScheduler
	geoIP     *GeoIPLib
	mu        sync.RWMutex
	stats     *SmartDNSStats
	ctx       context.Context
	cancel    context.CancelFunc
}

// SmartDNSConfig 智能DNS配置
type SmartDNSConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 监听配置
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"` // 默认53

	// DNS协议
	Protocols []string `yaml:"protocols"` // "udp", "tcp", "dns-over-tls", "dns-over-https"

	// 缓存配置
	Cache *DNSCacheConfig `yaml:"cache"`

	// 调度配置
	Scheduling *DNSSchedulingConfig `yaml:"scheduling"`

	// 安全配置
	Security *DNSSecurityConfig `yaml:"security"`

	// 区域配置
	Zones []*DNSZoneConfig `yaml:"zones"`

	// 解析器配置
	Resolvers []*ResolverConfig `yaml:"resolvers"`

	// 防御配置
	Defense *DNSDefenseConfig `yaml:"defense"`
}

// DNSZoneConfig 区域配置
type DNSZoneConfig struct {
	Name    string            `yaml:"name"`
	Type    string            `yaml:"type"` // "master", "slave"
	Records []*SmartDNSRecord `yaml:"records"`
}

// DNSCacheConfig DNS缓存配置
type DNSCacheConfig struct {
	// 启用缓存
	Enabled bool `yaml:"enabled"`

	// 缓存大小
	Size int `yaml:"size"` // 条目数

	// TTL配置
	MinTTL time.Duration `yaml:"min_ttl"`
	MaxTTL time.Duration `yaml:"max_ttl"`

	// 负缓存
	NegativeCache bool `yaml:"negative_cache"`

	// 负缓存TTL
	NegativeTTL time.Duration `yaml:"negative_ttl"`
}

// DNSSchedulingConfig DNS调度配置
type DNSSchedulingConfig struct {
	// 调度策略
	Strategy string `yaml:"strategy"` // "geo", "latency", "load", "health", "smart"

	// 节点状态检测
	NodeHealthCheck *SmartHealthCheckConfig `yaml:"node_health_check"`

	// 延迟测量
	LatencyConfig *LatencyConfig `yaml:"latency_config"`

	// 负载均衡配置
	LoadBalance *SmartLoadBalanceConfig `yaml:"load_balance"`

	// 故障转移配置
	Failover *SmartFailoverConfig `yaml:"failover"`

	// 假墙防御
	GFWDefense *GFWDefenseConfig `yaml:"gfw_defense"`
}

// SmartHealthCheckConfig 健康检查配置
type SmartHealthCheckConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 检查间隔
	Interval time.Duration `yaml:"interval"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 不健康阈值
	UnhealthyThreshold int `yaml:"unhealthy_threshold"`

	// 健康阈值
	HealthyThreshold int `yaml:"healthy_threshold"`

	// 检查类型
	Type string `yaml:"type"` // "tcp", "http", "ping"

	// 检查端点
	Endpoints []string `yaml:"endpoints"`
}

// LatencyConfig 延迟配置
type LatencyConfig struct {
	// 启用延迟测量
	Enabled bool `yaml:"enabled"`

	// 测量间隔
	Interval time.Duration `yaml:"interval"`

	// 测量超时
	Timeout time.Duration `yaml:"timeout"`

	// 采样数
	SampleCount int `yaml:"sample_count"`

	// 平滑窗口
	SmoothWindow int `yaml:"smooth_window"`
}

// SmartLoadBalanceConfig 负载均衡配置
type SmartLoadBalanceConfig struct {
	// 算法
	Algorithm string `yaml:"algorithm"` // "round_robin", "least_latency", "weighted", "consistent_hash"

	// 权重
	Weights map[string]int `yaml:"weights"`

	// 最大连接数限制
	MaxConnections map[string]int64 `yaml:"max_connections"`

	// 流量限制
	RateLimit map[string]int64 `yaml:"rate_limit"` // per second
}

// SmartFailoverConfig 故障转移配置
type SmartFailoverConfig struct {
	// 启用故障转移
	Enabled bool `yaml:"enabled"`

	// 检测间隔
	Interval time.Duration `yaml:"interval"`

	// 故障阈值
	FailureThreshold int `yaml:"failure_threshold"`

	// 恢复阈值
	RecoveryThreshold int `yaml:"recovery_threshold"`

	// 切换时间
	SwitchoverTime time.Duration `yaml:"switchover_time"`

	// 备用节点
	BackupNodes []string `yaml:"backup_nodes"`
}

// GFWDefenseConfig 假墙防御配置
type GFWDefenseConfig struct {
	// 启用防御
	Enabled bool `yaml:"enabled"`

	// 检测模式
	DetectionMode string `yaml:"detection_mode"` // "passive", "active", "hybrid"

	// IP列表
	GFWIPList []string `yaml:"gfw_ip_list"`

	// 域名检测
	DomainDetection bool `yaml:"domain_detection"`

	// 响应策略
	ResponseStrategy string `yaml:"response_strategy"` // "return_backup", "return_empty", "return_404"

	// 备用IP列表
	BackupIPs []string `yaml:"backup_ips"`

	// 自动切换
	AutoSwitch bool `yaml:"auto_switch"`

	// 切换阈值
	SwitchThreshold float64 `yaml:"switch_threshold"` // 成功率低于此值时切换
}

// DNSSecurityConfig DNS安全配置
type DNSSecurityConfig struct {
	// DNSSEC
	DNSSEC *DNSSECConfig `yaml:"dnssec"`

	// 限速
	RateLimit *DNSRateLimitConfig `yaml:"rate_limit"`

	// IP过滤
	IPFilter *DNSIPFilterConfig `yaml:"ip_filter"`

	// 域名过滤
	DomainFilter *DNSDomainFilterConfig `yaml:"domain_filter"`

	// 反弹攻击防护
	ReflectionProtection bool `yaml:"reflection_protection"`

	// 放大攻击防护
	AmplificationProtection bool `yaml:"amplification_protection"`
}

// DNSSECConfig DNSSEC配置
type DNSSECConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 密钥类型
	KeyType string `yaml:"key_type"` // "RSASHA256", "ECDSAP256SHA256", "ECDSAP384SHA384"

	// 密钥轮转
	KeyRotation *KeyRotationConfig `yaml:"key_rotation"`

	// ZSK密钥
	ZSK *KeyConfig `yaml:"zsk"`

	// KSK密钥
	KSK *KeyConfig `yaml:"ksk"`
}

// KeyRotationConfig 密钥轮转配置
type KeyRotationConfig struct {
	// 启用
	Enabled bool `yaml:"enabled"`

	// 轮转周期
	Interval time.Duration `yaml:"interval"`

	// 提前天数
	AdvanceDays int `yaml:"advance_days"`
}

// KeyConfig 密钥配置
type KeyConfig struct {
	Algorithm string        `yaml:"algorithm"`
	Length    int           `yaml:"length"`
	Lifetime  time.Duration `yaml:"lifetime"`
}

// DNSRateLimitConfig DNS限速配置
type DNSRateLimitConfig struct {
	// 启用限速
	Enabled bool `yaml:"enabled"`

	// 全局限速
	Global *RateLimitRule `yaml:"global"`

	// 单IP限速
	PerIP *RateLimitRule `yaml:"per_ip"`

	// 单域名限速
	PerDomain *RateLimitRule `yaml:"per_domain"`

	// 响应码限速
	PerRCODE map[string]*RateLimitRule `yaml:"per_rcode"`
}

// RateLimitRule 限速规则
type RateLimitRule struct {
	// 每秒请求数
	QueriesPerSecond int64 `yaml:"queries_per_second"`

	// 突发限制
	Burst int64 `yaml:"burst"`

	// 窗口大小
	Window time.Duration `yaml:"window"`

	// 响应策略
	Response string `yaml:"response"` // "drop", "truncate", "refuse"
}

// DNSIPFilterConfig DNS IP过滤配置
type DNSIPFilterConfig struct {
	// 启用IP过滤
	Enabled bool `yaml:"enabled"`

	// 白名单
	Whitelist []string `yaml:"whitelist"`

	// 黑名单
	Blacklist []string `yaml:"blacklist"`

	// 国家代码过滤
	CountryFilter *CountryFilterConfig `yaml:"country_filter"`
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
	DefaultPolicy string `yaml:"default_policy"` // "allow", "block"
}

// DNSDomainFilterConfig DNS域名过滤配置
type DNSDomainFilterConfig struct {
	// 启用域名过滤
	Enabled bool `yaml:"enabled"`

	// 阻止的域名
	BlockedDomains []string `yaml:"blocked_domains"`

	// 阻止的正则
	BlockedRegexes []string `yaml:"blocked_regexes"`

	// 阻止的关键词
	BlockedKeywords []string `yaml:"blocked_keywords"`

	// 自定义过滤规则
	CustomRules []*DomainFilterRule `yaml:"custom_rules"`
}

// DomainFilterRule 域名过滤规则
type DomainFilterRule struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"` // "allow", "block", "redirect"
	RedirectTo  string `json:"redirect_to"`
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}

// DNSZone DNS区域
type DNSZone struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// SOA记录
	SOA *SOARecord `json:"soa"`

	// NS记录
	NS []*NSRecord `json:"ns"`

	// 记录列表
	Records []*SmartDNSRecord `json:"records"`

	// 区域传输
	AXFREnabled bool `json:"axfr_enabled"`

	// 动态更新
	DynamicUpdate bool `json:"dynamic_update"`

	// 统计
	Stats *ZoneStats `json:"stats"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SOARecord SOA记录
type SOARecord struct {
	Nameserver string        `json:"nameserver"`
	Admin      string        `json:"admin"`
	Serial     uint32        `json:"serial"`
	Refresh    time.Duration `json:"refresh"`
	Retry      time.Duration `json:"retry"`
	Expire     time.Duration `json:"expire"`
	Minimum    time.Duration `json:"minimum"`
}

// NSRecord NS记录
type NSRecord struct {
	Nameserver string `json:"nameserver"`
	Priority   int    `json:"priority"`
}

// SmartDNSRecord DNS记录
type SmartDNSRecord struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Type     string        `json:"type"` // "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR"
	Value    string        `json:"value"`
	TTL      time.Duration `json:"ttl"`
	Priority int           `json:"priority"`
	Weight   int           `json:"weight"`

	// 调度配置
	Scheduling *RecordScheduling `json:"scheduling"`

	// 健康检查
	HealthCheck *SmartHealthCheckConfig `json:"health_check"`

	// 地理定位
	GeoTarget string `json:"geo_target"` // "cn", "us", "hk", etc.

	// 运营商定位
	ISPTarget string `json:"isp_target"` // "cmcc", "cucc", "ctcc"

	// 状态
	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RecordScheduling 记录调度配置
type RecordScheduling struct {
	// 启用调度
	Enabled bool `json:"enabled"`

	// 生效时间
	EffectiveFrom time.Time `json:"effective_from"`

	// 失效时间
	EffectiveTo time.Time `json:"effective_to"`

	// 调度策略
	Strategy string `json:"strategy"` // "time_based", "load_based", "health_based"

	// 备用记录
	BackupRecords []string `json:"backup_records"`
}

// ZoneStats 区域统计
type ZoneStats struct {
	TotalQueries   int64 `json:"total_queries"`
	TotalResponses int64 `json:"total_responses"`

	// 按类型统计
	QueriesByType map[string]int64 `json:"queries_by_type"`

	// 按响应码统计
	ResponsesByRCODE map[string]int64 `json:"responses_by_rcode"`

	// 平均响应时间
	AverageLatency time.Duration `json:"average_latency"`

	// 缓存命中率
	CacheHitRate float64 `json:"cache_hit_rate"`

	// 限速次数
	RateLimited int64 `json:"rate_limited"`

	// 过滤次数
	Filtered int64 `json:"filtered"`

	mu sync.RWMutex
}

// DNSResolver DNS解析器
type DNSResolver interface {
	Resolve(ctx context.Context, question *DNSQuestion) (*DNSResponse, error)
	GetName() string
	GetPriority() int
}

// DNSQuestion DNS问题
type DNSQuestion struct {
	Name     string `json:"name"`
	Type     string `json:"type"`  // "A", "AAAA", "CNAME", "MX", etc.
	Class    string `json:"class"` // "IN"
	ClientIP string `json:"client_ip"`
}

// DNSResponse DNS响应
type DNSResponse struct {
	// 问题
	Question *DNSQuestion `json:"question"`

	// 答案
	Answers []*DNSAnswer `json:"answers"`

	// 权限
	Authority []*DNSAnswer `json:"authority"`

	// 附加
	Additional []*DNSAnswer `json:"additional"`

	// 响应码
	RCODE int `json:"rcode"` // 0 = NoError, 3 = NXDomain, etc.

	// 标志
	Flags *DNSFlags `json:"flags"`

	// 响应时间
	Latency time.Duration `json:"latency"`

	// 缓存信息
	Cached bool `json:"cached"`

	// 来源解析器
	SourceResolver string `json:"source_resolver"`
}

// DNSAnswer DNS答案
type DNSAnswer struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Class    string        `json:"class"`
	TTL      time.Duration `json:"ttl"`
	Priority int           `json:"priority"`
	Weight   int           `json:"weight"`
	Data     string        `json:"data"`
}

// DNSFlags DNS标志
type DNSFlags struct {
	Authoritative      bool `json:"authoritative"`
	Truncated          bool `json:"truncated"`
	RecursionDesired   bool `json:"recursion_desired"`
	RecursionAvailable bool `json:"recursion_available"`
	Authenticated      bool `json:"authenticated"`
}

// ResolverConfig 解析器配置
type ResolverConfig struct {
	Name string `json:"name"`
	Type string `json:"type"` // "upstream", "forward", "cache", "stub"

	// 地址
	Addresses []string `json:"addresses"`

	// 端口
	Port int `json:"port"`

	// 认证
	Auth *ResolverAuth `json:"auth"`

	// 超时
	Timeout time.Duration `json:"timeout"`

	// 负载均衡
	LoadBalance *ResolverLoadBalance `json:"load_balance"`

	// 健康检查
	HealthCheck *SmartHealthCheckConfig `json:"health_check"`
}

// ResolverAuth 解析器认证
type ResolverAuth struct {
	Type   string `json:"type"` // "none", "tls", "https"
	CAFile string `json:"ca_file"`
}

// ResolverLoadBalance 解析器负载均衡
type ResolverLoadBalance struct {
	Algorithm string `json:"algorithm"` // "round_robin", "random", "ordered"

	// 健康检查排序
	HealthCheckSort bool `json:"health_check_sort"`

	// 延迟排序
	LatencySort bool `json:"latency_sort"`
}

// DNSDefenseConfig DNS防御配置
type DNSDefenseConfig struct {
	// DDoS防护
	DDoS *DNSDDoSConfig `json:"ddos"`

	// 缓存投毒防护
	CachePoisoning *CachePoisoningConfig `json:"cache_poisoning"`

	// 隧道检测
	TunnelDetection *TunnelDetectionConfig `json:"tunnel_detection"`

	// 随机化配置
	Randomization *DNSRandomizationConfig `json:"randomization"`
}

// DNSDDoSConfig DNS DDoS配置
type DNSDDoSConfig struct {
	// 启用防护
	Enabled bool `json:"enabled"`

	// 清洗配置
	Cleaning *DNSCleaningConfig `json:"cleaning"`

	// 黑洞配置
	Blackhole *DNSBlackholeConfig `json:"blackhole"`

	// 流量限制
	RateLimits []*DNSRateLimit `json:"rate_limits"`
}

// DNSCleaningConfig DNS清洗配置
type DNSCleaningConfig struct {
	// 启用清洗
	Enabled bool `json:"enabled"`

	// 清洗中心
	Centers []string `json:"centers"`

	// 清洗阈值
	Threshold int64 `json:"threshold"` // QPS

	// 自动清洗
	AutoClean bool `json:"auto_clean"`

	// 清洗算法
	Algorithm string `json:"algorithm"` // "carpet", "scrubbing"
}

// DNSBlackholeConfig DNS黑洞配置
type DNSBlackholeConfig struct {
	// 启用黑洞
	Enabled bool `json:"enabled"`

	// 触发阈值
	Threshold int64 `json:"threshold"` // QPS

	// 黑洞时间
	Duration time.Duration `json:"duration"`

	// 自动恢复
	AutoRecover bool `json:"auto_recover"`

	// 恢复阈值
	RecoveryThreshold int64 `json:"recovery_threshold"`
}

// DNSRateLimit DNS限速
type DNSRateLimit struct {
	Name string `json:"name"`
	Type string `json:"type"` // "global", "per_ip", "per_subnet", "per_domain"

	// 匹配条件
	Match *RateLimitMatch `json:"match"`

	// 限制值
	Limit *RateLimitValue `json:"limit"`

	// 响应
	Response string `json:"response"` // "drop", "truncate", "refuse"

	// 窗口
	Window time.Duration `json:"window"`
}

// RateLimitMatch 限速匹配
type RateLimitMatch struct {
	Subnet     string `json:"subnet"`
	Domain     string `json:"domain"`
	RCODE      string `json:"rcode"`
	RecordType string `json:"record_type"`
}

// RateLimitValue 限速值
type RateLimitValue struct {
	QueriesPerSecond int64 `json:"queries_per_second"`
	Burst            int64 `json:"burst"`
}

// CachePoisoningConfig 缓存投毒防护配置
type CachePoisoningConfig struct {
	// 启用防护
	Enabled bool `json:"enabled"`

	// 源端口随机化
	SourcePortRandomization bool `json:"source_port_randomization"`

	// 查询ID随机化
	QueryIDRandomization bool `json:"query_id_randomization"`

	// 请求令牌
	RequestToken bool `json:"request_token"`

	// 双重查询验证
	DualQueryValidation bool `json:"dual_query_validation"`

	// 最大缓存时间
	MaxCacheTime time.Duration `json:"max_cache_time"`
}

// TunnelDetectionConfig 隧道检测配置
type TunnelDetectionConfig struct {
	// 启用检测
	Enabled bool `json:"enabled"`

	// 检测阈值
	Threshold float64 `json:"threshold"` // 隧道流量比例

	// 检测算法
	Algorithm string `json:"algorithm"` // "packet_size", "timing", "behavior"

	// 响应策略
	Response string `json:"response"` // "drop", "flag", "alert"

	// 白名单
	Whitelist []string `json:"whitelist"`
}

// DNSRandomizationConfig DNS随机化配置
type DNSRandomizationConfig struct {
	// 源端口随机化
	SourcePort bool `json:"source_port"`

	// 查询ID随机化
	QueryID bool `json:"query_id"`

	// 响应排序随机化
	ResponseOrder bool `json:"response_order"`

	// 大小写随机化（域名）
	CaseRandomization bool `json:"case_randomization"`

	// 熵值
	EntropyBits int `json:"entropy_bits"`
}

// NodeScheduler 节点调度器
type NodeScheduler struct {
	config    *DNSSchedulingConfig
	nodes     map[string]*NodeInfo
	mu        sync.RWMutex
	lastCheck time.Time
}

// NodeInfo 节点信息
type NodeInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Region  string `json:"region"`
	ISP     string `json:"isp"`

	Status string `json:"status"` // "online", "offline", "degraded"

	// 健康状态
	HealthScore float64 `json:"health_score"` // 0-100

	// 延迟
	Latency time.Duration `json:"latency"`

	// 负载
	Load float64 `json:"load"` // 0-1

	// 带宽
	Bandwidth int64 `json:"bandwidth"` // Mbps

	// 连接数
	Connections int64 `json:"connections"`

	// QPS
	QPS int64 `json:"qps"`

	// 错误率
	ErrorRate float64 `json:"error_rate"`

	// 最后检查时间
	LastCheck time.Time `json:"last_check"`

	// 权重
	Weight int `json:"weight"`

	mu sync.RWMutex
}

// SmartDNSStats 智能DNS统计
type SmartDNSStats struct {
	TotalQueries   int64 `json:"total_queries"`
	TotalResponses int64 `json:"total_responses"`
	CacheHits      int64 `json:"cache_hits"`
	CacheMisses    int64 `json:"cache_misses"`

	// 按类型统计
	QueriesByType map[string]int64 `json:"queries_by_type"`

	// 按区域统计
	QueriesByRegion map[string]int64 `json:"queries_by_region"`

	// 按ISP统计
	QueriesByISP map[string]int64 `json:"queries_by_isp"`

	// 平均响应时间
	AverageLatency time.Duration `json:"average_latency"`

	// 调度统计
	NodeSwitches int64 `json:"node_switches"`
	Failovers    int64 `json:"failovers"`
	GFWDefenses  int64 `json:"gfw_defenses"`

	// 安全统计
	RateLimited    int64 `json:"rate_limited"`
	Filtered       int64 `json:"filtered"`
	AttacksBlocked int64 `json:"attacks_blocked"`

	// 在线节点
	OnlineNodes int `json:"online_nodes"`
	TotalNodes  int `json:"total_nodes"`

	mu sync.RWMutex
}

// DNSDefenseConfig DNS防御配置
type DNSDefense struct {
	config *DNSDefenseConfig
	mu     sync.RWMutex
	stats  *DefenseStats
}

// DefenseStats 防御统计
type DefenseStats struct {
	TotalAttacks     int64 `json:"total_attacks"`
	AttacksBlocked   int64 `json:"attacks_blocked"`
	AttacksMitigated int64 `json:"attacks_mitigated"`

	AttackTypes map[string]int64 `json:"attack_types"`

	// DDoS统计
	DDoSAttacks      int64 `json:"ddos_attacks"`
	DDoSBytesDropped int64 `json:"ddos_bytes_dropped"`

	// 放大攻击
	AmplificationAttacks int64 `json:"amplification_attacks"`

	// 缓存投毒
	CachePoisoningAttempts int64 `json:"cache_poisoning_attempts"`

	// 隧道检测
	TunnelDetections int64 `json:"tunnel_detections"`

	mu sync.RWMutex
}

// NewSmartDNS 创建智能DNS系统
func NewSmartDNS(config *SmartDNSConfig) *SmartDNS {
	if config == nil {
		config = &SmartDNSConfig{
			Enabled:    true,
			ListenPort: 53,
			Protocols:  []string{"udp", "tcp"},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SmartDNS{
		config:    config,
		zones:     make(map[string]*DNSZone),
		records:   make(map[string][]*SmartDNSRecord),
		resolvers: make([]DNSResolver, 0),
		scheduler: &NodeScheduler{config: config.Scheduling, nodes: make(map[string]*NodeInfo)},
		geoIP:     NewGeoIPLib(),
		stats: &SmartDNSStats{
			QueriesByType:   make(map[string]int64),
			QueriesByRegion: make(map[string]int64),
			QueriesByISP:    make(map[string]int64),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// NewGeoIPLib 创建GeoIP库
func NewGeoIPLib() *GeoIPLib {
	return &GeoIPLib{
		data: make(map[string]*GeoInfo),
	}
}

// GeoIPLib GeoIP库
type GeoIPLib struct {
	data map[string]*GeoInfo
	mu   sync.RWMutex
}

// GeoInfo 地理信息
type GeoInfo struct {
	IPRange     string  `json:"ip_range"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	ISPType     string  `json:"isp_type"` // "isp", "idc", "edu", "gov"
	ASN         string  `json:"asn"`
}

// Lookup IP查询
func (g *GeoIPLib) Lookup(ip string) *GeoInfo {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if info, ok := g.data[ip]; ok && info != nil {
		return info
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	for key, info := range g.data {
		rangeKey := key
		if rangeKey == "" && info != nil {
			rangeKey = info.IPRange
		}
		if rangeKey == "" {
			continue
		}
		if ipInRange(parsedIP, rangeKey) {
			return info
		}
	}

	return &GeoInfo{
		Country:     "未知",
		CountryCode: "XX",
	}
}

func ipInRange(ip net.IP, rangeStr string) bool {
	if ip == nil || rangeStr == "" {
		return false
	}

	if strings.Contains(rangeStr, "/") {
		_, cidr, err := net.ParseCIDR(rangeStr)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}

	if strings.Contains(rangeStr, "-") {
		parts := strings.SplitN(rangeStr, "-", 2)
		if len(parts) != 2 {
			return false
		}
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start == nil || end == nil {
			return false
		}
		return bytes.Compare(ip, start) >= 0 && bytes.Compare(ip, end) <= 0
	}

	parsed := net.ParseIP(rangeStr)
	if parsed == nil {
		return false
	}
	return ip.Equal(parsed)
}

// AddZone 添加区域
func (s *SmartDNS) AddZone(zone *DNSZone) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	zone.CreatedAt = time.Now()
	zone.UpdatedAt = time.Now()
	zone.Stats = &ZoneStats{
		QueriesByType:    make(map[string]int64),
		ResponsesByRCODE: make(map[string]int64),
	}

	s.zones[zone.Name] = zone
	s.records[zone.Name] = zone.Records

	return nil
}

// Resolve 解析域名
func (s *SmartDNS) Resolve(ctx context.Context, question *DNSQuestion) (*DNSResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 查找区域
	_, ok := s.zones[question.Name]
	if !ok {
		return nil, fmt.Errorf("区域不存在: %s", question.Name)
	}

	// 查找记录
	records := s.records[question.Name]

	// 根据调度策略选择记录
	selectedRecords := s.selectRecords(records, question)

	// 构建响应
	response := &DNSResponse{
		Question: question,
		Answers:  make([]*DNSAnswer, 0),
		Flags: &DNSFlags{
			RecursionAvailable: true,
		},
		Latency: 0,
	}

	for _, record := range selectedRecords {
		if record.Type == question.Type && record.Enabled {
			response.Answers = append(response.Answers, &DNSAnswer{
				Name: record.Name,
				Type: record.Type,
				TTL:  record.TTL,
				Data: record.Value,
			})
		}
	}

	if len(response.Answers) == 0 {
		response.RCODE = 3 // NXDomain
	}

	// 更新统计
	s.updateStats(question, response)

	return response, nil
}

// selectRecords 选择记录（根据调度策略）
func (s *SmartDNS) selectRecords(records []*SmartDNSRecord, question *DNSQuestion) []*SmartDNSRecord {
	if s.config == nil || s.config.Scheduling == nil {
		return records
	}

	region := s.getClientRegion(question)
	switch s.config.Scheduling.Strategy {
	case "geo":
		return s.geoSelect(records, region)
	case "latency":
		return s.latencySelect(records)
	case "load":
		return s.loadSelect(records)
	case "health":
		return s.healthSelect(records)
	case "smart":
		return s.smartSelect(records, question, region)
	default:
		return records
	}
}

func (s *SmartDNS) getClientRegion(question *DNSQuestion) string {
	if question == nil || question.ClientIP == "" || s.geoIP == nil {
		return ""
	}

	info := s.geoIP.Lookup(question.ClientIP)
	if info == nil {
		return ""
	}
	if info.CountryCode != "" && info.CountryCode != "XX" {
		return strings.ToLower(info.CountryCode)
	}
	if info.Region != "" {
		return info.Region
	}
	return ""
}

// geoSelect 地理选择
func (s *SmartDNS) geoSelect(records []*SmartDNSRecord, region string) []*SmartDNSRecord {
	enabled := filterEnabledRecords(records)
	if len(enabled) == 0 {
		return records
	}
	if region == "" {
		return enabled
	}

	var matched []*SmartDNSRecord
	for _, record := range enabled {
		if record.GeoTarget == "" || strings.EqualFold(record.GeoTarget, region) {
			matched = append(matched, record)
		}
	}
	if len(matched) == 0 {
		return enabled
	}
	return matched
}

// latencySelect 延迟选择
func (s *SmartDNS) latencySelect(records []*SmartDNSRecord) []*SmartDNSRecord {
	enabled := filterEnabledRecords(records)
	if len(enabled) == 0 {
		return records
	}

	var best *SmartDNSRecord
	var bestLatency time.Duration
	for _, record := range enabled {
		node := s.findNodeForRecord(record)
		latency := time.Duration(0)
		if node != nil && node.Latency > 0 {
			latency = node.Latency
		} else {
			latency = 5 * time.Second
		}
		if best == nil || latency < bestLatency {
			best = record
			bestLatency = latency
		}
	}
	if best == nil {
		return enabled
	}
	return []*SmartDNSRecord{best}
}

// loadSelect 负载选择
func (s *SmartDNS) loadSelect(records []*SmartDNSRecord) []*SmartDNSRecord {
	enabled := filterEnabledRecords(records)
	if len(enabled) == 0 {
		return records
	}

	var best *SmartDNSRecord
	bestLoad := 2.0
	for _, record := range enabled {
		node := s.findNodeForRecord(record)
		load := 1.0
		if node != nil && node.Load > 0 {
			load = node.Load
		}
		if best == nil || load < bestLoad {
			best = record
			bestLoad = load
		}
	}
	if best == nil {
		return enabled
	}
	return []*SmartDNSRecord{best}
}

// healthSelect 健康选择
func (s *SmartDNS) healthSelect(records []*SmartDNSRecord) []*SmartDNSRecord {
	enabled := filterEnabledRecords(records)
	if len(enabled) == 0 {
		return records
	}

	var healthy []*SmartDNSRecord
	for _, record := range enabled {
		node := s.findNodeForRecord(record)
		if node == nil {
			healthy = append(healthy, record)
			continue
		}
		if strings.EqualFold(node.Status, "offline") {
			continue
		}
		if node.HealthScore <= 0 {
			continue
		}
		healthy = append(healthy, record)
	}
	if len(healthy) == 0 {
		return enabled
	}
	return healthy
}

// smartSelect 智能选择
func (s *SmartDNS) smartSelect(records []*SmartDNSRecord, question *DNSQuestion, region string) []*SmartDNSRecord {
	candidates := s.healthSelect(records)
	if len(candidates) == 0 {
		candidates = records
	}
	if region != "" {
		candidates = s.geoSelect(candidates, region)
	}
	if len(candidates) == 0 {
		return records
	}

	if selected := s.latencySelect(candidates); len(selected) > 0 {
		return selected
	}
	if selected := s.loadSelect(candidates); len(selected) > 0 {
		return selected
	}
	return weightedSelectRecords(candidates)
}

func (s *SmartDNS) findNodeForRecord(record *SmartDNSRecord) *NodeInfo {
	if record == nil {
		return nil
	}

	s.scheduler.mu.RLock()
	defer s.scheduler.mu.RUnlock()

	for _, node := range s.scheduler.nodes {
		if node.Address == record.Value {
			return node
		}
		if node.ID != "" && node.ID == record.Value {
			return node
		}
	}
	return nil
}

func filterEnabledRecords(records []*SmartDNSRecord) []*SmartDNSRecord {
	enabled := make([]*SmartDNSRecord, 0, len(records))
	for _, record := range records {
		if record != nil && record.Enabled {
			enabled = append(enabled, record)
		}
	}
	return enabled
}

func weightedSelectRecords(records []*SmartDNSRecord) []*SmartDNSRecord {
	if len(records) == 0 {
		return records
	}

	totalWeight := 0
	for _, record := range records {
		weight := record.Weight
		if weight <= 0 {
			weight = 1
		}
		totalWeight += weight
	}
	if totalWeight <= 0 {
		return records
	}

	random := int(time.Now().UnixNano() % int64(totalWeight))
	accumulated := 0
	for _, record := range records {
		weight := record.Weight
		if weight <= 0 {
			weight = 1
		}
		accumulated += weight
		if accumulated > random {
			return []*SmartDNSRecord{record}
		}
	}
	return []*SmartDNSRecord{records[0]}
}

func measureNodeLatency(address string, timeout time.Duration, samples int) time.Duration {
	if samples <= 0 {
		samples = 1
	}

	addr := normalizeNodeAddress(address)
	if addr == "" {
		return timeout
	}

	var total time.Duration
	for i := 0; i < samples; i++ {
		total += dialLatency(addr, timeout)
	}
	return total / time.Duration(samples)
}

func normalizeNodeAddress(address string) string {
	addr := strings.TrimSpace(address)
	if addr == "" {
		return ""
	}
	if idx := strings.Index(addr, "://"); idx != -1 {
		addr = addr[idx+3:]
	}
	if slash := strings.Index(addr, "/"); slash != -1 {
		addr = addr[:slash]
	}
	return addr
}

func dialLatency(address string, timeout time.Duration) time.Duration {
	addr := address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "80")
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return timeout
	}
	_ = conn.Close()

	return time.Since(start)
}

// updateStats 更新统计
func (s *SmartDNS) updateStats(question *DNSQuestion, response *DNSResponse) {
	s.stats.mu.Lock()
	s.stats.TotalQueries++
	s.stats.QueriesByType[question.Type]++

	if response.Cached {
		s.stats.CacheHits++
	} else {
		s.stats.CacheMisses++
	}

	if response.RCODE == 0 {
		s.stats.TotalResponses++
	}

	s.stats.AverageLatency = time.Duration(float64(s.stats.AverageLatency) + float64(response.Latency-s.stats.AverageLatency)/float64(s.stats.TotalResponses))
	s.stats.mu.Unlock()
}

// Start 启动智能DNS
func (s *SmartDNS) Start() error {
	// 启动健康检查
	go s.runHealthChecks()

	// 启动延迟测量
	go s.runLatencyMeasurements()

	// 启动调度
	go s.runScheduler()

	return nil
}

// runHealthChecks 运行健康检查
func (s *SmartDNS) runHealthChecks() {
	if s.config == nil || s.config.Scheduling == nil || s.config.Scheduling.NodeHealthCheck == nil {
		return
	}
	if !s.config.Scheduling.NodeHealthCheck.Enabled {
		return
	}
	interval := s.config.Scheduling.NodeHealthCheck.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// 检查节点健康状态
			s.checkNodeHealth()
		}
	}
}

// checkNodeHealth 检查节点健康
func (s *SmartDNS) checkNodeHealth() {
	if s.config == nil || s.config.Scheduling == nil || s.config.Scheduling.NodeHealthCheck == nil {
		return
	}
	if !s.config.Scheduling.NodeHealthCheck.Enabled {
		return
	}

	now := time.Now()
	s.scheduler.mu.Lock()
	defer s.scheduler.mu.Unlock()

	for _, node := range s.scheduler.nodes {
		if node == nil {
			continue
		}

		score := 100.0
		if strings.EqualFold(node.Status, "offline") {
			score = 0
		} else {
			if node.ErrorRate >= 0.5 {
				score -= 70
			} else if node.ErrorRate >= 0.2 {
				score -= 40
			}
			if node.Load >= 0.9 {
				score -= 30
			} else if node.Load >= 0.7 {
				score -= 15
			}
			if node.Latency >= 500*time.Millisecond {
				score -= 25
			} else if node.Latency >= 200*time.Millisecond {
				score -= 10
			}
		}

		if score < 0 {
			score = 0
		}

		node.HealthScore = score
		node.LastCheck = now
		if score == 0 {
			node.Status = "offline"
		} else if score < 60 {
			node.Status = "degraded"
		} else if node.Status == "" || strings.EqualFold(node.Status, "offline") {
			node.Status = "online"
		}
	}
}

// runLatencyMeasurements 运行延迟测量
func (s *SmartDNS) runLatencyMeasurements() {
	if s.config == nil || s.config.Scheduling == nil || s.config.Scheduling.LatencyConfig == nil {
		return
	}
	if !s.config.Scheduling.LatencyConfig.Enabled {
		return
	}
	interval := s.config.Scheduling.LatencyConfig.Interval
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.measureLatencies()
		}
	}
}

// measureLatencies 测量延迟
func (s *SmartDNS) measureLatencies() {
	if s.config == nil || s.config.Scheduling == nil || s.config.Scheduling.LatencyConfig == nil {
		return
	}
	cfg := s.config.Scheduling.LatencyConfig
	if !cfg.Enabled {
		return
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	sampleCount := cfg.SampleCount
	if sampleCount <= 0 {
		sampleCount = 1
	}
	smoothWindow := cfg.SmoothWindow
	if smoothWindow <= 0 {
		smoothWindow = 1
	}

	now := time.Now()
	s.scheduler.mu.Lock()
	defer s.scheduler.mu.Unlock()

	for _, node := range s.scheduler.nodes {
		if node == nil {
			continue
		}
		avg := measureNodeLatency(node.Address, timeout, sampleCount)
		if smoothWindow > 1 && node.Latency > 0 {
			node.Latency = time.Duration((float64(node.Latency)*float64(smoothWindow-1) + float64(avg)) / float64(smoothWindow))
		} else {
			node.Latency = avg
		}
		node.LastCheck = now
	}
}

// runScheduler 运行调度器
func (s *SmartDNS) runScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.updateNodeScheduling()
		}
	}
}

// updateNodeScheduling 更新节点调度
func (s *SmartDNS) updateNodeScheduling() {
	if s.config == nil || s.config.Scheduling == nil {
		return
	}

	s.scheduler.mu.Lock()
	defer s.scheduler.mu.Unlock()

	for _, node := range s.scheduler.nodes {
		if node == nil {
			continue
		}

		weight := 1
		if node.HealthScore > 0 {
			weight = int(node.HealthScore / 10)
			if weight < 1 {
				weight = 1
			}
		}
		if node.Load > 0 {
			adjusted := int(float64(weight) * (1 - node.Load))
			if adjusted > 0 {
				weight = adjusted
			}
		}

		if s.config.Scheduling.LoadBalance != nil && s.config.Scheduling.LoadBalance.Weights != nil {
			if override, ok := s.config.Scheduling.LoadBalance.Weights[node.ID]; ok && override > 0 {
				weight = override
			}
		}

		node.Weight = weight
	}

	s.scheduler.lastCheck = time.Now()
}

// RegisterResolver 注册解析器
func (s *SmartDNS) RegisterResolver(resolver DNSResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resolvers = append(s.resolvers, resolver)
}

// GetStats 获取统计
func (s *SmartDNS) GetStats() *SmartDNSStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return s.stats
}

// GFWDefense 假墙防御
func (s *SmartDNS) GFWDefense(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 检查是否在GFW IP列表中
	for _, gfwIP := range s.config.Scheduling.GFWDefense.GFWIPList {
		if ip == gfwIP {
			return true
		}
	}

	return false
}

// AutoSwitchToBackup 自动切换到备用IP
func (s *SmartDNS) AutoSwitchToBackup(domain string) ([]string, error) {
	s.mu.RLock()
	backupIPs := s.config.Scheduling.GFWDefense.BackupIPs
	s.mu.RUnlock()

	if len(backupIPs) == 0 {
		return nil, fmt.Errorf("没有配置备用IP")
	}

	// 更新DNS记录
	s.mu.Lock()
	records := s.records[domain]
	for i := range records {
		records[i].Value = backupIPs[0]
	}
	s.mu.Unlock()

	s.stats.mu.Lock()
	s.stats.GFWDefenses++
	s.stats.mu.Unlock()

	return backupIPs, nil
}

// GetNodeStatus 获取节点状态
func (s *SmartDNS) GetNodeStatus() []*NodeInfo {
	s.scheduler.mu.RLock()
	defer s.scheduler.mu.RUnlock()

	nodes := make([]*NodeInfo, 0, len(s.scheduler.nodes))
	for _, node := range s.scheduler.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// RegisterNode 注册节点
func (s *SmartDNS) RegisterNode(node *NodeInfo) {
	s.scheduler.mu.Lock()
	defer s.scheduler.mu.Unlock()

	node.LastCheck = time.Now()
	s.scheduler.nodes[node.ID] = node

	s.stats.mu.Lock()
	s.stats.TotalNodes++
	s.stats.OnlineNodes++
	s.stats.mu.Unlock()
}

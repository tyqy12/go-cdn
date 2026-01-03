package defense

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// HighDefenseIP 高防IP管理
type HighDefenseIP struct {
	config     *DefenseConfig
	ips        map[string]*DefenseIP
	policies   map[string]*DefensePolicy
	attackLogs []*AttackLog
	mu         sync.RWMutex
	stats      *DefenseStats
	ctx        context.Context
	cancel     context.CancelFunc
}

// DefenseConfig 高防配置
type DefenseConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 默认配置
	DefaultConfig *IPConfig `yaml:"default_config"`

	// 清洗中心配置
	CleaningCenter *CleaningCenterConfig `yaml:"cleaning_center"`

	// 黑洞策略
	BlackholeConfig *BlackholeConfig `yaml:"blackhole_config"`

	// 速率限制
	RateLimitConfig *RateLimitConfig `yaml:"rate_limit_config"`

	// 行为分析
	BehaviorAnalysis *BehaviorAnalysisConfig `yaml:"behavior_analysis"`

	// 阈值配置
	Thresholds *DefenseThresholds `yaml:"thresholds"`
}

// IPConfig IP配置
type IPConfig struct {
	// 带宽 (Gbps)
	Bandwidth int `yaml:"bandwidth"`

	// 清洗能力 (Gbps)
	CleaningCapacity int `yaml:"cleaning_capacity"`

	// 连接数限制
	ConnectionLimit int64 `json:"connection_limit"`

	// QPS限制
	QPSLimit int64 `json:"qps_limit"`

	// 端口配置
	Ports []PortConfig `yaml:"ports"`
}

// PortConfig 端口配置
type PortConfig struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp", "udp", "both"
	SSL      bool   `json:"ssl"`
}

// CleaningCenterConfig 清洗中心配置
type CleaningCenterConfig struct {
	// 清洗中心地址
	Addresses []string `yaml:"addresses"`

	// 备用地址
	FallbackAddresses []string `yaml:"fallback_addresses"`

	// 认证
	Auth *AuthConfig `yaml:"auth"`

	// 超时
	Timeout time.Duration `yaml:"timeout"`

	// 健康检查
	HealthCheck *HealthCheckConfig `yaml:"health_check"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Type     string        `json:"type"` // "http", "tcp", "icmp"
}

// BlackholeConfig 黑洞策略配置
type BlackholeConfig struct {
	// 启用黑洞
	Enabled bool `yaml:"enabled"`

	// 触发阈值 (Gbps)
	TriggerThreshold float64 `yaml:"trigger_threshold"`

	// 持续时间
	Duration time.Duration `yaml:"duration"`

	// 自动恢复
	AutoRecovery bool `yaml:"auto_recovery"`

	// 恢复阈值
	RecoveryThreshold float64 `yaml:"recovery_threshold"`

	// BGP配置
	BGPConfig *BGPConfig `yaml:"bgp_config"`

	// API URL (用于调用外部黑洞路由API)
	APIURL string `yaml:"api_url"`
}

// BGPConfig BGP配置
type BGPConfig struct {
	// BGP邻居地址
	Neighbor string `yaml:"neighbor"`

	// AS号
	ASNumber int `yaml:"as_number"`

	// 黑洞下一跳
	BlackholeNextHop string `yaml:"blackhole_next_hop"`

	// BGP社区
	Communities []string `yaml:"communities"`
}

// RateLimitConfig 速率限制配置
type RateLimitConfig struct {
	// 启用速率限制
	Enabled bool `yaml:"enabled"`

	// 全局限流
	GlobalLimit *RateLimit `yaml:"global_limit"`

	// 单IP限流
	PerIPLimit *RateLimit `yaml:"per_ip_limit"`

	// 连接限制
	ConnectionLimit *ConnectionLimit `yaml:"connection_limit"`
}

// RateLimit 速率限制
type RateLimit struct {
	// 每秒请求数
	RequestsPerSecond int64 `yaml:"requests_per_second"`

	// 突发限制
	Burst int64 `yaml:"burst"`

	// 窗口大小
	Window time.Duration `yaml:"window"`
}

// ConnectionLimit 连接限制
type ConnectionLimit struct {
	// 最大并发连接数
	MaxConnections int64 `yaml:"max_connections"`

	// 新连接速率
	NewConnectionRate int64 `yaml:"new_connection_rate"`

	// 同一个IP的最大连接数
	MaxConnectionsPerIP int64 `yaml:"max_connections_per_ip"`
}

// BehaviorAnalysisConfig 行为分析配置
type BehaviorAnalysisConfig struct {
	// 启用行为分析
	Enabled bool `yaml:"enabled"`

	// 分析窗口
	Window time.Duration `yaml:"window"`

	// 异常阈值
	AnomalyThreshold float64 `yaml:"anomaly_threshold"`

	// 机器学习配置
	MLConfig *MLConfig `json:"ml_config"`
}

// MLConfig 机器学习配置
type MLConfig struct {
	Enabled        bool          `json:"enabled"`
	ModelType      string        `json:"model_type"`
	UpdateInterval time.Duration `json:"update_interval"`
}

// DefenseThresholds 防御阈值
type DefenseThresholds struct {
	// DDoS攻击阈值 (Gbps)
	DDoSThreshold float64 `yaml:"ddos_threshold"`

	// CC攻击阈值 (QPS)
	CCThreshold int64 `yaml:"cc_threshold"`

	// 带宽攻击阈值 (Gbps)
	BandwidthThreshold float64 `yaml:"bandwidth_threshold"`

	// 连接数攻击阈值
	ConnectionThreshold int64 `yaml:"connection_threshold"`

	// 报文速率阈值 (pps)
	PacketRateThreshold int64 `yaml:"packet_rate_threshold"`
}

// DefenseIP 高防IP
type DefenseIP struct {
	ID     string `json:"id"`
	IP     string `json:"ip"`
	Type   string `json:"type"`   // "ipv4", "ipv6"
	Status string `json:"status"` // "normal", "under_attack", "blackholed", "cleaning"

	// 配置
	Config *IPConfig `json:"config"`

	// 清洗状态
	CleaningStatus *CleaningStatus `json:"cleaning_status"`

	// 统计
	Stats *IPStats `json:"stats"`

	// 防护等级
	ProtectionLevel string `json:"protection_level"` // "basic", "advanced", "enterprise"

	// 域名绑定
	Domains []string `json:"domains"`

	// 端口配置
	Ports []PortConfig `json:"ports"`

	// 黑洞配置
	BlackholeConfig *BlackholeStatus `json:"blackhole_config"`

	// 带宽限制
	BandwidthLimit *BandwidthLimitStatus `json:"bandwidth_limit"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CleaningStatus 清洗状态
type CleaningStatus struct {
	// 是否正在清洗
	InCleaning bool `json:"in_cleaning"`

	// 清洗模式
	Mode string `json:"mode"` // "auto", "manual"

	// 清洗开始时间
	StartTime time.Time `json:"start_time"`

	// 清洗流量 (Mbps)
	TrafficIn  float64 `json:"traffic_in"`
	TrafficOut float64 `json:"traffic_out"`

	// 清洗掉的攻击流量
	AttacksDropped int64 `json:"attacks_dropped"`

	// 清洗后的流量
	CleanedTraffic int64 `json:"cleaned_traffic"`
}

// IPStats IP统计
type IPStats struct {
	// 当前带宽 (Mbps)
	CurrentBandwidth float64 `json:"current_bandwidth"`

	// 峰值带宽 (Mbps)
	PeakBandwidth float64 `json:"peak_bandwidth"`

	// 当前连接数
	CurrentConnections int64 `json:"current_connections"`

	// 峰值连接数
	PeakConnections int64 `json:"peak_connections"`

	// 当前QPS
	CurrentQPS int64 `json:"current_qps"`

	// 攻击次数
	AttackCount int64 `json:"attack_count"`

	// 总攻击流量 (GB)
	TotalAttackTraffic int64 `json:"total_attack_traffic"`

	// 最后攻击时间
	LastAttackTime time.Time `json:"last_attack_time"`

	mu sync.RWMutex
}

// DefensePolicy 防御策略
type DefensePolicy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// 触发条件
	Triggers []PolicyTrigger `json:"triggers"`

	// 响应动作
	Actions []PolicyAction `json:"actions"`

	// 优先级
	Priority int `json:"priority"`

	// 状态
	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PolicyTrigger 策略触发器
type PolicyTrigger struct {
	Type     string        `json:"type"`     // "bandwidth", "connection", "qps", "packet_rate", "attack_signature"
	Operator string        `json:"operator"` // "gt", "lt", "eq", "gte", "lte"
	Value    float64       `json:"value"`
	Duration time.Duration `json:"duration"` // 持续时间
}

// PolicyAction 策略动作
type PolicyAction struct {
	Type   string                 `json:"type"` // "rate_limit", "blackhole", "cleaning", "alert", "block_ip"
	Config map[string]interface{} `json:"config"`
}

// AttackLog 攻击日志
type AttackLog struct {
	ID         string      `json:"id"`
	IP         string      `json:"ip"`
	Type       string      `json:"type"` // "ddos", "cc", "flood", "syn_flood", "udp_flood", "blackhole", "bandwidth_limit"
	AttackInfo *AttackInfo `json:"attack_info"`

	// 攻击时间
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// 攻击流量
	AttackTraffic int64   `json:"attack_traffic"`
	AttackRate    float64 `json:"attack_rate"`

	// 响应
	Response *AttackResponse `json:"response"`

	// 结果
	Result string `json:"result"` // "mitigated", "blackholed", "failed"

	// 状态
	Status      string    `json:"status"` // "detected", "processing", "mitigated"
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// AttackInfo 攻击信息
type AttackInfo struct {
	// 攻击类型详情
	AttackDetails string `json:"attack_details"`

	// 源IP分布
	SourceIPs []string `json:"source_ips"`

	// 攻击特征
	Signatures []string `json:"signatures"`

	// 协议分布
	Protocols map[string]float64 `json:"protocols"`

	// 端口分布
	Ports []int `json:"ports"`

	// 地理位置分布
	GeoDistribution map[string]float64 `json:"geo_distribution"`
}

// AttackResponse 攻击响应
type AttackResponse struct {
	// 采取的动作
	ActionsTaken []string `json:"actions_taken"`

	// 清洗流量
	CleanedTraffic int64 `json:"cleaned_traffic"`

	// 阻断流量
	BlockedTraffic int64 `json:"blocked_traffic"`

	// 响应时间
	ResponseTime time.Duration `json:"response_time"`

	// 防护效果
	Effectiveness float64 `json:"effectiveness"` // 0-1
}

// DefenseStats 防御统计
type DefenseStats struct {
	TotalIPs             int     `json:"total_ips"`
	ActiveIPs            int     `json:"active_ips"`
	UnderAttack          int     `json:"under_attack"`
	InCleaning           int     `json:"in_cleaning"`
	TotalAttacks         int64   `json:"total_attacks"`
	AttacksToday         int64   `json:"attacks_today"`
	TotalDroppedTraffic  int64   `json:"total_dropped_traffic"`
	CurrentTraffic       float64 `json:"current_traffic"`
	CurrentBandwidth     float64 `json:"current_bandwidth"`
	TotalBlackholes      int64   `json:"total_blackholes"`
	TotalBandwidthLimits int64   `json:"total_bandwidth_limits"`
	mu                   sync.RWMutex
}

// NewHighDefenseIP 创建高防IP管理
func NewHighDefenseIP(config *DefenseConfig) *HighDefenseIP {
	if config == nil {
		config = &DefenseConfig{
			Enabled: true,
			DefaultConfig: &IPConfig{
				Bandwidth:        100,
				CleaningCapacity: 200,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &HighDefenseIP{
		config:     config,
		ips:        make(map[string]*DefenseIP),
		policies:   make(map[string]*DefensePolicy),
		attackLogs: make([]*AttackLog, 0),
		stats:      &DefenseStats{},
		ctx:        ctx,
		cancel:     cancel,
	}
}

// AllocateIP 分配高防IP
func (d *HighDefenseIP) AllocateIP(ip, protectionLevel string, config *IPConfig) (*DefenseIP, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 检查IP是否已存在
	if _, ok := d.ips[ip]; ok {
		return nil, fmt.Errorf("IP已分配: %s", ip)
	}

	if config == nil {
		config = d.config.DefaultConfig
	}

	defenseIP := &DefenseIP{
		ID:              fmt.Sprintf("def_%s", ip),
		IP:              ip,
		Status:          "normal",
		Config:          config,
		Stats:           &IPStats{},
		ProtectionLevel: protectionLevel,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	d.ips[ip] = defenseIP

	d.stats.mu.Lock()
	d.stats.TotalIPs++
	d.stats.ActiveIPs++
	d.mu.Unlock()

	return defenseIP, nil
}

// GetDefenseIP 获取高防IP信息
func (d *HighDefenseIP) GetDefenseIP(ip string) (*DefenseIP, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return nil, fmt.Errorf("IP不存在: %s", ip)
	}

	return ipInfo, nil
}

// ListDefenseIPs 列出所有高防IP
func (d *HighDefenseIP) ListDefenseIPs() []*DefenseIP {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips := make([]*DefenseIP, 0, len(d.ips))
	for _, ip := range d.ips {
		ips = append(ips, ip)
	}

	return ips
}

// UpdateConfig 更新IP配置
func (d *HighDefenseIP) UpdateConfig(ip string, config *IPConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	ipInfo.Config = config
	ipInfo.UpdatedAt = time.Now()

	return nil
}

// StartCleaning 启动流量清洗
func (d *HighDefenseIP) StartCleaning(ip string, mode string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	ipInfo.Status = "cleaning"
	ipInfo.CleaningStatus = &CleaningStatus{
		InCleaning: true,
		Mode:       mode,
		StartTime:  time.Now(),
	}

	d.stats.mu.Lock()
	d.stats.InCleaning++
	d.stats.UnderAttack--
	d.mu.Unlock()

	return nil
}

// StopCleaning 停止流量清洗
func (d *HighDefenseIP) StopCleaning(ip string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	ipInfo.Status = "normal"
	ipInfo.CleaningStatus = nil

	d.stats.mu.Lock()
	d.stats.InCleaning--
	d.mu.Unlock()

	return nil
}

// Blackhole 黑洞路由
func (d *HighDefenseIP) Blackhole(ip string, duration time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	ipInfo.Status = "blackholed"

	// 实现黑洞路由功能
	// 黑洞路由是一种DDoS防护技术，将攻击流量导入"黑洞"丢弃

	// 1. BGP路由发布
	// 向上游路由器发布特定IP的黑洞路由(null route)
	if err := d.announceBGPBlackhole(ip); err != nil {
		return fmt.Errorf("BGP黑洞路由发布失败: %w", err)
	}

	// 2. 设置黑洞过期时间
	expiryTime := time.Now().Add(duration)
	if ipInfo.BlackholeConfig == nil {
		ipInfo.BlackholeConfig = &BlackholeStatus{}
	}
	ipInfo.BlackholeConfig.Active = true
	ipInfo.BlackholeConfig.StartTime = time.Now()
	ipInfo.BlackholeConfig.ExpiryTime = expiryTime

	// 3. 启动自动解除定时器
	if duration > 0 {
		go func() {
			time.Sleep(duration)
			d.RemoveBlackhole(ip)
		}()
	}

	// 4. 记录日志
	attackLog := &AttackLog{
		IP:          ip,
		Type:        "blackhole",
		Timestamp:   time.Now(),
		Status:      "activated",
		Description: fmt.Sprintf("黑洞路由已激活，持续时间: %v", duration),
	}
	d.attackLogs = append(d.attackLogs, attackLog)

	// 5. 更新统计
	d.stats.mu.Lock()
	if d.stats.UnderAttack > 0 {
		d.stats.UnderAttack--
	}
	d.stats.TotalBlackholes++
	d.stats.mu.Unlock()

	return nil
}

// announceBGPBlackhole 发布BGP黑洞路由
func (d *HighDefenseIP) announceBGPBlackhole(ip string) error {
	// BGP黑洞路由发布的几种方式：

	// 方式1: RTBH (Remotely Triggered Black Hole)
	// - 使用BGP社区属性标记流量
	// - 上游路由器接收到特定社区标记后丢弃流量
	// 社区标记例子: 65535:666 (RFC 7999标准黑洞社区)

	// 方式2: 静态路由
	// - 配置静态路由指向null0接口
	// - 例如: ip route <攻击IP> null0

	// 方式3: 通过API调用
	// - 如果使用云服务商，可调用其DDoS防护API
	// - 例如: 阿里云、腾讯云、AWS Shield等

	if d.config != nil && d.config.BlackholeConfig != nil {
		// 获取BGP配置
		bgpConfig := d.config.BlackholeConfig.BGPConfig

		if bgpConfig != nil {
			// 构建BGP更新消息
			announcement := BGPAnnouncement{
				Prefix:      ip + "/32", // 单个IP的/32前缀
				NextHop:     bgpConfig.BlackholeNextHop,
				Communities: []string{"65535:666"}, // RTBH标准社区
				Timestamp:   time.Now(),
			}

			// 发送到BGP speaker
			if err := d.sendBGPUpdate(announcement); err != nil {
				return fmt.Errorf("BGP更新发送失败: %w", err)
			}
		}

		// 如果配置了外部API
		if d.config.BlackholeConfig.APIURL != "" {
			if err := d.callBlackholeAPI(ip, "activate"); err != nil {
				return fmt.Errorf("黑洞API调用失败: %w", err)
			}
		}
	}

	return nil
}

// sendBGPUpdate 发送BGP更新
func (d *HighDefenseIP) sendBGPUpdate(announcement BGPAnnouncement) error {
	// 实际实现需要：
	// 1. 建立BGP会话连接
	// 2. 发送UPDATE消息
	// 3. 处理响应

	// 这里提供框架实现
	// 生产环境可以使用gobgp库或调用外部BGP speaker

	// 模拟发送
	time.Sleep(10 * time.Millisecond)

	return nil
}

// callBlackholeAPI 调用外部黑洞API
func (d *HighDefenseIP) callBlackholeAPI(ip, action string) error {
	// 调用云服务商或硬件防火墙的黑洞路由API
	// 例如:
	// - POST /api/v1/blackhole
	// - Body: {"ip": "1.2.3.4", "action": "activate"}

	// 这里提供框架实现
	time.Sleep(10 * time.Millisecond)

	return nil
}

// BGPAnnouncement BGP路由公告
type BGPAnnouncement struct {
	Prefix      string    // IP前缀
	NextHop     string    // 下一跳
	Communities []string  // BGP社区
	Timestamp   time.Time // 时间戳
}

// BlackholeStatus 黑洞状态
type BlackholeStatus struct {
	Active     bool      // 是否激活
	StartTime  time.Time // 开始时间
	ExpiryTime time.Time // 过期时间
}

// RemoveBlackhole 解除黑洞
func (d *HighDefenseIP) RemoveBlackhole(ip string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	ipInfo.Status = "normal"

	return nil
}

// AddPolicy 添加防御策略
func (d *HighDefenseIP) AddPolicy(policy *DefensePolicy) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	d.policies[policy.ID] = policy

	return nil
}

// DetectAttack 检测攻击
func (d *HighDefenseIP) DetectAttack(ip string, metrics *AttackMetrics) (*AttackDetection, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return nil, false
	}

	// 检查阈值
	detection := &AttackDetection{
		IP:         ip,
		DetectedAt: time.Now(),
		Metrics:    metrics,
	}

	// DDoS攻击检测
	if metrics.Bandwidth > d.config.Thresholds.DDoSThreshold*1e9 { // Gbps to bps
		detection.AttackType = "ddos"
		detection.Confidence = 0.9
		return detection, true
	}

	// CC攻击检测
	if metrics.QPS > d.config.Thresholds.CCThreshold {
		detection.AttackType = "cc"
		detection.Confidence = 0.85
		return detection, true
	}

	// 带宽攻击检测
	if metrics.Bandwidth > d.config.Thresholds.BandwidthThreshold*1e9 {
		detection.AttackType = "bandwidth"
		detection.Confidence = 0.8
		return detection, true
	}

	// 连接数攻击检测
	if metrics.Connections > d.config.Thresholds.ConnectionThreshold {
		detection.AttackType = "connection"
		detection.Confidence = 0.75
		return detection, true
	}

	ipInfo.Stats.mu.Lock()
	ipInfo.Stats.CurrentBandwidth = metrics.Bandwidth / 1e6 // Mbps
	ipInfo.Stats.CurrentConnections = metrics.Connections
	ipInfo.Stats.CurrentQPS = metrics.QPS
	ipInfo.Stats.mu.Unlock()

	return nil, false
}

// AttackMetrics 攻击指标
type AttackMetrics struct {
	Bandwidth   float64 // bps
	PPS         int64   // packets per second
	QPS         int64   // queries per second
	Connections int64
	PacketRate  int64
}

// AttackDetection 攻击检测结果
type AttackDetection struct {
	IP         string         `json:"ip"`
	AttackType string         `json:"attack_type"`
	Confidence float64        `json:"confidence"`
	DetectedAt time.Time      `json:"detected_at"`
	Metrics    *AttackMetrics `json:"metrics"`
	Severity   string         `json:"severity"` // "low", "medium", "high", "critical"
}

// MitigateAttack 缓解攻击
func (d *HighDefenseIP) MitigateAttack(detection *AttackDetection) (*AttackResponse, error) {
	ip := detection.IP
	startTime := time.Now()

	// 应用防御策略
	d.mu.RLock()
	ipInfo, ok := d.ips[ip]
	d.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("IP不存在: %s", ip)
	}

	response := &AttackResponse{
		ActionsTaken: make([]string, 0),
	}

	// 根据攻击类型采取行动
	switch detection.AttackType {
	case "ddos":
		// 启动流量清洗
		if err := d.StartCleaning(ip, "auto"); err != nil {
			return nil, err
		}
		response.ActionsTaken = append(response.ActionsTaken, "auto_cleaning")

	case "cc":
		// 启动CC防护
		if err := d.EnableCCProtection(ip); err != nil {
			return nil, err
		}
		response.ActionsTaken = append(response.ActionsTaken, "cc_protection")

	case "bandwidth":
		// 带宽限制
		if err := d.ApplyBandwidthLimit(ip, 0.5); err != nil {
			return nil, err
		}
		response.ActionsTaken = append(response.ActionsTaken, "bandwidth_limiting")

	default:
		// 默认使用清洗
		d.StartCleaning(ip, "manual")
		response.ActionsTaken = append(response.ActionsTaken, "manual_cleaning")
	}

	// 更新统计
	d.stats.mu.Lock()
	d.stats.TotalAttacks++
	d.stats.AttacksToday++
	d.stats.UnderAttack++
	d.mu.Unlock()

	ipInfo.Stats.mu.Lock()
	ipInfo.Stats.AttackCount++
	ipInfo.Stats.LastAttackTime = time.Now()
	ipInfo.Stats.mu.Unlock()

	response.ResponseTime = time.Since(startTime)
	response.Effectiveness = 0.95

	return response, nil
}

// EnableCCProtection 启用CC防护
func (d *HighDefenseIP) EnableCCProtection(ip string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	ipInfo.Status = "under_attack"

	return nil
}

// ApplyBandwidthLimit 应用带宽限制
func (d *HighDefenseIP) ApplyBandwidthLimit(ip string, percentage float64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	// 带宽限制实现
	// 通过流量整形(Traffic Shaping)技术限制带宽使用

	// 1. 计算限制后的带宽
	originalBandwidth := ipInfo.Config.Bandwidth // Gbps
	limitedBandwidth := float64(originalBandwidth) * percentage

	// 2. 创建带宽限制配置
	limitConfig := &BandwidthLimitConfig{
		IP:                ip,
		OriginalBandwidth: float64(originalBandwidth),
		LimitedBandwidth:  limitedBandwidth,
		Percentage:        percentage,
		StartTime:         time.Now(),
		Active:            true,
	}

	// 3. 应用流量整形
	// 方法1: Token Bucket算法
	// - 以固定速率向桶中添加令牌
	// - 每个数据包需要消耗令牌才能发送
	// - 桶满时多余令牌丢弃，实现平滑限速

	// 方法2: Leaky Bucket算法
	// - 桶以固定速率漏出数据
	// - 突发流量被缓存在桶中
	// - 桶满时丢弃数据包

	// 方法3: Linux TC (Traffic Control)
	// - 使用HTB (Hierarchical Token Bucket)
	// - 配置类别和过滤器
	// - 精确控制带宽

	if err := d.applyTrafficShaping(limitConfig); err != nil {
		return fmt.Errorf("流量整形应用失败: %w", err)
	}

	// 4. 更新IP状态
	if ipInfo.BandwidthLimit == nil {
		ipInfo.BandwidthLimit = &BandwidthLimitStatus{}
	}
	ipInfo.BandwidthLimit.Active = true
	ipInfo.BandwidthLimit.Config = limitConfig
	ipInfo.BandwidthLimit.AppliedAt = time.Now()

	// 5. 记录日志
	attackLog := &AttackLog{
		IP:        ip,
		Type:      "bandwidth_limit",
		Timestamp: time.Now(),
		Status:    "applied",
		Description: fmt.Sprintf(
			"带宽限制已应用: %.2fGbps -> %.2fGbps (%.0f%%)",
			limitConfig.OriginalBandwidth,
			limitConfig.LimitedBandwidth,
			percentage*100,
		),
	}
	d.attackLogs = append(d.attackLogs, attackLog)

	// 6. 更新统计
	d.stats.mu.Lock()
	d.stats.TotalBandwidthLimits++
	d.stats.mu.Unlock()

	return nil
}

// applyTrafficShaping 应用流量整形
func (d *HighDefenseIP) applyTrafficShaping(config *BandwidthLimitConfig) error {
	// 实现流量整形的几种方式：

	// 方式1: Linux TC命令
	// tc qdisc add dev eth0 root handle 1: htb default 10
	// tc class add dev eth0 parent 1: classid 1:1 htb rate <limitedBandwidth>
	// tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst <ip> flowid 1:1

	// 方式2: iptables + tc
	// iptables -A FORWARD -d <ip> -j MARK --set-mark 10
	// tc filter add dev eth0 parent 1:0 prio 1 handle 10 fw flowid 1:1

	// 方式3: 使用第三方库或硬件
	// - 如果有专用DDoS防护硬件，调用其API
	// - 使用SDN控制器下发流控规则

	// 方式4: 应用层限速
	// - 使用速率限制器(Rate Limiter)
	// - 在代理层控制转发速率

	// 这里提供框架实现
	// 实际部署时需要根据网络环境选择合适的方案

	limitMbps := config.LimitedBandwidth * 1000 // Gbps to Mbps

	// 构建TC命令（示例）
	tcCommand := fmt.Sprintf(
		"tc class add dev eth0 parent 1: classid 1:10 htb rate %dmbit",
		int(limitMbps),
	)

	_ = tcCommand // 实际需要执行这个命令

	// 应用限制
	time.Sleep(10 * time.Millisecond)

	return nil
}

// RemoveBandwidthLimit 移除带宽限制
func (d *HighDefenseIP) RemoveBandwidthLimit(ip string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipInfo, ok := d.ips[ip]
	if !ok {
		return fmt.Errorf("IP不存在: %s", ip)
	}

	if ipInfo.BandwidthLimit == nil || !ipInfo.BandwidthLimit.Active {
		return fmt.Errorf("该IP没有激活的带宽限制")
	}

	// 移除流量整形规则
	if err := d.removeTrafficShaping(ipInfo.BandwidthLimit.Config); err != nil {
		return fmt.Errorf("移除流量整形失败: %w", err)
	}

	// 更新状态
	ipInfo.BandwidthLimit.Active = false
	ipInfo.BandwidthLimit.RemovedAt = time.Now()

	// 记录日志
	attackLog := &AttackLog{
		IP:          ip,
		Type:        "bandwidth_limit",
		Timestamp:   time.Now(),
		Status:      "removed",
		Description: "带宽限制已移除",
	}
	d.attackLogs = append(d.attackLogs, attackLog)

	return nil
}

// removeTrafficShaping 移除流量整形
func (d *HighDefenseIP) removeTrafficShaping(config *BandwidthLimitConfig) error {
	// 移除TC规则
	// tc class del dev eth0 parent 1: classid 1:10

	time.Sleep(10 * time.Millisecond)
	return nil
}

// BandwidthLimitConfig 带宽限制配置
type BandwidthLimitConfig struct {
	IP                string    // IP地址
	OriginalBandwidth float64   // 原始带宽(Gbps)
	LimitedBandwidth  float64   // 限制后带宽(Gbps)
	Percentage        float64   // 限制百分比
	StartTime         time.Time // 开始时间
	Active            bool      // 是否激活
}

// BandwidthLimitStatus 带宽限制状态
type BandwidthLimitStatus struct {
	Active    bool                  // 是否激活
	Config    *BandwidthLimitConfig // 配置
	AppliedAt time.Time             // 应用时间
	RemovedAt time.Time             // 移除时间
}

// GetAttackLogs 获取攻击日志
func (d *HighDefenseIP) GetAttackLogs(page, pageSize int) ([]*AttackLog, int64) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	total := int64(len(d.attackLogs))
	start := (page - 1) * pageSize
	end := start + pageSize

	if start > len(d.attackLogs) {
		return nil, total
	}

	if end > len(d.attackLogs) {
		end = len(d.attackLogs)
	}

	return d.attackLogs[start:end], total
}

// LogAttack 记录攻击
func (d *HighDefenseIP) LogAttack(log *AttackLog) {
	d.mu.Lock()
	defer d.mu.Unlock()

	log.ID = fmt.Sprintf("atk_%d", time.Now().UnixNano())
	d.attackLogs = append(d.attackLogs, log)
}

// GetStats 获取统计
func (d *HighDefenseIP) GetStats() *DefenseStats {
	d.stats.mu.RLock()
	defer d.stats.mu.RUnlock()

	return d.stats
}

// GetCleaningCenters 获取清洗中心列表
func (d *HighDefenseIP) GetCleaningCenters() []*CleaningCenter {
	centers := make([]*CleaningCenter, 0)

	for _, addr := range d.config.CleaningCenter.Addresses {
		centers = append(centers, &CleaningCenter{
			Address:  addr,
			Status:   "online",
			Capacity: d.config.DefaultConfig.CleaningCapacity,
		})
	}

	return centers
}

// CleaningCenter 清洗中心
type CleaningCenter struct {
	Address  string        `json:"address"`
	Status   string        `json:"status"`   // "online", "offline", "busy"
	Capacity int           `json:"capacity"` // Gbps
	Latency  time.Duration `json:"latency"`
}

// SimulateAttack 模拟攻击测试
func (d *HighDefenseIP) SimulateAttack(ip string, attackType string, intensity float64) (*AttackSimulation, error) {
	simulation := &AttackSimulation{
		IP:         ip,
		AttackType: attackType,
		Intensity:  intensity,
		StartTime:  time.Now(),
	}

	// 验证IP是否存在
	d.mu.RLock()
	ipInfo, exists := d.ips[ip]
	d.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("IP不存在: %s", ip)
	}

	// 验证攻击类型
	validTypes := map[string]bool{
		"ddos":       true,
		"cc":         true,
		"syn_flood":  true,
		"udp_flood":  true,
		"icmp_flood": true,
		"http_flood": true,
		"slowloris":  true,
	}

	if !validTypes[attackType] {
		return nil, fmt.Errorf("不支持的攻击类型: %s", attackType)
	}

	// 验证强度
	if intensity < 0 || intensity > 1 {
		return nil, fmt.Errorf("攻击强度必须在0-1之间")
	}

	// 计算模拟流量
	baseTraffic := int64(100 * 1024 * 1024) // 100MB base
	trafficUsed := baseTraffic + int64(intensity*float64(baseTraffic))

	// 生成模拟攻击
	simulation.TrafficUsed = trafficUsed
	simulation.Metrics = d.generateAttackMetrics(attackType, intensity, trafficUsed)

	// 模拟执行时间
	duration := time.Duration(5+int(intensity*15)) * time.Second
	time.Sleep(duration)

	// 模拟防护结果
	simulation.EndTime = time.Now()

	// 根据攻击类型和强度计算模拟结果
	if ipInfo.ProtectionLevel == "enterprise" {
		simulation.Result = "mitigated"
	} else if ipInfo.ProtectionLevel == "advanced" && intensity < 0.7 {
		simulation.Result = "mitigated"
	} else if intensity < 0.3 {
		simulation.Result = "mitigated"
	} else {
		simulation.Result = "partial"
	}

	// 记录攻击日志
	d.LogAttack(&AttackLog{
		ID:            fmt.Sprintf("atk_sim_%d", time.Now().UnixNano()),
		IP:            ip,
		Type:          attackType,
		StartTime:     simulation.StartTime,
		EndTime:       simulation.EndTime,
		AttackTraffic: trafficUsed,
		AttackRate:    float64(trafficUsed) / duration.Seconds(),
		Response: &AttackResponse{
			ActionsTaken:   []string{"simulation"},
			CleanedTraffic: int64(float64(trafficUsed) * 0.95),
			ResponseTime:   duration,
			Effectiveness:  0.95,
		},
		Result: simulation.Result,
	})

	return simulation, nil
}

// generateAttackMetrics 生成攻击指标
func (d *HighDefenseIP) generateAttackMetrics(attackType string, intensity float64, traffic int64) *AttackMetrics {
	baseMetrics := &AttackMetrics{
		Bandwidth:   float64(traffic) * 8, // bits per second
		PacketRate:  int64(100000 + int(float64(100000)*intensity)),
		QPS:         int64(5000 + int(float64(5000)*intensity)),
		Connections: int64(1000 + int(float64(1000)*intensity)),
	}

	switch attackType {
	case "ddos":
		baseMetrics.Bandwidth = float64(traffic) * 10 // Higher bandwidth
		baseMetrics.PacketRate = int64(500000 + int(float64(500000)*intensity))
	case "cc":
		baseMetrics.QPS = int64(50000 + int(float64(50000)*intensity))
		baseMetrics.Connections = int64(10000 + int(float64(10000)*intensity))
	case "syn_flood":
		baseMetrics.PacketRate = int64(200000 + int(float64(200000)*intensity))
		baseMetrics.Connections = int64(5000 + int(float64(5000)*intensity))
	case "udp_flood":
		baseMetrics.Bandwidth = float64(traffic) * 8
		baseMetrics.PacketRate = int64(300000 + int(float64(300000)*intensity))
	case "http_flood":
		baseMetrics.QPS = int64(100000 + int(float64(100000)*intensity))
		baseMetrics.Connections = int64(50000 + int(float64(50000)*intensity))
	case "slowloris":
		baseMetrics.Connections = int64(50000 + int(float64(50000)*intensity))
		baseMetrics.QPS = int64(1000) // Low QPS but high connections
	case "icmp_flood":
		baseMetrics.PacketRate = int64(150000 + int(float64(150000)*intensity))
	}

	return baseMetrics
}

// AttackSimulation 攻击模拟
type AttackSimulation struct {
	IP          string         `json:"ip"`
	AttackType  string         `json:"attack_type"`
	Intensity   float64        `json:"intensity"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     time.Time      `json:"end_time"`
	TrafficUsed int64          `json:"traffic_used"`
	Result      string         `json:"result"` // "mitigated", "partial", "failed"
	Metrics     *AttackMetrics `json:"metrics"`
}

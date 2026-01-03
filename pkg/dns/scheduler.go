package dns

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/pkg/iplib"
	"github.com/patrickmn/go-cache"
)

// DNSScheduler DNS智能调度服务
type DNSScheduler struct {
	config      *SchedulerConfig
	providers   []DNSProvider
	records     map[string][]DNSRecord
	geoMap      *GeoMap
	healthCheck *HealthChecker
	analytics   *DNSAnalytics
	mu          sync.RWMutex
	stats       *SchedulerStats
	ctx         context.Context
	cancel      context.CancelFunc
	cache       *cache.Cache
}

// SchedulerConfig 调度配置
type SchedulerConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 调度策略
	Strategy string `yaml:"strategy"` // "geo", "latency", "load", "weighted", "smart"

	// 默认TTL
	DefaultTTL time.Duration `yaml:"default_ttl"`

	// 健康检查配置
	HealthCheck HealthCheckConfig `yaml:"health_check"`

	// 地理定位配置
	GeoConfig GeoConfig `yaml:"geo_config"`

	// 负载均衡配置
	LoadBalanceConfig LoadBalanceConfig `yaml:"load_balance_config"`

	// 故障转移配置
	FailoverConfig FailoverConfig `yaml:"failover_config"`

	// 备用DNS提供商
	BackupProviders []string `yaml:"backup_providers"`
}

// GetHealthCheckConfig 获取健康检查配置
func (c *SchedulerConfig) GetHealthCheckConfig() *HealthCheckConfig {
	if c.HealthCheck.Interval <= 0 {
		c.HealthCheck.Interval = 30 * time.Second
	}
	if c.HealthCheck.Timeout <= 0 {
		c.HealthCheck.Timeout = 5 * time.Second
	}
	if c.HealthCheck.Type == "" {
		c.HealthCheck.Type = "tcp"
	}
	return &c.HealthCheck
}

// DNSProvider DNS提供商
type DNSProvider struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // "aliyun", "dnspod", "cloudflare", "aws_route53", "custom"
	APIKey    string `json:"api_key"`
	SecretKey string `json:"secret_key"`
	Endpoint  string `json:"endpoint"`
	Enabled   bool   `json:"enabled"`
	Weight    int    `json:"weight"`
	Priority  int    `json:"priority"`
}

// DNSRecord DNS记录
type DNSRecord struct {
	ID        string        `json:"id"`
	Type      string        `json:"type"` // "A", "AAAA", "CNAME", "MX", "TXT", "NS"
	Name      string        `json:"name"`
	Value     string        `json:"value"`
	TTL       time.Duration `json:"ttl"`
	Weight    int           `json:"weight"`
	Priority  int           `json:"priority"`
	GeoTarget string        `json:"geo_target"` // 地理目标
	Enabled   bool          `json:"enabled"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// GeoConfig 地理配置
type GeoConfig struct {
	// 启用地理定位
	Enabled bool `yaml:"enabled"`

	// 默认区域
	DefaultRegion string `yaml:"default_region"`

	// 区域映射
	RegionMapping map[string][]string `yaml:"region_mapping"` // "cn" -> ["中国大陆"]

	// IP库路径
	IPDatabasePath string `yaml:"ip_database_path"`
}

// LoadBalanceConfig 负载均衡配置
type LoadBalanceConfig struct {
	// 启用负载均衡
	Enabled bool `yaml:"enabled"`

	// 算法
	Algorithm string `yaml:"algorithm"` // "round_robin", "least_conn", "weighted", "ip_hash"

	// 检查间隔
	CheckInterval time.Duration `yaml:"check_interval"`

	// 最大连接数阈值
	MaxConnections int `yaml:"max_connections"`

	// 响应时间阈值
	ResponseTimeThreshold time.Duration `json:"response_time_threshold"`
}

// FailoverConfig 故障转移配置
type FailoverConfig struct {
	// 启用故障转移
	Enabled bool `yaml:"enabled"`

	// 检测间隔
	CheckInterval time.Duration `yaml:"check_interval"`

	// 故障阈值
	FailureThreshold int `yaml:"failure_threshold"` // 连续失败次数

	// 恢复阈值
	RecoveryThreshold int `yaml:"recovery_threshold"` // 连续成功次数

	// 切换时间
	SwitchoverTime time.Duration `yaml:"switchover_time"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	// 启用健康检查
	Enabled bool `yaml:"enabled"`

	// 检查间隔
	Interval time.Duration `yaml:"interval"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 检查类型
	Type string `yaml:"type"` // "tcp", "http", "ping"

	// 检查路径
	Path string `yaml:"path"`

	// 预期状态码
	ExpectedStatusCode int `yaml:"expected_status_code"`
}

// GeoMap 地理映射
type GeoMap struct {
	ipLib         iplib.IPLib
	defaultRegion string
	regionMapping map[string][]string
	regionDB      map[string]*RegionInfo
	mu            sync.RWMutex
}

// RegionInfo 区域信息
type RegionInfo struct {
	Name       string   `json:"name"`
	Code       string   `json:"code"`
	Countries  []string `json:"countries"`
	ISPs       []string `json:"isps"`
	Latency    float64  `json:"latency"`
	Throughput float64  `json:"throughput"`
	Load       float64  `json:"load"`
}

// HealthChecker 健康检查器
type HealthChecker struct {
	config  *HealthCheckConfig
	results map[string]*HealthResult
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// HealthResult 健康检查结果
type HealthResult struct {
	Target       string        `json:"target"`
	Status       string        `json:"status"` // "healthy", "degraded", "unhealthy"
	LastCheck    time.Time     `json:"last_check"`
	ResponseTime time.Duration `json:"response_time"`
	SuccessRate  float64       `json:"success_rate"`
	FailureCount int           `json:"failure_count"`
}

// DNSAnalytics DNS分析
type DNSAnalytics struct {
	queries     []QueryLog
	queryCounts map[string]int64
	mu          sync.RWMutex
}

// QueryLog 查询日志
type QueryLog struct {
	Domain    string        `json:"domain"`
	ClientIP  string        `json:"client_ip"`
	QueryType string        `json:"query_type"`
	Region    string        `json:"region"`
	ISP       string        `json:"isp"`
	Latency   time.Duration `json:"latency"`
	Timestamp time.Time     `json:"timestamp"`
}

// SchedulerStats 调度统计
type SchedulerStats struct {
	TotalQueries      int64                    `json:"total_queries"`
	QueriesByRegion   map[string]int64         `json:"queries_by_region"`
	QueriesByProvider map[string]int64         `json:"queries_by_provider"`
	AverageLatency    time.Duration            `json:"average_latency"`
	LatencyByRegion   map[string]time.Duration `json:"latency_by_region"`
	FailoverCount     int64                    `json:"failover_count"`
	HealthCheckCount  int64                    `json:"health_check_count"`
	HealthyProviders  int                      `json:"healthy_providers"`
	TotalProviders    int                      `json:"total_providers"`
	mu                sync.RWMutex
}

// NewDNSScheduler 创建DNS调度服务
func NewDNSScheduler(config *SchedulerConfig) *DNSScheduler {
	if config == nil {
		config = &SchedulerConfig{
			Enabled:    true,
			Strategy:   "smart",
			DefaultTTL: 300 * time.Second,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defaultTTL := config.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = 300 * time.Second
	}
	cleanupInterval := defaultTTL * 2
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}

	return &DNSScheduler{
		config:      config,
		records:     make(map[string][]DNSRecord),
		geoMap:      NewGeoMap(&config.GeoConfig),
		healthCheck: NewHealthChecker(config.GetHealthCheckConfig(), ctx),
		analytics:   &DNSAnalytics{queryCounts: make(map[string]int64)},
		stats: &SchedulerStats{
			QueriesByRegion:   make(map[string]int64),
			QueriesByProvider: make(map[string]int64),
			LatencyByRegion:   make(map[string]time.Duration),
		},
		ctx:    ctx,
		cancel: cancel,
		cache:  cache.New(defaultTTL, cleanupInterval),
	}
}

// NewGeoMap 创建地理映射
func NewGeoMap(config *GeoConfig) *GeoMap {
	geoMap := &GeoMap{
		regionDB: make(map[string]*RegionInfo),
	}
	if config == nil {
		return geoMap
	}

	geoMap.defaultRegion = config.DefaultRegion
	geoMap.regionMapping = config.RegionMapping

	if config.IPDatabasePath == "" {
		return geoMap
	}

	lib := iplib.NewProfessionalIPLib()
	if err := lib.Init(config.IPDatabasePath); err == nil {
		geoMap.ipLib = lib
	}

	return geoMap
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker(config *HealthCheckConfig, ctx context.Context) *HealthChecker {
	if config == nil {
		config = &HealthCheckConfig{
			Enabled:  true,
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
			Type:     "tcp",
		}
	}

	checkCtx, cancel := context.WithCancel(ctx)

	checker := &HealthChecker{
		config:  config,
		results: make(map[string]*HealthResult),
		ctx:     checkCtx,
		cancel:  cancel,
	}

	// 启动健康检查
	go checker.runChecks()

	return checker
}

// AddProvider 添加DNS提供商
func (s *DNSScheduler) AddProvider(provider DNSProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.providers = append(s.providers, provider)
}

// AddRecord 添加DNS记录
func (s *DNSScheduler) AddRecord(record DNSRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[record.Name] = append(s.records[record.Name], record)
}

// Resolve 智能解析域名
func (s *DNSScheduler) Resolve(domain, clientIP string) ([]net.IP, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 获取客户端区域
	region := s.geoMap.GetRegion(clientIP)

	// 获取记录
	records := s.records[domain]
	if len(records) == 0 {
		return nil, nil
	}

	// 根据策略选择记录
	switch s.config.Strategy {
	case "geo":
		return s.geoResolve(records, region, clientIP)
	case "latency":
		return s.latencyResolve(records, clientIP)
	case "load":
		return s.loadResolve(records)
	case "weighted":
		return s.weightedResolve(records)
	case "smart":
		return s.smartResolve(records, region, clientIP)
	default:
		return s.weightedResolve(records)
	}
}

// geoResolve 地理定位解析
func (s *DNSScheduler) geoResolve(records []DNSRecord, region, clientIP string) ([]net.IP, error) {
	var matchedRecords []DNSRecord

	for _, record := range records {
		if !record.Enabled {
			continue
		}
		if record.GeoTarget == "" || record.GeoTarget == region {
			matchedRecords = append(matchedRecords, record)
		}
	}

	if len(matchedRecords) == 0 {
		matchedRecords = records
	}

	return s.recordsToIPs(matchedRecords)
}

// latencyResolve 延迟优先解析
func (s *DNSScheduler) latencyResolve(records []DNSRecord, clientIP string) ([]net.IP, error) {
	// 选择响应时间最短的记录
	var bestRecord *DNSRecord
	var minLatency time.Duration

	for i := range records {
		if !records[i].Enabled {
			continue
		}

		latency := s.measureLatency(records[i].Value)
		if bestRecord == nil || latency < minLatency {
			bestRecord = &records[i]
			minLatency = latency
		}
	}

	if bestRecord == nil {
		return nil, nil
	}

	return s.recordsToIPs([]DNSRecord{*bestRecord})
}

// loadResolve 负载均衡解析
func (s *DNSScheduler) loadResolve(records []DNSRecord) ([]net.IP, error) {
	var enabledRecords []DNSRecord
	for _, record := range records {
		if record.Enabled {
			enabledRecords = append(enabledRecords, record)
		}
	}

	if len(enabledRecords) == 0 {
		return nil, nil
	}

	// 简单轮询
	index := time.Now().UnixNano() % int64(len(enabledRecords))
	return s.recordsToIPs([]DNSRecord{enabledRecords[index]})
}

// weightedResolve 权重解析
func (s *DNSScheduler) weightedResolve(records []DNSRecord) ([]net.IP, error) {
	var enabledRecords []DNSRecord
	totalWeight := 0

	for _, record := range records {
		if record.Enabled {
			enabledRecords = append(enabledRecords, record)
			totalWeight += record.Weight
		}
	}

	if len(enabledRecords) == 0 {
		return nil, nil
	}

	// 权重选择
	random := time.Now().UnixNano() % int64(totalWeight)
	accumulated := 0

	for _, record := range enabledRecords {
		accumulated += record.Weight
		if int64(accumulated) > random {
			return s.recordsToIPs([]DNSRecord{record})
		}
	}

	return s.recordsToIPs([]DNSRecord{enabledRecords[0]})
}

// smartResolve 智能解析（综合多种因素）
func (s *DNSScheduler) smartResolve(records []DNSRecord, region, clientIP string) ([]net.IP, error) {
	var candidates []DNSRecord

	for _, record := range records {
		if !record.Enabled {
			continue
		}

		// 检查健康状态
		result := s.healthCheck.results[record.Value]
		if result != nil && result.Status == "unhealthy" {
			continue
		}

		// 地理匹配优先
		if record.GeoTarget == region {
			candidates = append(candidates, record)
		} else if record.GeoTarget == "" {
			candidates = append(candidates, record)
		}
	}

	if len(candidates) == 0 {
		// 如果没有匹配的，返回所有可用记录
		for _, record := range records {
			if record.Enabled {
				candidates = append(candidates, record)
			}
		}
	}

	return s.weightedResolve(candidates)
}

// recordsToIPs 将DNS记录转换为IP地址
func (s *DNSScheduler) recordsToIPs(records []DNSRecord) ([]net.IP, error) {
	var ips []net.IP

	for _, record := range records {
		if record.Type == "A" {
			if ip := net.ParseIP(record.Value); ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

// measureLatency 测量延迟
func (s *DNSScheduler) measureLatency(host string) time.Duration {
	start := time.Now()

	// 简单的TCP连接测试
	conn, err := net.DialTimeout("tcp", host+":80", 5*time.Second)
	if err != nil {
		return 10 * time.Second
	}
	defer conn.Close()

	return time.Since(start)
}

// runChecks 运行健康检查
func (c *HealthChecker) runChecks() {
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.performChecks()
		}
	}
}

// performChecks 执行检查
func (c *HealthChecker) performChecks() {
	c.mu.RLock()
	c.mu.RUnlock()

	for target, result := range c.results {
		c.checkTarget(target, result)
	}
}

// checkTarget 检查目标
func (c *HealthChecker) checkTarget(target string, result *HealthResult) {
	if result == nil {
		result = &HealthResult{
			Target: target,
			Status: "unknown",
		}
	}

	switch c.config.Type {
	case "tcp":
		c.tcpCheck(target, result)
	case "http":
		c.httpCheck(target, result)
	case "ping":
		c.pingCheck(target, result)
	}
}

// tcpCheck TCP检查
func (c *HealthChecker) tcpCheck(target string, result *HealthResult) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", target, c.config.Timeout)
	if err != nil {
		c.recordFailure(target, result, time.Since(start))
		return
	}
	defer conn.Close()

	c.recordSuccess(target, result, time.Since(start))
}

// httpCheck HTTP检查
func (c *HealthChecker) httpCheck(target string, result *HealthResult) {
	start := time.Now()
	path := c.config.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	urlStr := target
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		c.recordFailure(target, result, time.Since(start))
		return
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = path
	}

	client := &http.Client{Timeout: c.config.Timeout}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, parsed.String(), nil)
	if err != nil {
		c.recordFailure(target, result, time.Since(start))
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		c.recordFailure(target, result, time.Since(start))
		return
	}
	defer resp.Body.Close()

	expected := c.config.ExpectedStatusCode
	latency := time.Since(start)
	if expected > 0 {
		if resp.StatusCode == expected {
			c.recordSuccess(target, result, latency)
		} else {
			c.recordFailure(target, result, latency)
		}
		return
	}

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
		c.recordSuccess(target, result, latency)
		return
	}
	c.recordFailure(target, result, latency)
}

// pingCheck Ping检查
func (c *HealthChecker) pingCheck(target string, result *HealthResult) {
	start := time.Now()
	host := target

	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		if parsed, err := url.Parse(host); err == nil {
			host = parsed.Hostname()
		}
	}
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	if strings.TrimSpace(host) == "" {
		c.recordFailure(target, result, time.Since(start))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", host}
	} else {
		args = []string{"-c", "1", host}
	}

	cmd := exec.CommandContext(ctx, "ping", args...)
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		c.recordFailure(target, result, time.Since(start))
		return
	}
	c.recordSuccess(target, result, time.Since(start))
}

// recordFailure 记录失败
func (c *HealthChecker) recordFailure(target string, result *HealthResult, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result.FailureCount++
	result.LastCheck = time.Now()
	result.ResponseTime = latency

	if result.FailureCount >= 3 {
		result.Status = "unhealthy"
	} else {
		result.Status = "degraded"
	}

	c.results[target] = result
}

// recordSuccess 记录成功
func (c *HealthChecker) recordSuccess(target string, result *HealthResult, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result.FailureCount = 0
	result.LastCheck = time.Now()
	result.ResponseTime = latency
	result.Status = "healthy"
	result.SuccessRate = 1.0

	c.results[target] = result
}

// GetRegion 获取区域
func (m *GeoMap) GetRegion(ip string) string {
	m.mu.RLock()
	defaultRegion := m.defaultRegion
	regionMapping := m.regionMapping
	ipLib := m.ipLib
	m.mu.RUnlock()

	ipBytes := net.ParseIP(ip)
	if ipBytes == nil {
		if defaultRegion != "" {
			return defaultRegion
		}
		return "unknown"
	}

	if ipLib != nil {
		if info, err := ipLib.Query(ipBytes); err == nil && info != nil {
			if region := mapRegion(info, regionMapping); region != "" {
				return region
			}
			if info.CountryCode != "" && info.CountryCode != "XX" {
				return strings.ToLower(info.CountryCode)
			}
		}
	}

	if ipBytes.IsPrivate() {
		if defaultRegion != "" {
			return defaultRegion
		}
		return "cn"
	}
	if defaultRegion != "" {
		return defaultRegion
	}
	return "other"
}

// GetStats 获取统计
func (s *DNSScheduler) GetStats() *SchedulerStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return s.stats
}

// ResolveWithCache 带缓存的解析
func (s *DNSScheduler) ResolveWithCache(domain, clientIP string, ttl time.Duration) ([]net.IP, error) {
	if s.cache != nil {
		key := strings.ToLower(domain) + "|" + clientIP
		if cached, ok := s.cache.Get(key); ok {
			if ips, ok := cached.([]net.IP); ok {
				return append([]net.IP(nil), ips...), nil
			}
		}
	}

	ips, err := s.Resolve(domain, clientIP)
	if err != nil || len(ips) == 0 {
		return ips, err
	}

	if ttl <= 0 {
		ttl = s.config.DefaultTTL
	}
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	if s.cache != nil {
		s.cache.Set(strings.ToLower(domain)+"|"+clientIP, ips, ttl)
	}

	return ips, nil
}

func mapRegion(info *iplib.IPInfo, mapping map[string][]string) string {
	if info == nil || len(mapping) == 0 {
		return ""
	}

	if info.CountryCode != "" {
		code := strings.ToLower(info.CountryCode)
		if _, ok := mapping[code]; ok {
			return code
		}
	}

	for code, aliases := range mapping {
		for _, alias := range aliases {
			if alias == "" {
				continue
			}
			if strings.EqualFold(alias, info.Country) ||
				strings.EqualFold(alias, info.Region) ||
				strings.EqualFold(alias, info.City) {
				return code
			}
		}
	}

	return ""
}

// ForceFailover 强制故障转移
func (s *DNSScheduler) ForceFailover(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 触发故障转移
	records := s.records[domain]
	for i := range records {
		records[i].Enabled = !records[i].Enabled
	}

	s.stats.mu.Lock()
	s.stats.FailoverCount++
	s.stats.mu.Unlock()
}

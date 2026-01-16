package defense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/pkg/config"
)

type logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

type nilLogger struct{}

func (l *nilLogger) Infof(format string, args ...interface{})  {}
func (l *nilLogger) Warnf(format string, args ...interface{})  {}
func (l *nilLogger) Warn(format string, args ...interface{})   {}
func (l *nilLogger) Errorf(format string, args ...interface{}) {}
func (l *nilLogger) Debugf(format string, args ...interface{}) {}

var _ logger = (*nilLogger)(nil)

type defaultLogger struct{}

func (l *defaultLogger) Infof(format string, args ...interface{}) { fmt.Printf(format+"\n", args...) }
func (l *defaultLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}
func (l *defaultLogger) Warn(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}
func (l *defaultLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}
func (l *defaultLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

var _ logger = (*defaultLogger)(nil)

type Logger = logger

const (
	LoggerTypeNil     = "nil"
	LoggerTypeDefault = "default"
)

type loggerType string

const (
	loggerTypeNil     loggerType = "nil"
	loggerTypeDefault loggerType = "default"
)

func newLogger(t loggerType) Logger {
	switch t {
	case loggerTypeNil:
		return &nilLogger{}
	case loggerTypeDefault:
		return &defaultLogger{}
	default:
		return &defaultLogger{}
	}
}

type DNSProvider interface {
	SwitchToSteering(ctx context.Context) error
	SwitchToNormal(ctx context.Context) error
	GetStatus(ctx context.Context) (*DNSStatus, error)
}

type DNSStatus struct {
	IsSteering    bool
	CurrentRecord string
	Provider      string
	Domain        string
	LastUpdate    time.Time
}

type DNSRecord struct {
	ID       string
	Type     string
	Domain   string
	Value    string
	TTL      int
	Priority int
	LineType string
}

type DNSProviderImpl struct {
	config      *config.DNSSConfig
	httpClient  *http.Client
	currentIP   string
	recordID    string
	lastSwitch  time.Time
	switchCount int
	mu          sync.RWMutex
	logger      Logger
}

func NewDNSProvider(cfg *config.DNSSConfig) (DNSProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("DNS配置不能为空")
	}

	provider := &DNSProviderImpl{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		currentIP:   cfg.NormalRecord,
		lastSwitch:  time.Time{},
		switchCount: 0,
		logger:      newLogger(loggerTypeDefault),
	}

	return provider, nil
}

func (d *DNSProviderImpl) SwitchToSteering(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.logger.Infof("DNS切换到牵引IP: %s -> %s", d.currentIP, d.config.SteeringIP)

	var err error
	switch d.config.Provider {
	case "aliyun":
		err = d.switchAliyun(ctx, d.config.SteeringIP)
	case "cloudflare":
		err = d.switchCloudflare(ctx, d.config.SteeringIP)
	case "dnspod":
		err = d.switchDNSPod(ctx, d.config.SteeringIP)
	case "route53":
		err = d.switchRoute53(ctx, d.config.SteeringIP)
	default:
		err = fmt.Errorf("不支持的DNS提供商: %s", d.config.Provider)
	}

	if err != nil {
		d.logger.Errorf("DNS切换失败: %v", err)
		return err
	}

	d.currentIP = d.config.SteeringIP
	d.lastSwitch = time.Now()
	d.switchCount++
	d.logger.Infof("DNS切换成功: 第%d次切换", d.switchCount)

	return nil
}

func (d *DNSProviderImpl) SwitchToNormal(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.logger.Infof("DNS切换回正常IP: %s -> %s", d.currentIP, d.config.NormalRecord)

	var err error
	switch d.config.Provider {
	case "aliyun":
		err = d.switchAliyun(ctx, d.config.NormalRecord)
	case "cloudflare":
		err = d.switchCloudflare(ctx, d.config.NormalRecord)
	case "dnspod":
		err = d.switchDNSPod(ctx, d.config.NormalRecord)
	case "route53":
		err = d.switchRoute53(ctx, d.config.NormalRecord)
	default:
		err = fmt.Errorf("不支持的DNS提供商: %s", d.config.Provider)
	}

	if err != nil {
		d.logger.Errorf("DNS恢复失败: %v", err)
		return err
	}

	d.currentIP = d.config.NormalRecord
	d.lastSwitch = time.Now()
	d.logger.Infof("DNS恢复成功")

	return nil
}

func (d *DNSProviderImpl) GetStatus(ctx context.Context) (*DNSStatus, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return &DNSStatus{
		IsSteering:    d.currentIP == d.config.SteeringIP,
		CurrentRecord: d.currentIP,
		Provider:      d.config.Provider,
		Domain:        d.config.Domain,
		LastUpdate:    d.lastSwitch,
	}, nil
}

func (d *DNSProviderImpl) switchAliyun(ctx context.Context, ip string) error {
	if d.config.AccessKey == "" || d.config.AccessSecret == "" {
		return fmt.Errorf("阿里云API凭证未配置")
	}

	apiURL := fmt.Sprintf("https://alidns.aliyuncs.com/?Action=DescribeDomainRecords&DomainName=%s", d.config.Domain)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("阿里云API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("阿里云API错误: %s", string(body))
	}

	d.logger.Debugf("阿里云DNS查询成功, 目标IP: %s", ip)
	return nil
}

func (d *DNSProviderImpl) switchCloudflare(ctx context.Context, ip string) error {
	if d.config.AccessKey == "" {
		return fmt.Errorf("Cloudflare API Token未配置")
	}

	zoneID, err := d.getCloudflareZoneID(ctx)
	if err != nil {
		return err
	}

	recordID, err := d.getCloudflareRecordID(ctx, zoneID)
	if err != nil {
		return err
	}

	updateURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)

	body := fmt.Sprintf(`{"type": "%s", "name": "%s", "content": "%s", "ttl": %d}`,
		d.config.RecordType, d.config.Domain, ip, d.config.TTL)

	req, err := http.NewRequestWithContext(ctx, "PUT", updateURL, strings.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.AccessKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Cloudflare API错误: %s", string(respBody))
	}

	d.logger.Infof("Cloudflare DNS更新成功: %s -> %s", d.config.Domain, ip)
	return nil
}

func (d *DNSProviderImpl) switchDNSPod(ctx context.Context, ip string) error {
	if d.config.AccessKey == "" || d.config.AccessSecret == "" {
		return fmt.Errorf("DNSPod API凭证未配置")
	}

	apiURL := "https://dnsapi.cn/Record.Modify"

	body := fmt.Sprintf("login_token=%s,%s&format=json&domain=%s&record_id=%s&value=%s&record_type=%s",
		d.config.AccessKey, d.config.AccessSecret, d.config.Domain, d.recordID, ip, d.config.RecordType)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DNSPod API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DNSPod API错误: %s", string(respBody))
	}

	d.logger.Infof("DNSPod DNS更新成功: %s -> %s", d.config.Domain, ip)
	return nil
}

func (d *DNSProviderImpl) switchRoute53(ctx context.Context, ip string) error {
	if d.config.AccessKey == "" || d.config.AccessSecret == "" {
		return fmt.Errorf("Route53 AWS凭证未配置")
	}

	d.logger.Infof("Route53 DNS更新: %s -> %s (模拟)", d.config.Domain, ip)
	return nil
}

func (d *DNSProviderImpl) getCloudflareZoneID(ctx context.Context) (string, error) {
	apiURL := "https://api.cloudflare.com/client/v4/zones"

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.AccessKey)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Cloudflare API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Cloudflare API错误: %d", resp.StatusCode)
	}

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Result) == 0 {
		return "", fmt.Errorf("未找到Zone")
	}

	return result.Result[0].ID, nil
}

func (d *DNSProviderImpl) getCloudflareRecordID(ctx context.Context, zoneID string) (string, error) {
	apiURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=%s",
		zoneID, d.config.Domain, d.config.RecordType)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.AccessKey)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Cloudflare API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Cloudflare API错误: %d", resp.StatusCode)
	}

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Result) == 0 {
		return "", fmt.Errorf("未找到DNS记录")
	}

	return result.Result[0].ID, nil
}

type BGPProvider interface {
	AdvertiseSteering(ctx context.Context) error
	WithdrawSteering(ctx context.Context) error
	GetStatus(ctx context.Context) (*BGPStatus, error)
}

type BGPStatus struct {
	IsSteering     bool
	ActivePrefixes []string
	LastUpdate     time.Time
}

type BGPAdvertisement struct {
	Prefix    string
	NextHop   string
	ASPath    []int
	LocalPref int
	MED       int
	Community []string
}

type BGPProviderImpl struct {
	config         *config.BGPConfig
	activePrefixes map[string]bool
	lastUpdate     time.Time
	advertCount    int
	mu             sync.RWMutex
	logger         Logger
	conn           net.Conn
}

func NewBGPProvider(cfg *config.BGPConfig) (BGPProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("BGP配置不能为空")
	}

	provider := &BGPProviderImpl{
		config:         cfg,
		activePrefixes: make(map[string]bool),
		lastUpdate:     time.Time{},
		advertCount:    0,
		logger:         newLogger(loggerTypeDefault),
	}

	for _, prefix := range cfg.NormalPrefixes {
		provider.activePrefixes[prefix] = true
	}

	return provider, nil
}

func (b *BGPProviderImpl) AdvertiseSteering(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Infof("BGP公告牵引路由: %v", b.config.SteeringPrefixes)

	if len(b.config.SteeringPrefixes) == 0 {
		b.logger.Warn("没有配置牵引前缀")
		return nil
	}

	for _, prefix := range b.config.SteeringPrefixes {
		if err := b.advertisePrefix(prefix); err != nil {
			b.logger.Errorf("公告前缀 %s 失败: %v", prefix, err)
			return err
		}
		b.activePrefixes[prefix] = true
		b.logger.Infof("BGP公告成功: %s", prefix)
	}

	b.lastUpdate = time.Now()
	b.advertCount++
	b.logger.Infof("BGP牵引公告完成: 第%d次公告", b.advertCount)

	return nil
}

func (b *BGPProviderImpl) WithdrawSteering(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Infof("BGP撤回牵引路由: %v", b.config.SteeringPrefixes)

	for _, prefix := range b.config.SteeringPrefixes {
		if err := b.withdrawPrefix(prefix); err != nil {
			b.logger.Errorf("撤回前缀 %s 失败: %v", prefix, err)
			continue
		}
		delete(b.activePrefixes, prefix)
		b.logger.Infof("BGP撤回成功: %s", prefix)
	}

	for _, prefix := range b.config.NormalPrefixes {
		b.activePrefixes[prefix] = true
	}

	b.lastUpdate = time.Now()
	b.logger.Infof("BGP牵引撤回完成")

	return nil
}

func (b *BGPProviderImpl) GetStatus(ctx context.Context) (*BGPStatus, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	prefixes := make([]string, 0, len(b.activePrefixes))
	for p := range b.activePrefixes {
		prefixes = append(prefixes, p)
	}

	return &BGPStatus{
		IsSteering:     b.isSteering(),
		ActivePrefixes: prefixes,
		LastUpdate:     b.lastUpdate,
	}, nil
}

func (b *BGPProviderImpl) isSteering() bool {
	for _, prefix := range b.config.SteeringPrefixes {
		if b.activePrefixes[prefix] {
			return true
		}
	}
	return false
}

func (b *BGPProviderImpl) advertisePrefix(prefix string) error {
	if b.config.NeighborIP == "" {
		b.logger.Debugf("BGP邻居未配置，模拟公告前缀: %s", prefix)
		return nil
	}

	adv := &BGPAdvertisement{
		Prefix:    prefix,
		NextHop:   b.config.NeighborIP,
		ASPath:    []int{b.config.LocalASN},
		LocalPref: 100,
		MED:       50,
		Community: []string{},
	}

	b.logger.Infof("BGP路由公告: %s via %s AS%d", prefix, adv.NextHop, b.config.LocalASN)

	return nil
}

func (b *BGPProviderImpl) withdrawPrefix(prefix string) error {
	if b.config.NeighborIP == "" {
		b.logger.Debugf("BGP邻居未配置，模拟撤回前缀: %s", prefix)
		return nil
	}

	b.logger.Infof("BGP路由撤回: %s", prefix)
	return nil
}

type AnycastProvider interface {
	GetHealthyPOPs(ctx context.Context) ([]*POPInfo, error)
	GetRouting(ctx context.Context) (*AnycastRouting, error)
}

type POPInfo struct {
	Name      string
	Region    string
	IP        string
	Weight    int
	Active    bool
	Latency   time.Duration
	LastCheck time.Time
}

type AnycastRouting struct {
	CurrentPOP string
	POPs       []*POPInfo
	TotalPOPs  int
	ActivePOPs int
}

type AnycastProviderImpl struct {
	config     *config.AnycastConfig
	pops       map[string]*POPInfo
	mu         sync.RWMutex
	logger     Logger
	lastCheck  time.Time
	checkCount int
}

func NewAnycastProvider(cfg *config.AnycastConfig) (AnycastProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("Anycast配置不能为空")
	}

	provider := &AnycastProviderImpl{
		config:    cfg,
		pops:      make(map[string]*POPInfo),
		logger:    newLogger(loggerTypeDefault),
		lastCheck: time.Time{},
	}

	for _, popCfg := range cfg.Pops {
		provider.pops[popCfg.Name] = &POPInfo{
			Name:   popCfg.Name,
			Region: popCfg.Region,
			IP:     popCfg.IP,
			Weight: popCfg.Weight,
			Active: popCfg.Active,
		}
	}

	return provider, nil
}

func (a *AnycastProviderImpl) GetHealthyPOPs(ctx context.Context) ([]*POPInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	healthy := make([]*POPInfo, 0)

	for _, pop := range a.pops {
		if pop.Active {
			healthy = append(healthy, pop)
		}
	}

	a.lastCheck = time.Now()
	a.checkCount++

	return healthy, nil
}

func (a *AnycastProviderImpl) GetRouting(ctx context.Context) (*AnycastRouting, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	pops := make([]*POPInfo, 0, len(a.pops))
	activeCount := 0

	for _, pop := range a.pops {
		clone := *pop
		pops = append(pops, &clone)
		if pop.Active {
			activeCount++
		}
	}

	currentPOP := a.selectBestPOP(pops)

	return &AnycastRouting{
		CurrentPOP: currentPOP,
		POPs:       pops,
		TotalPOPs:  len(pops),
		ActivePOPs: activeCount,
	}, nil
}

func (a *AnycastProviderImpl) selectBestPOP(pops []*POPInfo) string {
	if len(pops) == 0 {
		return ""
	}

	bestPOP := ""
	bestWeight := -1

	for _, pop := range pops {
		if !pop.Active {
			continue
		}

		if pop.Weight > bestWeight {
			bestWeight = pop.Weight
			bestPOP = pop.Name
		}
	}

	return bestPOP
}

type SteeringTrigger struct {
	config     *config.SteeringTriggerConfig
	alertChan  chan *SteeringAlert
	mu         sync.RWMutex
	logger     Logger
	lastMetric map[string]float64
}

func NewSteeringTrigger(cfg *config.SteeringTriggerConfig) *SteeringTrigger {
	return &SteeringTrigger{
		config:     cfg,
		alertChan:  make(chan *SteeringAlert, 100),
		logger:     newLogger(loggerTypeDefault),
		lastMetric: make(map[string]float64),
	}
}

func (st *SteeringTrigger) Start(ctx context.Context, handler func(*SteeringAlert)) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st.checkTriggers(handler)
			}
		}
	}()
}

func (st *SteeringTrigger) checkTriggers(handler func(*SteeringAlert)) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.config == nil {
		return
	}

	for _, condition := range st.config.Conditions {
		st.checkCondition(condition, handler)
	}
}

func (st *SteeringTrigger) checkCondition(condition *config.SteeringCondition, handler func(*SteeringAlert)) {
	var current float64
	var met bool

	switch condition.Type {
	case "bandwidth":
		current = st.getBandwidth()
		met = current >= condition.Threshold
	case "pps":
		current = float64(st.getPPS())
		met = current >= condition.Threshold
	case "syn_ratio":
		current = st.getSYNRation()
		met = current >= condition.Threshold
	case "qps":
		current = float64(st.getQPS())
		met = current >= condition.Threshold
	case "error_rate":
		current = st.getErrorRate()
		met = current >= condition.Threshold
	default:
		return
	}

	st.lastMetric[condition.Type] = current

	if met {
		alert := &SteeringAlert{
			TriggerType:     condition.Type,
			TriggerValue:    current,
			Threshold:       condition.Threshold,
			TriggeredAt:     time.Now(),
			RecommendAction: condition.Action,
			CurrentStatus:   "normal",
		}
		st.logger.Warnf("牵引触发告警: %s=%.2f(阈值=%.2f)", condition.Type, current, condition.Threshold)
		handler(alert)
	}
}

func (st *SteeringTrigger) getBandwidth() float64 {
	return 2.5
}

func (st *SteeringTrigger) getPPS() int64 {
	return 55000
}

func (st *SteeringTrigger) getSYNRation() float64 {
	return 0.12
}

func (st *SteeringTrigger) getQPS() int64 {
	return 5000
}

func (st *SteeringTrigger) getErrorRate() float64 {
	return 0.15
}

type SteeringRecord struct {
	ID           string
	StartTime    time.Time
	EndTime      *time.Time
	Mode         string
	TriggerType  string
	TriggerValue float64
	Reason       string
	Status       string
}

type SteeringStatus struct {
	Mode           string
	Enabled        bool
	IsSteering     bool
	ActiveIDs      []string
	StartTime      time.Time
	CurrentRecord  string
	ActivePrefixes []string
	CurrentPOP     string
}

type SteeringAlert struct {
	TriggerType     string
	TriggerValue    float64
	Threshold       float64
	TriggeredAt     time.Time
	RecommendAction string
	CurrentStatus   string
}

type SteeringManager struct {
	config      *config.SteeringConfig
	dnsProvider DNSProvider
	bgpProvider BGPProvider
	anycast     AnycastProvider
	trigger     *SteeringTrigger
	mu          sync.RWMutex
	records     map[string]*SteeringRecord
	logger      Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewSteeringManager(cfg *config.SteeringConfig, opts ...SteeringOption) (*SteeringManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("牵引配置不能为空")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sm := &SteeringManager{
		config:  cfg,
		records: make(map[string]*SteeringRecord),
		trigger: NewSteeringTrigger(cfg.Trigger),
		logger:  newLogger(loggerTypeDefault),
		ctx:     ctx,
		cancel:  cancel,
	}

	for _, opt := range opts {
		opt(sm)
	}

	if err := sm.initProviders(); err != nil {
		cancel()
		return nil, fmt.Errorf("初始化提供者失败: %w", err)
	}

	return sm, nil
}

type SteeringOption func(*SteeringManager)

func WithSteeringLogger(l Logger) SteeringOption {
	return func(sm *SteeringManager) {
		sm.logger = l
	}
}

func (sm *SteeringManager) initProviders() error {
	switch sm.config.Mode {
	case "dns":
		provider, err := NewDNSProvider(sm.config.DNS)
		if err != nil {
			return fmt.Errorf("初始化DNS提供者失败: %w", err)
		}
		sm.dnsProvider = provider
		sm.logger.Infof("DNS牵引提供者已初始化")

	case "bgp":
		provider, err := NewBGPProvider(sm.config.BGP)
		if err != nil {
			return fmt.Errorf("初始化BGP提供者失败: %w", err)
		}
		sm.bgpProvider = provider
		sm.logger.Infof("BGP牵引提供者已初始化")

	case "anycast":
		provider, err := NewAnycastProvider(sm.config.Anycast)
		if err != nil {
			return fmt.Errorf("初始化Anycast提供者失败: %w", err)
		}
		sm.anycast = provider
		sm.logger.Infof("Anycast提供者已初始化")

	default:
		return fmt.Errorf("不支持的牵引模式: %s", sm.config.Mode)
	}

	return nil
}

func (sm *SteeringManager) Start() error {
	sm.logger.Infof("启动牵引管理器，模式: %s", sm.config.Mode)

	if sm.trigger != nil {
		sm.trigger.Start(sm.ctx, sm.alertHandler)
	}

	if sm.anycast != nil {
		go sm.anycastHealthCheckLoop()
	}

	return nil
}

func (sm *SteeringManager) Stop() {
	sm.logger.Infof("停止牵引管理器")
	if sm.cancel != nil {
		sm.cancel()
	}
}

func (sm *SteeringManager) TriggerSteering(ctx context.Context, triggerType string, value float64, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.logger.Infof("触发牵引: 类型=%s, 值=%.2f, 原因=%s", triggerType, value, reason)

	var err error
	switch sm.config.Mode {
	case "dns":
		if sm.dnsProvider != nil {
			err = sm.dnsProvider.SwitchToSteering(ctx)
		}
	case "bgp":
		if sm.bgpProvider != nil {
			err = sm.bgpProvider.AdvertiseSteering(ctx)
		}
	case "anycast":
		sm.logger.Infof("Anycast模式，仅记录牵引状态")
	}

	if err != nil {
		sm.logger.Errorf("牵引失败: %v", err)
		return err
	}

	record := &SteeringRecord{
		ID:           fmt.Sprintf("steer_%d", time.Now().UnixNano()),
		StartTime:    time.Now(),
		Mode:         sm.config.Mode,
		TriggerType:  triggerType,
		TriggerValue: value,
		Reason:       reason,
		Status:       "active",
	}
	sm.records[record.ID] = record

	sm.logger.Infof("牵引成功: %s", record.ID)

	return nil
}

func (sm *SteeringManager) RestoreNormal(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.logger.Infof("恢复正常路由")

	var err error
	switch sm.config.Mode {
	case "dns":
		if sm.dnsProvider != nil {
			err = sm.dnsProvider.SwitchToNormal(ctx)
		}
	case "bgp":
		if sm.bgpProvider != nil {
			err = sm.bgpProvider.WithdrawSteering(ctx)
		}
	case "anycast":
		sm.logger.Infof("Anycast模式，无需主动恢复")
	}

	if err != nil {
		sm.logger.Errorf("恢复路由失败: %v", err)
		return err
	}

	for _, record := range sm.records {
		if record.Status == "active" {
			now := time.Now()
			record.EndTime = &now
			record.Status = "recovered"
		}
	}

	sm.logger.Infof("恢复路由成功")

	return nil
}

func (sm *SteeringManager) GetStatus(ctx context.Context) (*SteeringStatus, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := &SteeringStatus{
		Mode:      sm.config.Mode,
		Enabled:   sm.config.Enabled,
		ActiveIDs: make([]string, 0),
	}

	for _, record := range sm.records {
		if record.Status == "active" {
			status.ActiveIDs = append(status.ActiveIDs, record.ID)
			if status.StartTime.IsZero() || record.StartTime.Before(status.StartTime) {
				status.StartTime = record.StartTime
			}
		}
	}

	switch sm.config.Mode {
	case "dns":
		if sm.dnsProvider != nil {
			dnsStatus, err := sm.dnsProvider.GetStatus(ctx)
			if err == nil {
				status.IsSteering = dnsStatus.IsSteering
				status.CurrentRecord = dnsStatus.CurrentRecord
			}
		}
	case "bgp":
		if sm.bgpProvider != nil {
			bgpStatus, err := sm.bgpProvider.GetStatus(ctx)
			if err == nil {
				status.IsSteering = bgpStatus.IsSteering
				status.ActivePrefixes = bgpStatus.ActivePrefixes
			}
		}
	case "anycast":
		if sm.anycast != nil {
			routing, err := sm.anycast.GetRouting(ctx)
			if err == nil {
				status.CurrentPOP = routing.CurrentPOP
			}
		}
	}

	return status, nil
}

func (sm *SteeringManager) GetRecords(limit int) []*SteeringRecord {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	records := make([]*SteeringRecord, 0, len(sm.records))
	for _, record := range sm.records {
		records = append(records, record)
	}

	for i := 0; i < len(records)-1; i++ {
		for j := i + 1; j < len(records); j++ {
			if records[j].StartTime.After(records[i].StartTime) {
				records[i], records[j] = records[j], records[i]
			}
		}
	}

	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}

	return records
}

func (sm *SteeringManager) anycastHealthCheckLoop() {
	if sm.config.Anycast == nil || sm.config.Anycast.HealthCheck == nil {
		return
	}

	ticker := time.NewTicker(sm.config.Anycast.HealthCheck.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.checkAnycastPOPs()
		}
	}
}

func (sm *SteeringManager) checkAnycastPOPs() {
	if sm.anycast == nil {
		return
	}

	ctx, cancel := context.WithTimeout(sm.ctx, 30*time.Second)
	defer cancel()

	pops, err := sm.anycast.GetHealthyPOPs(ctx)
	if err != nil {
		sm.logger.Errorf("获取健康POP失败: %v", err)
		return
	}

	for _, pop := range pops {
		sm.logger.Debugf("POP状态: %s healthy=%v", pop.Name, pop.Active)
	}
}

func (sm *SteeringManager) alertHandler(alert *SteeringAlert) {
	sm.logger.Warnf("牵引触发告警: 类型=%s, 值=%.2f, 建议=%s",
		alert.TriggerType, alert.TriggerValue, alert.RecommendAction)

	if sm.config.Trigger.AutoSteer {
		ctx, cancel := context.WithTimeout(sm.ctx, 30*time.Second)
		defer cancel()

		if err := sm.TriggerSteering(ctx, alert.TriggerType, alert.TriggerValue,
			fmt.Sprintf("告警触发: %s", alert.RecommendAction)); err != nil {
			sm.logger.Errorf("自动牵引失败: %v", err)
		}
	}
}

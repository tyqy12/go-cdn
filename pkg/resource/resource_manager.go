package resource

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ResourceManager 资源管理器
type ResourceManager struct {
	config  *ResourceConfig
	quotas  map[string]*ResourceQuota
	usage   map[string]*ResourceUsage
	limits  *SystemLimits
	monitor *ResourceMonitor
	mu      sync.RWMutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// ResourceConfig 资源配置
type ResourceConfig struct {
	// 是否启用资源限制
	Enabled bool

	// 默认配额
	DefaultQuota *ResourceQuota

	// 系统限制
	SystemLimits *SystemLimits

	// 监控间隔
	MonitorInterval time.Duration
}

// ResourceQuota 资源配额
type ResourceQuota struct {
	UserID      string
	Bandwidth   BandwidthQuota
	Storage     StorageQuota
	Requests    RequestQuota
	Connections ConnectionQuota
	ExpiresAt   time.Time
}

// BandwidthQuota 带宽配额
type BandwidthQuota struct {
	MaxBytes  int64
	UsedBytes int64
	ResetTime time.Time
	Window    time.Duration
}

// StorageQuota 存储配额
type StorageQuota struct {
	MaxBytes  int64
	UsedBytes int64
	MaxFiles  int64
	UsedFiles int64
}

// RequestQuota 请求配额
type RequestQuota struct {
	MaxRequests  int64
	UsedRequests int64
	Window       time.Duration
	ResetTime    time.Time
}

// ConnectionQuota 连接配额
type ConnectionQuota struct {
	MaxConns     int64
	CurrentConns int64
}

// SystemLimits 系统限制
type SystemLimits struct {
	// 最大并发连接数
	MaxConnections int64

	// 最大带宽（字节/秒）
	MaxBandwidth int64

	// 最大存储（字节）
	MaxStorage int64

	// 最大请求率（请求/秒）
	MaxRequestRate int64

	// 最大文件大小
	MaxFileSize int64

	// 最大URL长度
	MaxURLLength int

	// 最大Header大小
	MaxHeaderSize int

	// 最大Body大小
	MaxBodySize int64
}

// ResourceUsage 资源使用情况
type ResourceUsage struct {
	UserID          string
	BandwidthIn     int64
	BandwidthOut    int64
	StorageUsed     int64
	RequestCount    int64
	ConnectionCount int64
	LastUpdated     time.Time
}

// ResourceMonitor 资源监控器
type ResourceMonitor struct {
	mu            sync.RWMutex
	metrics       map[string]*ResourceMetrics
	alertHandlers []AlertHandler
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// ResourceMetrics 资源指标
type ResourceMetrics struct {
	Timestamp       time.Time
	BandwidthIn     int64
	BandwidthOut    int64
	RequestRate     float64
	ConnectionCount int64
	CPUUsage        float64
	MemoryUsage     float64
	DiskUsage       float64
}

// AlertHandler 告警处理器
type AlertHandler interface {
	HandleAlert(alert *Alert)
}

// Alert 告警
type Alert struct {
	AlertType AlertType
	Severity  AlertSeverity
	UserID    string
	Message   string
	Timestamp time.Time
	Resolved  bool
}

// AlertType 告警类型
type AlertType string

const (
	AlertTypeBandwidthExceeded AlertType = "bandwidth_exceeded"
	AlertTypeStorageExceeded   AlertType = "storage_exceeded"
	AlertTypeRequestRateHigh   AlertType = "request_rate_high"
	AlertTypeConnectionLimit   AlertType = "connection_limit"
	AlertTypeCPULow            AlertType = "cpu_low"
	AlertTypeMemoryHigh        AlertType = "memory_high"
)

// AlertSeverity 告警级别
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// DefaultResourceConfig 默认配置
func DefaultResourceConfig() *ResourceConfig {
	return &ResourceConfig{
		Enabled:         true,
		DefaultQuota:    DefaultQuota(),
		SystemLimits:    DefaultSystemLimits(),
		MonitorInterval: 10 * time.Second,
	}
}

// DefaultQuota 默认配额
func DefaultQuota() *ResourceQuota {
	now := time.Now()
	return &ResourceQuota{
		Bandwidth: BandwidthQuota{
			MaxBytes:  100 * 1024 * 1024 * 1024, // 100GB
			UsedBytes: 0,
			Window:    24 * time.Hour,
			ResetTime: now.Add(24 * time.Hour),
		},
		Storage: StorageQuota{
			MaxBytes:  500 * 1024 * 1024 * 1024, // 500GB
			UsedBytes: 0,
			MaxFiles:  1000000,
			UsedFiles: 0,
		},
		Requests: RequestQuota{
			MaxRequests: 10000000,
			Window:      24 * time.Hour,
			ResetTime:   now.Add(24 * time.Hour),
		},
		Connections: ConnectionQuota{
			MaxConns:     10000,
			CurrentConns: 0,
		},
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

// DefaultSystemLimits 默认系统限制
func DefaultSystemLimits() *SystemLimits {
	return &SystemLimits{
		MaxConnections: 100000,
		MaxBandwidth:   10 * 1024 * 1024 * 1024,        // 10Gbps
		MaxStorage:     10 * 1024 * 1024 * 1024 * 1024, // 10TB
		MaxRequestRate: 1000000,
		MaxFileSize:    1024 * 1024 * 1024, // 1GB
		MaxURLLength:   8192,
		MaxHeaderSize:  65536,
		MaxBodySize:    100 * 1024 * 1024, // 100MB
	}
}

// NewResourceManager 创建资源管理器
func NewResourceManager(cfg *ResourceConfig) *ResourceManager {
	if cfg == nil {
		cfg = DefaultResourceConfig()
	}

	return &ResourceManager{
		config:  cfg,
		quotas:  make(map[string]*ResourceQuota),
		usage:   make(map[string]*ResourceUsage),
		limits:  cfg.SystemLimits,
		monitor: NewResourceMonitor(),
		stopCh:  make(chan struct{}),
	}
}

// NewResourceMonitor 创建资源监控器
func NewResourceMonitor() *ResourceMonitor {
	return &ResourceMonitor{
		metrics:       make(map[string]*ResourceMetrics),
		alertHandlers: make([]AlertHandler, 0),
		stopCh:        make(chan struct{}),
	}
}

// Start 启动资源管理器
func (m *ResourceManager) Start() {
	if !m.config.Enabled {
		log.Println("Resource manager is disabled")
		return
	}

	// 启动监控器
	m.monitor.Start()

	// 启动使用量重置协程
	m.wg.Add(1)
	go m.runUsageReset()

	log.Println("Resource manager started")
}

// Stop 停止资源管理器
func (m *ResourceManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.monitor.Stop()

	log.Println("Resource manager stopped")
}

// runUsageReset 运行使用量重置
func (m *ResourceManager) runUsageReset() {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.resetExpiredUsage()
		}
	}
}

// resetExpiredUsage 重置过期的使用量
func (m *ResourceManager) resetExpiredUsage() {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, quota := range m.quotas {
		// 重置带宽配额
		if now.After(quota.Bandwidth.ResetTime) {
			quota.Bandwidth.UsedBytes = 0
			quota.Bandwidth.ResetTime = now.Add(quota.Bandwidth.Window)
		}

		// 重置请求配额
		if now.After(quota.Requests.ResetTime) {
			quota.Requests.UsedRequests = 0
			quota.Requests.ResetTime = now.Add(quota.Requests.Window)
		}
	}
}

// SetQuota 设置用户配额
func (m *ResourceManager) SetQuota(userID string, quota *ResourceQuota) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.quotas[userID] = quota
}

// GetQuota 获取用户配额
func (m *ResourceManager) GetQuota(userID string) *ResourceQuota {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.quotas[userID]
}

// GetUsage 获取用户使用情况
func (m *ResourceManager) GetUsage(userID string) *ResourceUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.usage[userID]
}

// CheckQuota 检查配额
func (m *ResourceManager) CheckQuota(userID string, resourceType ResourceType, bytes int64) *QuotaCheckResult {
	m.mu.RLock()
	quota := m.quotas[userID]
	m.mu.RUnlock()

	if quota == nil {
		quota = m.config.DefaultQuota
	}

	switch resourceType {
	case ResourceTypeBandwidth:
		return m.checkBandwidthQuota(quota, bytes)
	case ResourceTypeStorage:
		return m.checkStorageQuota(quota, bytes)
	case ResourceTypeRequest:
		return m.checkRequestQuota(quota, 1)
	case ResourceTypeConnection:
		return m.checkConnectionQuota(quota)
	}

	return &QuotaCheckResult{Allowed: true}
}

// ResourceType 资源类型
type ResourceType string

const (
	ResourceTypeBandwidth  ResourceType = "bandwidth"
	ResourceTypeStorage    ResourceType = "storage"
	ResourceTypeRequest    ResourceType = "request"
	ResourceTypeConnection ResourceType = "connection"
)

// QuotaCheckResult 配额检查结果
type QuotaCheckResult struct {
	Allowed   bool
	Reason    string
	Used      int64
	Limit     int64
	Remaining int64
}

// checkBandwidthQuota 检查带宽配额
func (m *ResourceManager) checkBandwidthQuota(quota *ResourceQuota, bytes int64) *QuotaCheckResult {
	remaining := quota.Bandwidth.MaxBytes - quota.Bandwidth.UsedBytes

	if quota.Bandwidth.UsedBytes+bytes > quota.Bandwidth.MaxBytes {
		return &QuotaCheckResult{
			Allowed:   false,
			Reason:    "带宽配额已用尽",
			Used:      quota.Bandwidth.UsedBytes,
			Limit:     quota.Bandwidth.MaxBytes,
			Remaining: remaining,
		}
	}

	return &QuotaCheckResult{
		Allowed:   true,
		Used:      quota.Bandwidth.UsedBytes,
		Limit:     quota.Bandwidth.MaxBytes,
		Remaining: remaining,
	}
}

// checkStorageQuota 检查存储配额
func (m *ResourceManager) checkStorageQuota(quota *ResourceQuota, bytes int64) *QuotaCheckResult {
	remaining := quota.Storage.MaxBytes - quota.Storage.UsedBytes

	if quota.Storage.UsedBytes+bytes > quota.Storage.MaxBytes {
		return &QuotaCheckResult{
			Allowed:   false,
			Reason:    "存储配额已用尽",
			Used:      quota.Storage.UsedBytes,
			Limit:     quota.Storage.MaxBytes,
			Remaining: remaining,
		}
	}

	return &QuotaCheckResult{
		Allowed:   true,
		Used:      quota.Storage.UsedBytes,
		Limit:     quota.Storage.MaxBytes,
		Remaining: remaining,
	}
}

// checkRequestQuota 检查请求配额
func (m *ResourceManager) checkRequestQuota(quota *ResourceQuota, count int64) *QuotaCheckResult {
	remaining := quota.Requests.MaxRequests - quota.Requests.UsedRequests

	if quota.Requests.UsedRequests+count > quota.Requests.MaxRequests {
		return &QuotaCheckResult{
			Allowed:   false,
			Reason:    "请求配额已用尽",
			Used:      quota.Requests.UsedRequests,
			Limit:     quota.Requests.MaxRequests,
			Remaining: remaining,
		}
	}

	return &QuotaCheckResult{
		Allowed:   true,
		Used:      quota.Requests.UsedRequests,
		Limit:     quota.Requests.MaxRequests,
		Remaining: remaining,
	}
}

// checkConnectionQuota 检查连接配额
func (m *ResourceManager) checkConnectionQuota(quota *ResourceQuota) *QuotaCheckResult {
	remaining := quota.Connections.MaxConns - quota.Connections.CurrentConns

	if quota.Connections.CurrentConns >= quota.Connections.MaxConns {
		return &QuotaCheckResult{
			Allowed:   false,
			Reason:    "连接数已达上限",
			Used:      quota.Connections.CurrentConns,
			Limit:     quota.Connections.MaxConns,
			Remaining: remaining,
		}
	}

	return &QuotaCheckResult{
		Allowed:   true,
		Used:      quota.Connections.CurrentConns,
		Limit:     quota.Connections.MaxConns,
		Remaining: remaining,
	}
}

// UpdateUsage 更新使用量
func (m *ResourceManager) UpdateUsage(userID string, bandwidthIn, bandwidthOut int64, requestCount int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	usage := m.usage[userID]
	if usage == nil {
		usage = &ResourceUsage{UserID: userID}
		m.usage[userID] = usage
	}

	usage.BandwidthIn += bandwidthIn
	usage.BandwidthOut += bandwidthOut
	usage.RequestCount += requestCount
	usage.LastUpdated = time.Now()

	// 更新配额使用量
	if quota, ok := m.quotas[userID]; ok {
		quota.Bandwidth.UsedBytes += bandwidthIn + bandwidthOut
		quota.Requests.UsedRequests += requestCount
	}
}

// AddConnection 增加连接数
func (m *ResourceManager) AddConnection(userID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	quota := m.quotas[userID]
	if quota == nil {
		quota = m.config.DefaultQuota
	}

	if quota.Connections.CurrentConns >= quota.Connections.MaxConns {
		return false
	}

	quota.Connections.CurrentConns++

	usage := m.usage[userID]
	if usage == nil {
		usage = &ResourceUsage{UserID: userID}
		m.usage[userID] = usage
	}

	usage.ConnectionCount++
	return true
}

// RemoveConnection 减少连接数
func (m *ResourceManager) RemoveConnection(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	quota := m.quotas[userID]
	if quota != nil && quota.Connections.CurrentConns > 0 {
		quota.Connections.CurrentConns--
	}

	usage := m.usage[userID]
	if usage != nil && usage.ConnectionCount > 0 {
		usage.ConnectionCount--
	}
}

// StartMonitor 启动监控器
func (m *ResourceMonitor) Start() {
	m.wg.Add(1)
	go m.collectMetrics()
}

// StopMonitor 停止监控器
func (m *ResourceMonitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// collectMetrics 收集指标
func (m *ResourceMonitor) collectMetrics() {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.updateMetrics()
		}
	}
}

// updateMetrics 更新指标
func (m *ResourceMonitor) updateMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 收集系统指标
	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	m.metrics["system"] = metrics

	// 检查告警
	m.checkAlerts(metrics)
}

// checkAlerts 检查告警
func (m *ResourceMonitor) checkAlerts(metrics *ResourceMetrics) {
	// 检查CPU使用率
	if metrics.CPUUsage > 0.9 {
		m.triggerAlert(&Alert{
			AlertType: AlertTypeCPULow,
			Severity:  AlertSeverityCritical,
			Message:   fmt.Sprintf("CPU usage too high: %.2f%%", metrics.CPUUsage*100),
			Timestamp: time.Now(),
		})
	}

	// 检查内存使用率
	if metrics.MemoryUsage > 0.9 {
		m.triggerAlert(&Alert{
			AlertType: AlertTypeMemoryHigh,
			Severity:  AlertSeverityCritical,
			Message:   fmt.Sprintf("Memory usage too high: %.2f%%", metrics.MemoryUsage*100),
			Timestamp: time.Now(),
		})
	}

	// 检查连接数
	if metrics.ConnectionCount > 80000 { // 系统限制的80%
		m.triggerAlert(&Alert{
			AlertType: AlertTypeConnectionLimit,
			Severity:  AlertSeverityWarning,
			Message:   fmt.Sprintf("Connection count high: %d", metrics.ConnectionCount),
			Timestamp: time.Now(),
		})
	}
}

// triggerAlert 触发告警
func (m *ResourceMonitor) triggerAlert(alert *Alert) {
	for _, handler := range m.alertHandlers {
		handler.HandleAlert(alert)
	}
}

// AddAlertHandler 添加告警处理器
func (m *ResourceMonitor) AddAlertHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.alertHandlers = append(m.alertHandlers, handler)
}

// GetMetrics 获取指标
func (m *ResourceMonitor) GetMetrics() map[string]*ResourceMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := make(map[string]*ResourceMetrics)
	for k, v := range m.metrics {
		metrics[k] = v
	}
	return metrics
}

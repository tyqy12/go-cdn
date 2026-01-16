package protection

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// ResourceMonitor 资源监控器
type ResourceMonitor struct {
	mu            sync.RWMutex
	stats         *ResourceStats
	alertHandlers []AlertHandler
}

// ResourceStats 资源统计
type ResourceStats struct {
	CPUUsage       float64
	MemoryUsage    uint64
	GoroutineCount int
	LastUpdate     time.Time
}

// AlertHandler 告警处理器
type AlertHandler interface {
	HandleAlert(alert *ResourceAlert)
}

// ResourceAlert 资源告警
type ResourceAlert struct {
	Type      AlertType
	Value     float64
	Threshold float64
	Timestamp time.Time
}

// AlertType 告警类型
type AlertType string

const (
	AlertTypeHighCPU       AlertType = "high_cpu"
	AlertTypeHighMemory    AlertType = "high_memory"
	AlertTypeHighGoroutine AlertType = "high_goroutine"
)

// NewResourceMonitor 创建资源监控器
func NewResourceMonitor() *ResourceMonitor {
	return &ResourceMonitor{
		stats:         &ResourceStats{},
		alertHandlers: []AlertHandler{},
	}
}

// Run 运行监控器
func (rm *ResourceMonitor) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rm.check()
		}
	}
}

// check 检查资源状态
func (rm *ResourceMonitor) check() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rm.stats.MemoryUsage = m.Alloc
	rm.stats.GoroutineCount = runtime.NumGoroutine()
	rm.stats.LastUpdate = time.Now()

	rm.checkAlerts()
}

// checkAlerts 检查告警
func (rm *ResourceMonitor) checkAlerts() {
	// 检查内存
	memUsageGB := float64(rm.stats.MemoryUsage) / 1024 / 1024 / 1024
	if memUsageGB > 8.0 {
		rm.triggerAlert(&ResourceAlert{
			Type:      AlertTypeHighMemory,
			Value:     memUsageGB,
			Threshold: 8.0,
			Timestamp: time.Now(),
		})
	}

	// 检查Goroutine数量
	if rm.stats.GoroutineCount > 10000 {
		rm.triggerAlert(&ResourceAlert{
			Type:      AlertTypeHighGoroutine,
			Value:     float64(rm.stats.GoroutineCount),
			Threshold: 10000,
			Timestamp: time.Now(),
		})
	}
}

// triggerAlert 触发告警
func (rm *ResourceMonitor) triggerAlert(alert *ResourceAlert) {
	for _, handler := range rm.alertHandlers {
		handler.HandleAlert(alert)
	}
}

// AddAlertHandler 添加告警处理器
func (rm *ResourceMonitor) AddAlertHandler(handler AlertHandler) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.alertHandlers = append(rm.alertHandlers, handler)
}

// GetStats 获取统计信息
func (rm *ResourceMonitor) GetStats() *ResourceStats {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return &ResourceStats{
		CPUUsage:       rm.stats.CPUUsage,
		MemoryUsage:    rm.stats.MemoryUsage,
		GoroutineCount: rm.stats.GoroutineCount,
		LastUpdate:     rm.stats.LastUpdate,
	}
}

// DefaultAlertHandler 默认告警处理器
type DefaultAlertHandler struct{}

func (h *DefaultAlertHandler) HandleAlert(alert *ResourceAlert) {
	// 可以添加日志记录、通知等逻辑
}

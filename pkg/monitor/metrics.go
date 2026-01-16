package monitor

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector 指标收集器 - Prometheus兼容
type MetricsCollector struct {
	mu        sync.RWMutex
	counters  map[string]*Counter
	gauges    map[string]*Gauge
	histograms map[string]*Histogram
	enabled   bool
	namespace string
	subsystem string
}

// Counter 计数器
type Counter struct {
	value int64
	help  string
}

// Inc 增加计数器
func (c *Counter) Inc() {
	atomic.AddInt64(&c.value, 1)
}

// IncBy 增加指定值
func (c *Counter) IncBy(v int64) {
	atomic.AddInt64(&c.value, v)
}

// Value 获取当前值
func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

// Gauge 仪表盘
type Gauge struct {
	value int64
	help  string
}

// Set 设置值
func (g *Gauge) Set(v int64) {
	atomic.StoreInt64(&g.value, v)
}

// Inc 增加
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}

// Dec 减少
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}

// Value 获取当前值
func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}

// Histogram 直方图
type Histogram struct {
	buckets map[float64]int64
	count   int64
	sum     int64
	mu      sync.Mutex
	help    string
}

// Observe 观察值
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.count++
	h.sum += int64(v)

	for bucket := range h.buckets {
		if v <= bucket {
			h.buckets[bucket]++
		}
	}
}

// Count 获取样本数
func (h *Histogram) Count() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// Sum 获取总和
func (h *Histogram) Sum() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sum
}

// Buckets 获取桶
func (h *Histogram) Buckets() map[float64]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := make(map[float64]int64)
	for k, v := range h.buckets {
		result[k] = v
	}
	return result
}

// NewMetricsCollector 创建指标收集器
func NewMetricsCollector(namespace, subsystem string) *MetricsCollector {
	return &MetricsCollector{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		enabled:    true,
		namespace:  namespace,
		subsystem:  subsystem,
	}
}

// NewCounter 创建计数器
func (mc *MetricsCollector) NewCounter(name, help string) *Counter {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.fullName(name)
	if _, ok := mc.counters[key]; ok {
		return mc.counters[key]
	}

	counter := &Counter{help: help}
	mc.counters[key] = counter
	return counter
}

// NewGauge 创建仪表盘
func (mc *MetricsCollector) NewGauge(name, help string) *Gauge {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.fullName(name)
	if _, ok := mc.gauges[key]; ok {
		return mc.gauges[key]
	}

	gauge := &Gauge{help: help}
	mc.gauges[key] = gauge
	return gauge
}

// NewHistogram 创建直方图
func (mc *MetricsCollector) NewHistogram(name, help string, buckets []float64) *Histogram {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.fullName(name)
	if _, ok := mc.histograms[key]; ok {
		return mc.histograms[key]
	}

	bucketMap := make(map[float64]int64)
	for _, b := range buckets {
		bucketMap[b] = 0
	}

	histogram := &Histogram{buckets: bucketMap, help: help}
	mc.histograms[key] = histogram
	return histogram
}

// fullName 生成完整名称
func (mc *MetricsCollector) fullName(name string) string {
	if mc.namespace != "" && mc.subsystem != "" {
		return fmt.Sprintf("%s_%s_%s", mc.namespace, mc.subsystem, name)
	}
	if mc.namespace != "" {
		return fmt.Sprintf("%s_%s", mc.namespace, name)
	}
	return name
}

// Metrics 收集的所有指标
type Metrics struct {
	Counters   map[string]CounterValue
	Gauges     map[string]GaugeValue
	Histograms map[string]HistogramValue
	Timestamp  time.Time
}

// CounterValue 计数器值
type CounterValue struct {
	Value int64
	Help  string
}

// GaugeValue 仪表盘值
type GaugeValue struct {
	Value int64
	Help  string
}

// HistogramValue 直方图值
type HistogramValue struct {
	Count   int64
	Sum     int64
	Buckets map[float64]int64
	Help    string
}

// Collect 收集所有指标
func (mc *MetricsCollector) Collect() *Metrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics := &Metrics{
		Counters:   make(map[string]CounterValue),
		Gauges:     make(map[string]GaugeValue),
		Histograms: make(map[string]HistogramValue),
		Timestamp:  time.Now(),
	}

	for name, counter := range mc.counters {
		metrics.Counters[name] = CounterValue{
			Value: counter.Value(),
			Help:  counter.help,
		}
	}

	for name, gauge := range mc.gauges {
		metrics.Gauges[name] = GaugeValue{
			Value: gauge.Value(),
			Help:  gauge.help,
		}
	}

	for name, histogram := range mc.histograms {
		metrics.Histograms[name] = HistogramValue{
			Count:   histogram.Count(),
			Sum:     histogram.Sum(),
			Buckets: histogram.Buckets(),
			Help:    histogram.help,
		}
	}

	return metrics
}

// FormatPrometheus 格式化为Prometheus格式
func (mc *MetricsCollector) FormatPrometheus() string {
	metrics := mc.Collect()
	now := time.Now()

	var output string

	// Counters
	for name, counter := range metrics.Counters {
		if counter.Help != "" {
			output += fmt.Sprintf("# HELP %s %s\n", name, counter.Help)
		}
		output += fmt.Sprintf("# TYPE %s counter\n", name)
		output += fmt.Sprintf("%s %d\n", name, counter.Value)
	}

	// Gauges
	for name, gauge := range metrics.Gauges {
		if gauge.Help != "" {
			output += fmt.Sprintf("# HELP %s %s\n", name, gauge.Help)
		}
		output += fmt.Sprintf("# TYPE %s gauge\n", name)
		output += fmt.Sprintf("%s %d\n", name, gauge.Value)
	}

	// Histograms
	for name, histogram := range metrics.Histograms {
		if histogram.Help != "" {
			output += fmt.Sprintf("# HELP %s %s\n", name, histogram.Help)
		}
		output += fmt.Sprintf("# TYPE %s histogram\n", name)
		output += fmt.Sprintf("%s_count %d\n", name, histogram.Count)
		output += fmt.Sprintf("%s_sum %d\n", name, histogram.Sum)
		for bucket, count := range histogram.Buckets {
			output += fmt.Sprintf("%s_bucket{le=\"%.1f\"} %d\n", name, bucket, count)
		}
		output += fmt.Sprintf("%s_bucket{le=\"+Inf\"} %d\n", name, histogram.Count)
	}

	// 添加时间戳
	output += fmt.Sprintf("# Collection time: %s\n", now.Format(time.RFC3339))

	return output
}

// Handler HTTP处理器
func (mc *MetricsCollector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(mc.FormatPrometheus()))
	})
}

// Enable 启用指标收集
func (mc *MetricsCollector) Enable(enabled bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.enabled = enabled
}

// Reset 重置所有指标
func (mc *MetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.counters = make(map[string]*Counter)
	mc.gauges = make(map[string]*Gauge)
	mc.histograms = make(map[string]*Histogram)
}

// CDN特定指标

// CDNMetrics CDN指标收集器
type CDNMetrics struct {
	*MetricsCollector

	// 请求指标
	RequestsTotal    *Counter
	RequestsActive   *Gauge
	RequestDuration  *Histogram

	// 缓存指标
	CacheHits        *Counter
	CacheMisses      *Counter
	CacheSize        *Gauge
	CacheEvictions   *Counter

	// 带宽指标
	BytesIn          *Counter
	BytesOut         *Counter
	BandwidthUsage   *Gauge

	// 错误指标
	ErrorsTotal      *Counter
	Errors4xx        *Counter
	Errors5xx        *Counter

	// 延迟指标
	LatencyP50       *Gauge
	LatencyP95       *Gauge
	LatencyP99       *Gauge

	// 后端指标
	BackendRequests  *Counter
	BackendErrors    *Counter
	BackendLatency   *Histogram
	BackendHealthy   *Gauge

	// 安全指标
	BlockedRequests  *Counter
	ChallengeIssued  *Counter
	ChallengeSolved  *Counter
}

// NewCDNMetrics 创建CDN指标收集器
func NewCDNMetrics() *CDNMetrics {
	mc := NewMetricsCollector("gocdn", "cdn")

	metrics := &CDNMetrics{
		MetricsCollector: mc,

		// 请求指标
		RequestsTotal:   mc.NewCounter("http_requests_total", "Total HTTP requests"),
		RequestsActive:  mc.NewGauge("http_requests_active", "Active HTTP requests"),
		RequestDuration: mc.NewHistogram("http_request_duration_seconds", "Request duration in seconds", []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}),

		// 缓存指标
		CacheHits:       mc.NewCounter("cache_hits_total", "Total cache hits"),
		CacheMisses:     mc.NewCounter("cache_misses_total", "Total cache misses"),
		CacheSize:       mc.NewGauge("cache_size_bytes", "Cache size in bytes"),
		CacheEvictions:  mc.NewCounter("cache_evictions_total", "Total cache evictions"),

		// 带宽指标
		BytesIn:         mc.NewCounter("bytes_in_total", "Total bytes received"),
		BytesOut:        mc.NewCounter("bytes_out_total", "Total bytes sent"),
		BandwidthUsage:  mc.NewGauge("bandwidth_usage_bytes", "Current bandwidth usage"),

		// 错误指标
		ErrorsTotal:     mc.NewCounter("errors_total", "Total errors"),
		Errors4xx:       mc.NewCounter("errors_4xx_total", "Total 4xx errors"),
		Errors5xx:       mc.NewCounter("errors_5xx_total", "Total 5xx errors"),

		// 延迟指标
		LatencyP50:      mc.NewGauge("latency_p50_seconds", "P50 latency"),
		LatencyP95:      mc.NewGauge("latency_p95_seconds", "P95 latency"),
		LatencyP99:      mc.NewGauge("latency_p99_seconds", "P99 latency"),

		// 后端指标
		BackendRequests: mc.NewCounter("backend_requests_total", "Total backend requests"),
		BackendErrors:   mc.NewCounter("backend_errors_total", "Total backend errors"),
		BackendLatency:  mc.NewHistogram("backend_request_duration_seconds", "Backend request duration", []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}),
		BackendHealthy:  mc.NewGauge("backend_healthy_count", "Number of healthy backends"),

		// 安全指标
		BlockedRequests: mc.NewCounter("blocked_requests_total", "Total blocked requests"),
		ChallengeIssued: mc.NewCounter("challenge_issued_total", "Total challenges issued"),
		ChallengeSolved: mc.NewCounter("challenge_solved_total", "Total challenges solved"),
	}

	return metrics
}

// RecordRequest 记录请求
func (m *CDNMetrics) RecordRequest(success bool, statusCode int, duration time.Duration) {
	m.RequestsTotal.Inc()
	m.RequestDuration.Observe(duration.Seconds())

	if !success {
		m.ErrorsTotal.Inc()
		if statusCode >= 400 && statusCode < 500 {
			m.Errors4xx.Inc()
		} else if statusCode >= 500 {
			m.Errors5xx.Inc()
		}
	}
}

// RecordCacheHit 记录缓存命中
func (m *CDNMetrics) RecordCacheHit() {
	m.CacheHits.Inc()
}

// RecordCacheMiss 记录缓存未命中
func (m *CDNMetrics) RecordCacheMiss() {
	m.CacheMisses.Inc()
}

// RecordBandwidth 记录带宽
func (m *CDNMetrics) RecordBandwidth(bytesIn, bytesOut int64) {
	m.BytesIn.IncBy(bytesIn)
	m.BytesOut.IncBy(bytesOut)
}

// RecordBlocked 记录被阻止的请求
func (m *CDNMetrics) RecordBlocked() {
	m.BlockedRequests.Inc()
}

// RecordChallenge 记录挑战
func (m *CDNMetrics) RecordChallenge(verified bool) {
	m.ChallengeIssued.Inc()
	if verified {
		m.ChallengeSolved.Inc()
	}
}

// UpdateLatency 更新延迟百分位
func (m *CDNMetrics) UpdateLatency(p50, p95, p99 time.Duration) {
	m.LatencyP50.Set(int64(p50.Seconds() * 1000))
	m.LatencyP95.Set(int64(p95.Seconds() * 1000))
	m.LatencyP99.Set(int64(p99.Seconds() * 1000))
}

// BackendMetrics 后端指标
type BackendMetrics struct {
	Requests  *Counter
	Errors    *Counter
	Latency   *Histogram
	Healthy   *Gauge
}

// NewBackendMetrics 创建后端指标
func NewBackendMetrics(name string) *BackendMetrics {
	mc := NewMetricsCollector("gocdn", "backend")

	return &BackendMetrics{
		Requests: mc.NewCounter(fmt.Sprintf("backend_%s_requests_total", name), "Total requests to backend"),
		Errors:   mc.NewCounter(fmt.Sprintf("backend_%s_errors_total", name), "Total errors from backend"),
		Latency:  mc.NewHistogram(fmt.Sprintf("backend_%s_latency_seconds", name), "Backend latency", []float64{0.001, 0.01, 0.1, 0.5, 1, 5}),
		Healthy:  mc.NewGauge(fmt.Sprintf("backend_%s_healthy", name), "Backend healthy status"),
	}
}

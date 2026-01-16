package gostx

import (
	"sync"
	"time"

	"github.com/go-gost/core/metrics"
)

// MetricsAdapter 指标适配器 - 集成到 CDN Prometheus
type MetricsAdapter struct {
	mu          sync.RWMutex
	counters    map[string]*counter
	gauges      map[string]*gauge
	observers   map[string]*observer
	namespace   string
	subsystem   string
}

// counter 计数器
type counter struct {
	value float64
	mu    sync.Mutex
}

// gauge 仪表
type gauge struct {
	value float64
	mu    sync.Mutex
}

// observer 观察者 (用于延迟等)
type observer struct {
	sum   float64
	count float64
	min   float64
	max   float64
	mu    sync.Mutex
}

// MetricsOptions 指标选项
type MetricsOptions struct {
	Namespace string
	Subsystem string
}

// NewMetricsAdapter 创建指标适配器
func NewMetricsAdapter(opts ...MetricsOption) *MetricsAdapter {
	options := MetricsOptions{
		Namespace: "gostx",
		Subsystem: "runtime",
	}

	for _, opt := range opts {
		opt(&options)
	}

	return &MetricsAdapter{
		counters:  make(map[string]*counter),
		gauges:   make(map[string]*gauge),
		observers: make(map[string]*observer),
		namespace: options.Namespace,
		subsystem: options.Subsystem,
	}
}

// MetricsOption 指标配置选项
type MetricsOption func(*MetricsOptions)

// WithMetricsNamespace 设置命名空间
func WithMetricsNamespace(ns string) MetricsOption {
	return func(o *MetricsOptions) {
		o.Namespace = ns
	}
}

// WithMetricsSubsystem 设置子系统
func WithMetricsSubsystem(ss string) MetricsOption {
	return func(o *MetricsOptions) {
		o.Subsystem = ss
	}
}

// Counter 获取或创建计数器
func (m *MetricsAdapter) Counter(name string, labels map[string]string) metrics.Counter {
	key := m.makeKey(name, labels)
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.counters[key]; ok {
		return c
	}

	c := &counter{}
	m.counters[key] = c
	return c
}

// Gauge 获取或创建仪表
func (m *MetricsAdapter) Gauge(name string, labels map[string]string) metrics.Gauge {
	key := m.makeKey(name, labels)
	m.mu.Lock()
	defer m.mu.Unlock()

	if g, ok := m.gauges[key]; ok {
		return g
	}

	g := &gauge{}
	m.gauges[key] = g
	return g
}

// Observer 获取或创建观察者
func (m *MetricsAdapter) Observer(name string, labels map[string]string) metrics.Observer {
	key := m.makeKey(name, labels)
	m.mu.Lock()
	defer m.mu.Unlock()

	if o, ok := m.observers[key]; ok {
		return o
	}

	newObserver := &observer{}
	newObserver.min = float64(time.Hour)
	m.observers[key] = newObserver
	return newObserver
}

// makeKey 生成唯一键
func (m *MetricsAdapter) makeKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	result := name + "{"
	first := true
	for k, v := range labels {
		if !first {
			result += ","
		}
		result += k + "=" + v
		first = false
	}
	return result + "}"
}

// Inc 实现 metrics.Counter 接口
func (c *counter) Inc() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

// Add 实现 metrics.Counter 接口
func (c *counter) Add(delta float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value += delta
}

// Value 获取当前值
func (c *counter) Value() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// Set 实现 metrics.Gauge 接口
func (g *gauge) Set(v float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value = v
}

// Add 实现 metrics.Gauge 接口
func (g *gauge) Add(delta float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value += delta
}

// Inc 实现 metrics.Gauge 接口
func (g *gauge) Inc() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value++
}

// Dec 实现 metrics.Gauge 接口
func (g *gauge) Dec() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value--
}

// Value 获取当前值
func (g *gauge) Value() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.value
}

// Observe 实现 metrics.Observer 接口
func (o *observer) Observe(v float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sum += v
	o.count++
	if v < o.min {
		o.min = v
	}
	if v > o.max {
		o.max = v
	}
}

// GetStats 获取观察者统计
func (o *observer) GetStats() (sum, count, min, max float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sum, o.count, o.min, o.max
}

// GetAllStats 获取所有指标统计
func (m *MetricsAdapter) GetAllStats() MetricsStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := MetricsStats{
		Counters:  make(map[string]float64),
		Gauges:    make(map[string]float64),
		Observers: make(map[string]ObserverStats),
	}

	for k, c := range m.counters {
		stats.Counters[k] = c.Value()
	}
	for k, g := range m.gauges {
		stats.Gauges[k] = g.Value()
	}
	for k, o := range m.observers {
		sum, count, min, max := o.GetStats()
		stats.Observers[k] = ObserverStats{
			Sum:   sum,
			Count: count,
			Avg:   sum / count,
			Min:   min,
			Max:   max,
		}
	}

	return stats
}

// MetricsStats 指标统计
type MetricsStats struct {
	Counters  map[string]float64
	Gauges    map[string]float64
	Observers map[string]ObserverStats
}

// ObserverStats 观察者统计
type ObserverStats struct {
	Sum   float64
	Count float64
	Avg   float64
	Min   float64
	Max   float64
}

// NullMetrics 空指标收集器 (禁用指标时使用)
var NullMetrics = &nullMetrics{}

type nullMetrics struct{}

func (n *nullMetrics) Counter(name string, labels map[string]string) metrics.Counter {
	return &NullCounter{}
}

func (n *nullMetrics) Gauge(name string, labels map[string]string) metrics.Gauge {
	return &NullGauge{}
}

func (n *nullMetrics) Observer(name string, labels map[string]string) metrics.Observer {
	return &NullObserver{}
}

// NullCounter 空计数器
type NullCounter struct{}

func (n *NullCounter) Inc()   {}
func (n *NullCounter) Add(float64) {}

// NullGauge 空仪表
type NullGauge struct{}

func (n *NullGauge) Set(float64)    {}
func (n *NullGauge) Add(float64)    {}
func (n *NullGauge) Inc()           {}
func (n *NullGauge) Dec()           {}

// NullObserver 空观察者
type NullObserver struct{}

func (n *NullObserver) Observe(float64) {}

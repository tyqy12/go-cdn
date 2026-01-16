package monitor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// TraceID 追踪ID
type TraceID string

// SpanID Span ID
type SpanID string

// Trace 追踪
type Trace struct {
	TraceID   TraceID
	Spans     []*Span
	StartedAt time.Time
	EndedAt   time.Time
	Status    TraceStatus
}

// Span 跨度
type Span struct {
	SpanID     SpanID
	ParentID   SpanID
	TraceID    TraceID
	Name       string
	Kind       SpanKind
	Status     SpanStatus
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration

	// 标签
	Tags map[string]string

	// 事件
	Events []*SpanEvent

	// 引用
	References []*SpanReference

	// 指标
	Metrics map[string]float64
}

// SpanEvent 跨度事件
type SpanEvent struct {
	Name      string
	Timestamp time.Time
	Fields    map[string]interface{}
}

// SpanReference 跨度引用
type SpanReference struct {
	TraceID TraceID
	SpanID  SpanID
	Rel     string // "child_of", "follows_from"
}

// SpanKind 跨度类型
type SpanKind string

const (
	SpanKindServer    SpanKind = "server"
	SpanKindClient    SpanKind = "client"
	SpanKindProducer  SpanKind = "producer"
	SpanKindConsumer  SpanKind = "consumer"
	SpanKindInternal  SpanKind = "internal"
)

// SpanStatus 跨度状态
type SpanStatus string

const (
	SpanStatusOK      SpanStatus = "ok"
	SpanStatusError   SpanStatus = "error"
	SpanStatusTimeout SpanStatus = "timeout"
)

// TraceStatus 追踪状态
type TraceStatus string

const (
	TraceStatusOK       TraceStatus = "ok"
	TraceStatusError    TraceStatus = "error"
	TraceStatusPartial  TraceStatus = "partial"
	TraceStatusTimeout  TraceStatus = "timeout"
)

// Tracer 分布式追踪器
type Tracer struct {
	mu          sync.RWMutex
	traces      map[TraceID]*Trace
	activeSpans map[context.Context]*Span
	sampler     Sampler
	exporter    SpanExporter
	logger      Logger
	config      *TracerConfig
}

// TracerConfig 追踪器配置
type TracerConfig struct {
	Enabled     bool
	ServiceName string
	Sampler     *SamplerConfig
	Exporter    *ExporterConfig
}

// SamplerConfig 采样配置
type SamplerConfig struct {
	Type      string
	Rate      float64
	Param     float64
	MaxTraces uint64
}

// ExporterConfig 导出器配置
type ExporterConfig struct {
	Type      string
	URL       string
	Auth      string
	RateLimit float64
}

// Sampler 采样器接口
type Sampler interface {
	ShouldSample(operation string) bool
	SampleRate(operation string) float64
}

// ConstSampler 常量采样器
type ConstSampler struct {
	Sample bool
}

// ShouldSample 是否采样
func (s *ConstSampler) ShouldSample(operation string) bool {
	return s.Sample
}

// SampleRate 采样率
func (s *ConstSampler) SampleRate(operation string) float64 {
	if s.Sample {
		return 1.0
	}
	return 0.0
}

// RateSampler 比率采样器
type RateSampler struct {
	Rate float64
	mu   sync.RWMutex
}

// ShouldSample 是否采样
func (s *RateSampler) ShouldSample(operation string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Rate >= 1.0 || time.Now().UnixNano()%10000 < int64(s.Rate*10000)
}

// SampleRate 采样率
func (s *RateSampler) SampleRate(operation string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Rate
}

// SpanExporter Span导出器接口
type SpanExporter interface {
	Export(spans []*Span) error
	Shutdown() error
}

// MemoryExporter 内存导出器
type MemoryExporter struct {
	Spans []*Span
	mu    sync.RWMutex
	Limit int
}

// Export 导出
func (e *MemoryExporter) Export(spans []*Span) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Spans = append(e.Spans, spans...)
	if e.Limit > 0 && len(e.Spans) > e.Limit {
		e.Spans = e.Spans[len(e.Spans)-e.Limit:]
	}

	return nil
}

// Shutdown 关闭
func (e *MemoryExporter) Shutdown() error {
	e.Spans = nil
	return nil
}

// GetSpans 获取所有span
func (e *MemoryExporter) GetSpans() []*Span {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Span, len(e.Spans))
	copy(result, e.Spans)
	return result
}

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// DefaultLogger 默认日志
type DefaultLogger struct{}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {}
func (l *DefaultLogger) Infof(format string, args ...interface{})  {}
func (l *DefaultLogger) Warnf(format string, args ...interface{})  {}
func (l *DefaultLogger) Errorf(format string, args ...interface{}) {}

// NewTracer 创建追踪器
func NewTracer(config *TracerConfig) *Tracer {
	if config == nil {
		config = &TracerConfig{
			Enabled:     true,
			ServiceName: "gocdn",
		}
	}

	tracer := &Tracer{
		traces:      make(map[TraceID]*Trace),
		activeSpans: make(map[context.Context]*Span),
		logger:      &DefaultLogger{},
		config:      config,
	}

	// 设置采样器
	tracer.sampler = tracer.createSampler(config.Sampler)

	// 设置导出器
	tracer.exporter = tracer.createExporter(config.Exporter)

	return tracer
}

// createSampler 创建采样器
func (t *Tracer) createSampler(config *SamplerConfig) Sampler {
	if config == nil {
		config = &SamplerConfig{
			Type: "const",
			Rate: 1.0,
		}
	}

	switch config.Type {
	case "rate":
		return &RateSampler{Rate: config.Rate}
	case "const":
		return &ConstSampler{Sample: config.Rate >= 1.0}
	default:
		return &ConstSampler{Sample: true}
	}
}

// createExporter 创建导出器
func (t *Tracer) createExporter(config *ExporterConfig) SpanExporter {
	if config == nil || config.Type == "" || config.Type == "memory" {
		return &MemoryExporter{Limit: 1000}
	}

	switch config.Type {
	case "jaeger":
		return &JaegerExporter{URL: config.URL}
	case "zipkin":
		return &ZipkinExporter{URL: config.URL}
	case "stdout":
		return &StdoutExporter{}
	default:
		return &MemoryExporter{Limit: 1000}
	}
}

// StartSpan 开始Span
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	// 检查是否需要采样
	if !t.sampler.ShouldSample(name) {
		return ctx, nil
	}

	// 生成ID
	spanID := SpanID(generateID(8))
	traceID := TraceID(generateID(16))

	// 获取父span
	parentSpan := t.activeSpans[ctx]
	if parentSpan != nil {
		traceID = parentSpan.TraceID
	}

	// 创建span
	span := &Span{
		SpanID:    spanID,
		ParentID:  parentSpan.SpanID,
		TraceID:   traceID,
		Name:      name,
		StartTime: time.Now(),
		Tags:      make(map[string]string),
		Events:    make([]*SpanEvent, 0),
		Metrics:   make(map[string]float64),
	}

	// 应用选项
	for _, opt := range opts {
		opt(span)
	}

	// 存储span
	t.mu.Lock()
	if _, ok := t.traces[traceID]; !ok {
		t.traces[traceID] = &Trace{
			TraceID:   traceID,
			Spans:     make([]*Span, 0),
			StartedAt: span.StartTime,
		}
	}
	t.traces[traceID].Spans = append(t.traces[traceID].Spans, span)
	t.mu.Unlock()

	// 存储到context
	ctx = context.WithValue(ctx, spanKey, span)
	t.activeSpans[ctx] = span

	return ctx, span
}

// SpanOption Span选项
type SpanOption func(*Span)

// WithSpanKind 设置span类型
func WithSpanKind(kind SpanKind) SpanOption {
	return func(s *Span) {
		s.Kind = kind
	}
}

// WithSpanTag 设置span标签
func WithSpanTag(key, value string) SpanOption {
	return func(s *Span) {
		s.Tags[key] = value
	}
}

// WithSpanReference 设置span引用
func WithSpanReference(traceID TraceID, spanID SpanID, rel string) SpanOption {
	return func(s *Span) {
		s.References = append(s.References, &SpanReference{
			TraceID: traceID,
			SpanID:  spanID,
			Rel:     rel,
		})
	}
}

// EndSpan 结束Span
func (t *Tracer) EndSpan(ctx context.Context) {
	span, ok := t.activeSpans[ctx]
	if !ok {
		return
	}

	span.EndTime = time.Now()
	span.Duration = span.EndTime.Sub(span.StartTime)

	// 更新trace状态
	if span.Status == SpanStatusError {
		t.mu.Lock()
		if trace, ok := t.traces[span.TraceID]; ok {
			trace.Status = TraceStatusError
		}
		t.mu.Unlock()
	}

	// 导出span
	if t.exporter != nil {
		t.exporter.Export([]*Span{span})
	}

	// 从context移除
	delete(t.activeSpans, ctx)
}

// AddEvent 添加事件
func (t *Tracer) AddEvent(ctx context.Context, name string, fields map[string]interface{}) {
	span, ok := t.activeSpans[ctx]
	if !ok {
		return
	}

	span.Events = append(span.Events, &SpanEvent{
		Name:      name,
		Timestamp: time.Now(),
		Fields:    fields,
	})
}

// SetTag 设置标签
func (t *Tracer) SetTag(ctx context.Context, key, value string) {
	span, ok := t.activeSpans[ctx]
	if !ok {
		return
	}

	span.Tags[key] = value
}

// SetError 设置错误
func (t *Tracer) SetError(ctx context.Context, err error) {
	span, ok := t.activeSpans[ctx]
	if !ok {
		return
	}

	span.Status = SpanStatusError
	span.Tags["error"] = "true"
	span.Tags["error.message"] = err.Error()
}

// SetMetric 设置指标
func (t *Tracer) SetMetric(ctx context.Context, key string, value float64) {
	span, ok := t.activeSpans[ctx]
	if !ok {
		return
	}

	span.Metrics[key] = value
}

// GetTrace 获取追踪
func (t *Tracer) GetTrace(traceID TraceID) (*Trace, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	trace, ok := t.traces[traceID]
	return trace, ok
}

// GetAllTraces 获取所有追踪
func (t *Tracer) GetAllTraces() []*Trace {
	t.mu.RLock()
	defer t.mu.RUnlock()

	traces := make([]*Trace, 0, len(t.traces))
	for _, trace := range t.traces {
		traces = append(traces, trace)
	}
	return traces
}

// GetActiveSpans 获取活跃span
func (t *Tracer) GetActiveSpans() []*Span {
	t.mu.RLock()
	defer t.mu.RUnlock()

	spans := make([]*Span, 0, len(t.activeSpans))
	for _, span := range t.activeSpans {
		spans = append(spans, span)
	}
	return spans
}

// Cleanup 清理过期追踪
func (t *Tracer) Cleanup(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for traceID, trace := range t.traces {
		if trace.StartedAt.Before(cutoff) {
			delete(t.traces, traceID)
		}
	}
}

// Shutdown 关闭
func (t *Tracer) Shutdown() {
	if t.exporter != nil {
		t.exporter.Shutdown()
	}
}

// generateID 生成ID
func generateID(size int) string {
	bytes := make([]byte, size)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// spanKey context key
type spanKeyType struct{}

var spanKey = spanKeyType{}

// SpanFromContext 从context获取span
func SpanFromContext(ctx context.Context) *Span {
	span, ok := ctx.Value(spanKey).(*Span)
	if !ok {
		return nil
	}
	return span
}

// TraceIDFromContext 从context获取traceID
func TraceIDFromContext(ctx context.Context) TraceID {
	span := SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	return span.TraceID
}

// JaegerExporter Jaeger导出器
type JaegerExporter struct {
	URL string
}

// Export 导出
func (e *JaegerExporter) Export(spans []*Span) error {
	// 简化实现：发送到Jaeger
	// 实际实现需要使用jaeger-client-go
	return nil
}

// Shutdown 关闭
func (e *JaegerExporter) Shutdown() error {
	return nil
}

// ZipkinExporter Zipkin导出器
type ZipkinExporter struct {
	URL string
}

// Export 导出
func (e *ZipkinExporter) Export(spans []*Span) error {
	// 简化实现：发送到Zipkin
	return nil
}

// Shutdown 关闭
func (e *ZipkinExporter) Shutdown() error {
	return nil
}

// StdoutExporter 标准输出导出器
type StdoutExporter struct{}

// Export 导出
func (e *StdoutExporter) Export(spans []*Span) error {
	for _, span := range spans {
		fmt.Printf("Span: %s %s %v\n", span.TraceID, span.Name, span.Duration)
	}
	return nil
}

// Shutdown 关闭
func (e *StdoutExporter) Shutdown() error {
	return nil
}

// RequestTracer 请求追踪器
type RequestTracer struct {
	tracer   *Tracer
	handlers []RequestHandler
}

// RequestHandler 请求处理程序
type RequestHandler func(ctx context.Context, span *Span) error

// NewRequestTracer 创建请求追踪器
func NewRequestTracer(tracer *Tracer) *RequestTracer {
	return &RequestTracer{
		tracer:   tracer,
		handlers: make([]RequestHandler, 0),
	}
}

// RegisterHandler 注册处理程序
func (rt *RequestTracer) RegisterHandler(handler RequestHandler) {
	rt.handlers = append(rt.handlers, handler)
}

// TraceRequest 追踪请求
func (rt *RequestTracer) TraceRequest(ctx context.Context, name string, fn func(ctx context.Context) error) error {
	ctx, span := rt.tracer.StartSpan(ctx, name)
	if span == nil {
		return fn(ctx)
	}

	defer rt.tracer.EndSpan(ctx)

	// 执行处理程序
	for _, handler := range rt.handlers {
		if err := handler(ctx, span); err != nil {
			rt.tracer.SetError(ctx, err)
			return err
		}
	}

	// 执行请求
	if err := fn(ctx); err != nil {
		rt.tracer.SetError(ctx, err)
		return err
	}

	return nil
}

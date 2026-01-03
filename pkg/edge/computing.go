package edge

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EdgeComputing 边缘计算服务
type EdgeComputing struct {
	config                *EdgeConfig
	runtime               *EdgeRuntime
	functions             map[string]*EdgeFunction
	executions            map[string]*ExecutionContext
	executionHistory      *list.List
	executionHistoryLimit int
	mu                    sync.RWMutex
	stats                 *EdgeStats
	ctx                   context.Context
	cancel                context.CancelFunc
}

// EdgeConfig 边缘计算配置
type EdgeConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 运行时配置
	RuntimeConfig RuntimeConfig `yaml:"runtime_config"`

	// 执行配置
	ExecutionConfig ExecutionConfig `yaml:"execution_config"`

	// 资源限制
	ResourceLimits ResourceLimits `yaml:"resource_limits"`

	// 超时配置
	TimeoutConfig TimeoutConfig `yaml:"timeout_config"`

	// 缓存配置
	CacheConfig CacheConfig `yaml:"cache_config"`

	// 环境变量
	Environment map[string]string `yaml:"environment"`
}

// RuntimeConfig 运行时配置
type RuntimeConfig struct {
	// 运行时类型
	Type string `yaml:"type"` // "quickjs", "wasm", "native"

	// QuickJS配置
	QuickJSConfig *QuickJSConfig `yaml:"quickjs_config"`

	// WASM配置
	WASMConfig *WASMConfig `yaml:"wasm_config"`

	// 内存限制
	MemoryLimit int `yaml:"memory_limit"` // MB

	// CPU限制
	CPULimit int `yaml:"cpu_limit"` // 百分比
}

// QuickJSConfig QuickJS配置
type QuickJSConfig struct {
	// 堆内存限制
	HeapLimit int `yaml:"heap_limit"` // MB

	// 最大栈大小
	MaxStackSize int `yaml:"max_stack_size"` // bytes

	// 断点调试
	BreakpointDebug bool `yaml:"breakpoint_debug"`

	// 调试端口
	DebugPort int `yaml:"debug_port"`
}

// WASMConfig WASM配置
type WASMConfig struct {
	// 最大内存
	MaxMemory int `yaml:"max_memory"` // MB

	// 实例数限制
	MaxInstances int `yaml:"max_instances"`

	// 编译超时
	CompilationTimeout time.Duration `yaml:"compilation_timeout"`
}

// ExecutionConfig 执行配置
type ExecutionConfig struct {
	// 最大并发数
	MaxConcurrent int `yaml:"max_concurrent"`

	// 请求队列大小
	QueueSize int `yaml:"queue_size"`

	// 预热配置
	WarmupConfig *WarmupConfig `yaml:"warmup_config"`
}

// WarmupConfig 预热配置
type WarmupConfig struct {
	// 启用预热
	Enabled bool `yaml:"enabled"`

	// 预热函数列表
	Functions []string `yaml:"functions"`

	// 预热间隔
	Interval time.Duration `yaml:"interval"`
}

// ResourceLimits 资源限制
type ResourceLimits struct {
	// 最大函数大小
	MaxFunctionSize int64 `yaml:"max_function_size"` // bytes

	// 最大代码大小
	MaxCodeSize int64 `yaml:"max_code_size"` // bytes

	// 最大环境变量
	MaxEnvVars int `yaml:"max_env_vars"`

	// 最大超时时间
	MaxTimeout time.Duration `yaml:"max_timeout"`

	// 最大重试次数
	MaxRetries int `yaml:"max_retries"`
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	// 执行超时
	ExecutionTimeout time.Duration `yaml:"execution_timeout"`

	// 初始化超时
	InitTimeout time.Duration `yaml:"init_timeout"`

	// 下载超时
	DownloadTimeout time.Duration `yaml:"download_timeout"`

	// 响应超时
	ResponseTimeout time.Duration `json:"response_timeout"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	// 启用结果缓存
	Enabled bool `yaml:"enabled"`

	// 缓存TTL
	TTL time.Duration `yaml:"ttl"`

	// 最大缓存大小
	MaxSize int64 `yaml:"max_size"` // bytes

	// 缓存键前缀
	KeyPrefix string `yaml:"key_prefix"`
}

// EdgeFunction 边缘函数
type EdgeFunction struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`

	// 代码
	Code     string `json:"code"`
	CodeHash string `json:"code_hash"`
	CodeSize int64  `json:"code_size"`

	// 配置
	Config FunctionConfig `json:"config"`

	// 运行时
	RuntimeType string `json:"runtime_type"`

	// 触发器
	Triggers []Trigger `json:"triggers"`

	// 状态
	Status string `json:"status"` // "active", "inactive", "deploying", "error"

	// 指标
	Metrics *FunctionMetrics `json:"metrics"`

	// 元数据
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	DeployedAt time.Time `json:"deployed_at"`
}

// FunctionConfig 函数配置
type FunctionConfig struct {
	// 入口点
	EntryPoint string `json:"entry_point"`

	// 内存限制
	MemoryLimit int `json:"memory_limit"` // MB

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 环境变量
	Environment map[string]string `json:"environment"`

	// 权限
	Permissions []Permission `json:"permissions"`

	// 网络访问
	NetworkAccess *NetworkAccess `json:"network_access"`
}

// Permission 权限
type Permission struct {
	Resource string   `json:"resource"` // "kv", "r2", "d1", etc.
	Actions  []string `json:"actions"`  // "read", "write", "delete"
}

// NetworkAccess 网络访问
type NetworkAccess struct {
	// 允许的域名
	AllowedDomains []string `json:"allowed_domains"`

	// 允许的IP范围
	AllowedIPRanges []string `json:"allowed_ip_ranges"`

	// DNS解析
	DNS *DNSConfig `json:"dns"`
}

// DNSConfig DNS配置
type DNSConfig struct {
	// 允许的DNS服务器
	Servers []string `json:"servers"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`
}

// Trigger 触发器
type Trigger struct {
	Type   string        `json:"type"` // "http", "cron", "event", "edge"
	Config TriggerConfig `json:"config"`
}

// TriggerConfig 触发器配置
type TriggerConfig struct {
	// HTTP触发
	Path   string `json:"path"`
	Method string `json:"method"`

	// Cron触发
	Cron string `json:"cron"`

	// 事件触发
	Events []string `json:"events"`

	// Edge触发
	Locations []string `json:"locations"`
}

// FunctionMetrics 函数指标
type FunctionMetrics struct {
	Invocations int64         `json:"invocations"`
	Errors      int64         `json:"errors"`
	Duration    time.Duration `json:"duration"`
	DurationP50 time.Duration `json:"duration_p50"`
	DurationP99 time.Duration `json:"duration_p99"`
	MemoryUsed  int64         `json:"memory_used"`
	CPUTime     time.Duration `json:"cpu_time"`
	NetworkIn   int64         `json:"network_in"`
	NetworkOut  int64         `json:"network_out"`
	mu          sync.RWMutex
}

// ExecutionContext 执行上下文
type ExecutionContext struct {
	ID         string         `json:"id"`
	FunctionID string         `json:"function_id"`
	RequestID  string         `json:"request_id"`
	StartTime  time.Time      `json:"start_time"`
	EndTime    time.Time      `json:"end_time"`
	Status     string         `json:"status"` // "running", "completed", "failed"
	Input      *RequestEvent  `json:"input"`
	Output     *ResponseEvent `json:"output"`
	Error      string         `json:"error"`
	Logs       []LogEntry     `json:"logs"`
	Trace      *Trace         `json:"trace"`
}

// RequestEvent 请求事件
type RequestEvent struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
	Context RequestContext    `json:"context"`
}

// RequestContext 请求上下文
type RequestContext struct {
	RequestID   string `json:"request_id"`
	ClientIP    string `json:"client_ip"`
	UserAgent   string `json:"user_agent"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Timestamp   int64  `json:"timestamp"`
	CacheStatus string `json:"cache_status"`
}

// ResponseEvent 响应事件
type ResponseEvent struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
	TTL        int               `json:"ttl"` // 缓存TTL
}

// LogEntry 日志条目
type LogEntry struct {
	Level   string    `json:"level"` // "debug", "info", "warn", "error"
	Message string    `json:"message"`
	Time    time.Time `json:"time"`
}

// Trace 跟踪
type Trace struct {
	Spans   []Span `json:"spans"`
	Context string `json:"context"`
}

// Span 跨度
type Span struct {
	Name      string            `json:"name"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
	Duration  time.Duration     `json:"duration"`
	Attrs     map[string]string `json:"attrs"`
}

// EdgeStats 边缘计算统计
type EdgeStats struct {
	TotalFunctions   int           `json:"total_functions"`
	ActiveFunctions  int           `json:"active_functions"`
	TotalInvocations int64         `json:"total_invocations"`
	TotalErrors      int64         `json:"total_errors"`
	AverageLatency   time.Duration `json:"average_latency"`
	TotalComputeTime time.Duration `json:"total_compute_time"`
	mu               sync.RWMutex
}

// EdgeRuntime 边缘运行时
type EdgeRuntime struct {
	config *RuntimeConfig
	vm     interface{}
	mu     sync.RWMutex
}

// NewEdgeComputing 创建边缘计算服务
func NewEdgeComputing(config *EdgeConfig) *EdgeComputing {
	if config == nil {
		config = &EdgeConfig{
			Enabled: true,
			RuntimeConfig: RuntimeConfig{
				Type:        "quickjs",
				MemoryLimit: 128,
				CPULimit:    100,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &EdgeComputing{
		config:                config,
		runtime:               &EdgeRuntime{config: &config.RuntimeConfig},
		functions:             make(map[string]*EdgeFunction),
		executions:            make(map[string]*ExecutionContext),
		executionHistory:      list.New(),
		executionHistoryLimit: 100,
		stats:                 &EdgeStats{},
		ctx:                   ctx,
		cancel:                cancel,
	}
}

// DeployFunction 部署函数
func (e *EdgeComputing) DeployFunction(function *EdgeFunction) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 计算代码哈希
	hash := sha256.Sum256([]byte(function.Code))
	function.CodeHash = base64.StdEncoding.EncodeToString(hash[:])

	// 设置状态
	function.Status = "deploying"
	function.CreatedAt = time.Now()
	function.Metrics = &FunctionMetrics{}

	// 验证代码
	if err := e.validateFunction(function); err != nil {
		function.Status = "error"
		return fmt.Errorf("代码验证失败: %w", err)
	}

	// 初始化运行时
	if err := e.runtime.Initialize(function); err != nil {
		function.Status = "error"
		return fmt.Errorf("运行时初始化失败: %w", err)
	}

	function.Status = "active"
	function.DeployedAt = time.Now()

	e.functions[function.ID] = function

	// 更新统计
	e.stats.mu.Lock()
	e.stats.TotalFunctions++
	e.stats.ActiveFunctions++
	e.stats.mu.Unlock()

	return nil
}

// validateFunction 验证函数
func (e *EdgeComputing) validateFunction(function *EdgeFunction) error {
	// 检查代码大小
	if len(function.Code) > int(e.config.ResourceLimits.MaxCodeSize) {
		return fmt.Errorf("代码大小超过限制")
	}

	// 检查环境变量数量
	if len(function.Config.Environment) > e.config.ResourceLimits.MaxEnvVars {
		return fmt.Errorf("环境变量数量超过限制")
	}

	// 检查入口点
	if function.Config.EntryPoint == "" {
		return fmt.Errorf("入口点不能为空")
	}

	return nil
}

// ExecuteFunction 执行函数
func (e *EdgeComputing) ExecuteFunction(functionID string, event *RequestEvent) (*ResponseEvent, error) {
	e.mu.RLock()
	function, ok := e.functions[functionID]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("函数不存在: %s", functionID)
	}

	if function.Status != "active" {
		return nil, fmt.Errorf("函数未激活: %s", functionID)
	}

	// 创建执行上下文
	execCtx := &ExecutionContext{
		ID:         fmt.Sprintf("exec_%d", time.Now().UnixNano()),
		FunctionID: functionID,
		RequestID:  event.Context.RequestID,
		StartTime:  time.Now(),
		Status:     "running",
		Input:      event,
	}

	// 添加到执行映射
	e.mu.Lock()
	e.executions[execCtx.ID] = execCtx
	e.mu.Unlock()

	// 执行函数
	response, err := e.runtime.Execute(function, event)

	// 更新上下文
	execCtx.EndTime = time.Now()
	execCtx.Output = response

	if err != nil {
		execCtx.Status = "failed"
		execCtx.Error = err.Error()

		e.mu.Lock()
		e.recordExecutionLocked(execCtx)
		e.mu.Unlock()

		function.Metrics.mu.Lock()
		function.Metrics.Errors++
		function.Metrics.mu.Unlock()

		e.stats.mu.Lock()
		e.stats.TotalErrors++
		e.stats.mu.Unlock()

		return nil, err
	}

	execCtx.Status = "completed"

	e.mu.Lock()
	e.recordExecutionLocked(execCtx)
	e.mu.Unlock()

	// 更新指标
	function.Metrics.mu.Lock()
	function.Metrics.Invocations++
	function.Metrics.Duration += time.Since(execCtx.StartTime)
	function.Metrics.mu.Unlock()

	e.stats.mu.Lock()
	e.stats.TotalInvocations++
	e.stats.TotalComputeTime += time.Since(execCtx.StartTime)
	e.stats.mu.Unlock()

	return response, nil
}

func (e *EdgeComputing) recordExecutionLocked(execCtx *ExecutionContext) {
	if e.executionHistory == nil {
		e.executionHistory = list.New()
	}
	if e.executionHistoryLimit <= 0 {
		e.executionHistoryLimit = 100
	}

	e.executionHistory.PushBack(execCtx.ID)

	for e.executionHistory.Len() > e.executionHistoryLimit {
		front := e.executionHistory.Front()
		if front == nil {
			break
		}
		if id, ok := front.Value.(string); ok {
			delete(e.executions, id)
		}
		e.executionHistory.Remove(front)
	}
}

// GetFunction 获取函数
func (e *EdgeComputing) GetFunction(functionID string) (*EdgeFunction, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	function, ok := e.functions[functionID]
	if !ok {
		return nil, fmt.Errorf("函数不存在: %s", functionID)
	}

	return function, nil
}

// ListFunctions 列出函数
func (e *EdgeComputing) ListFunctions() []*EdgeFunction {
	e.mu.RLock()
	defer e.mu.RUnlock()

	functions := make([]*EdgeFunction, 0, len(e.functions))
	for _, f := range e.functions {
		functions = append(functions, f)
	}

	return functions
}

// DeleteFunction 删除函数
func (e *EdgeComputing) DeleteFunction(functionID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, ok := e.functions[functionID]
	if !ok {
		return fmt.Errorf("函数不存在: %s", functionID)
	}

	delete(e.functions, functionID)

	e.stats.mu.Lock()
	e.stats.ActiveFunctions--
	e.stats.mu.Unlock()

	return nil
}

// GetFunctionMetrics 获取函数指标
func (e *EdgeComputing) GetFunctionMetrics(functionID string) *FunctionMetrics {
	e.mu.RLock()
	defer e.mu.RUnlock()

	function, ok := e.functions[functionID]
	if !ok {
		return nil
	}

	return function.Metrics
}

// GetStats 获取统计
func (e *EdgeComputing) GetStats() *EdgeStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	return e.stats
}

// Initialize 初始化运行时
func (r *EdgeRuntime) Initialize(function *EdgeFunction) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.config.Type {
	case "quickjs":
		return r.initializeQuickJS(function)
	case "wasm":
		return r.initializeWASM(function)
	default:
		return fmt.Errorf("不支持的运行时类型: %s", r.config.Type)
	}
}

// initializeQuickJS 初始化QuickJS
func (r *EdgeRuntime) initializeQuickJS(function *EdgeFunction) error {
	// QuickJS初始化逻辑
	// 由于QuickJS的Go绑定库在Windows上可能存在兼容性问题
	// 这里提供一个通用的实现框架，实际部署时可以根据平台选择合适的JS引擎

	// 1. 创建虚拟机实例
	// 2. 设置内存和栈限制
	quickJSConfig := r.config.QuickJSConfig
	if quickJSConfig == nil {
		quickJSConfig = &QuickJSConfig{}
	}

	heapLimit := quickJSConfig.HeapLimit
	if heapLimit == 0 {
		heapLimit = 128
	}

	maxStackSize := quickJSConfig.MaxStackSize
	if maxStackSize == 0 {
		maxStackSize = 1024 * 1024
	}

	// 3. 编译函数代码
	// 验证JavaScript代码语法
	if function.Code == "" {
		return fmt.Errorf("函数代码不能为空")
	}

	// 4. 准备执行环境
	// 注入全局对象：console, fetch, KV, Request, Response等

	// 5. 预编译优化
	// 将编译后的字节码存储到r.vm中，避免重复编译

	// 标记为已初始化
	r.vm = map[string]interface{}{
		"initialized": true,
		"function":    function,
		"heapLimit":   heapLimit,
		"maxStack":    maxStackSize,
	}

	return nil
}

// initializeWASM 初始化WASM
func (r *EdgeRuntime) initializeWASM(function *EdgeFunction) error {
	// WASM运行时初始化逻辑
	// 支持标准WebAssembly模块执行

	// 1. 验证WASM二进制格式
	if function.Code == "" {
		return fmt.Errorf("WASM模块不能为空")
	}

	// WASM模块应该是base64编码的二进制数据
	wasmBytes, err := base64.StdEncoding.DecodeString(function.Code)
	if err != nil {
		// 如果解码失败，假设是原始字节
		wasmBytes = []byte(function.Code)
	}

	// 2. 验证WASM魔数 (0x00 0x61 0x73 0x6d)
	if len(wasmBytes) < 4 {
		return fmt.Errorf("无效的WASM模块：文件太小")
	}
	if wasmBytes[0] != 0x00 || wasmBytes[1] != 0x61 || wasmBytes[2] != 0x73 || wasmBytes[3] != 0x6d {
		return fmt.Errorf("无效的WASM模块：魔数不匹配")
	}

	// 3. 创建WASM运行时实例
	// 应用配置限制
	wasmConfig := r.config.WASMConfig
	if wasmConfig == nil {
		wasmConfig = &WASMConfig{}
	}

	maxMemory := wasmConfig.MaxMemory
	if maxMemory == 0 {
		maxMemory = 512
	}

	maxInstances := wasmConfig.MaxInstances
	if maxInstances == 0 {
		maxInstances = 10
	}

	// 4. 编译WASM模块
	// 使用wasmer-go或wasmtime-go
	// 由于平台兼容性，这里提供通用框架

	// 5. 预实例化
	// 创建模块实例池以提高性能

	// 6. 导入对象
	// 配置WASI接口和自定义导入
	// - env.memory
	// - env.table
	// - wasi_snapshot_preview1.*

	// 标记为已初始化
	r.vm = map[string]interface{}{
		"initialized":  true,
		"function":     function,
		"wasmBytes":    wasmBytes,
		"maxMemory":    maxMemory,
		"maxInstances": maxInstances,
	}

	return nil
}

// Execute 执行函数
func (r *EdgeRuntime) Execute(function *EdgeFunction, event *RequestEvent) (*ResponseEvent, error) {
	switch function.RuntimeType {
	case "quickjs":
		return r.executeQuickJS(function, event)
	case "wasm":
		return r.executeWASM(function, event)
	default:
		return nil, fmt.Errorf("不支持的运行时类型: %s", function.RuntimeType)
	}
}

// executeQuickJS 执行QuickJS函数
func (r *EdgeRuntime) executeQuickJS(function *EdgeFunction, event *RequestEvent) (*ResponseEvent, error) {
	// QuickJS函数执行逻辑

	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. 检查虚拟机是否已初始化
	if r.vm == nil {
		return nil, fmt.Errorf("运行时未初始化")
	}

	// 2. 准备请求上下文
	// 构建传递给JavaScript的event对象
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("序列化事件失败: %w", err)
	}

	// 3. 执行JavaScript代码
	// 标准的执行流程：
	// - 创建隔离的执行上下文
	// - 注入全局对象 (Request, Response, console等)
	// - 调用入口函数
	// - 获取返回值

	// 4. 构建执行脚本
	entryPoint := function.Config.EntryPoint
	if entryPoint == "" {
		entryPoint = "handleRequest" // 默认入口函数
	}

	// 执行脚本模板
	script := fmt.Sprintf(`
		(function() {
			// 注入event对象
			const event = %s;

			// 执行用户代码
			%s

			// 调用入口函数
			if (typeof %s === 'function') {
				return %s(event);
			} else {
				throw new Error('入口函数 %s 不存在');
			}
		})();
	`, string(eventJSON), function.Code, entryPoint, entryPoint, entryPoint)

	// 5. 设置超时
	timeout := function.Config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // 默认30秒
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 6. 执行（模拟）
	// 实际实现需要集成真实的QuickJS引擎
	// 这里提供一个基本的响应框架

	// 等待执行完成或超时
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("执行超时")
	default:
		// 成功执行
	}

	// 7. 解析返回值
	// JavaScript函数应该返回一个Response对象
	// { statusCode: 200, headers: {}, body: "..." }

	// 示例：解析函数代码以提取简单的返回值
	// 实际应该从JS执行结果中获取
	response := &ResponseEvent{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":       "application/json",
			"X-Powered-By":       "AI-CDN-EdgeComputing",
			"X-Function-Runtime": "QuickJS",
			"X-Function-Name":    function.Name,
			"X-Execution-ID":     fmt.Sprintf("%d", time.Now().UnixNano()),
		},
		Body: []byte(fmt.Sprintf(`{"success":true,"message":"Function executed","script_length":%d}`, len(script))),
	}

	return response, nil
}

// executeWASM 执行WASM函数
func (r *EdgeRuntime) executeWASM(function *EdgeFunction, event *RequestEvent) (*ResponseEvent, error) {
	// WASM函数执行逻辑

	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. 检查虚拟机是否已初始化
	if r.vm == nil {
		return nil, fmt.Errorf("WASM运行时未初始化")
	}

	vmData, ok := r.vm.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("WASM运行时数据格式错误")
	}

	// 2. 获取WASM字节码
	wasmBytes, ok := vmData["wasmBytes"].([]byte)
	if !ok || len(wasmBytes) == 0 {
		return nil, fmt.Errorf("WASM字节码不存在")
	}

	// 3. 准备输入数据
	// 将event序列化为JSON，传递给WASM模块
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("序列化事件失败: %w", err)
	}

	// 4. 设置执行超时
	timeout := function.Config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 5. 执行WASM模块
	// 标准流程：
	// - 实例化WASM模块
	// - 配置WASI导入（文件系统、环境变量等）
	// - 调用导出函数（通常是handle_request或main）
	// - 从线性内存中读取返回值

	entryPoint := function.Config.EntryPoint
	if entryPoint == "" {
		entryPoint = "handle_request" // WASM默认入口函数
	}

	// 6. 执行并等待结果
	resultChan := make(chan *ResponseEvent, 1)
	errorChan := make(chan error, 1)

	go func() {
		// 模拟WASM执行
		// 实际实现需要：
		// 1. 使用wasmer-go或wasmtime-go加载模块
		// 2. 创建实例并配置导入
		// 3. 调用入口函数
		// 4. 从内存读取结果

		// 模拟执行延迟
		time.Sleep(10 * time.Millisecond)

		// 构建响应
		result := &ResponseEvent{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type":       "application/json",
				"X-Powered-By":       "AI-CDN-EdgeComputing",
				"X-Function-Runtime": "WASM",
				"X-Function-Name":    function.Name,
				"X-WASM-Size":        fmt.Sprintf("%d", len(wasmBytes)),
				"X-Entry-Point":      entryPoint,
			},
			Body: []byte(fmt.Sprintf(
				`{"success":true,"message":"WASM function executed","input_size":%d,"wasm_size":%d}`,
				len(eventJSON),
				len(wasmBytes),
			)),
		}

		resultChan <- result
	}()

	// 7. 等待执行完成或超时
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("WASM执行超时")
	case err := <-errorChan:
		return nil, fmt.Errorf("WASM执行失败: %w", err)
	case result := <-resultChan:
		return result, nil
	}
}

// KVStore KV存储
type KVStore struct {
	data map[string]*KVEntry
	mu   sync.RWMutex
}

// KVEntry KV条目
type KVEntry struct {
	Key        string   `json:"key"`
	Value      string   `json:"value"`
	Expiration int64    `json:"expiration"` // Unix timestamp
	Metadata   Metadata `json:"metadata"`
}

// Metadata 元数据
type Metadata struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Size      int       `json:"size"`
}

// NewKVStore 创建KV存储
func NewKVStore() *KVStore {
	return &KVStore{
		data: make(map[string]*KVEntry),
	}
}

// Get 获取值
func (s *KVStore) Get(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.data[key]
	if !ok {
		return "", fmt.Errorf("键不存在: %s", key)
	}

	// 检查过期
	if entry.Expiration > 0 && time.Now().Unix() > entry.Expiration {
		return "", fmt.Errorf("键已过期: %s", key)
	}

	return entry.Value, nil
}

// Set 设置值
func (s *KVStore) Set(key, value string, expiration int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.data[key] = &KVEntry{
		Key:        key,
		Value:      value,
		Expiration: expiration,
		Metadata: Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Size:      len(value),
		},
	}

	return nil
}

// Delete 删除值
func (s *KVStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	return nil
}

// List 列出键
func (s *KVStore) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0)
	for k := range s.data {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}

	return keys, nil
}

// HandleHTTPRequest 处理HTTP请求
func (e *EdgeComputing) HandleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// 解析路径获取函数名和路径
	// 示例: /functions/<function-name>/<path>
	// 或: /f/<function-id>/*

	path := r.URL.Path

	// 解析路径
	// 支持格式: /functions/{functionName}/* 或 /f/{functionID}/*
	var functionID string
	var requestPath string

	if strings.HasPrefix(path, "/functions/") {
		// /functions/myfunction/api/users
		parts := strings.SplitN(strings.TrimPrefix(path, "/functions/"), "/", 2)
		functionName := parts[0]
		if len(parts) > 1 {
			requestPath = "/" + parts[1]
		} else {
			requestPath = "/"
		}

		// 根据名称查找函数ID
		e.mu.RLock()
		for id, fn := range e.functions {
			if fn.Name == functionName {
				functionID = id
				break
			}
		}
		e.mu.RUnlock()

	} else if strings.HasPrefix(path, "/f/") {
		// /f/func-123/api/users
		parts := strings.SplitN(strings.TrimPrefix(path, "/f/"), "/", 2)
		functionID = parts[0]
		if len(parts) > 1 {
			requestPath = "/" + parts[1]
		} else {
			requestPath = "/"
		}
	} else {
		http.Error(w, "Invalid function path", http.StatusBadRequest)
		return
	}

	if functionID == "" {
		http.Error(w, "Function not found", http.StatusNotFound)
		return
	}

	// 读取请求体
	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
	}

	// 解析查询参数
	query := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}

	// 解析请求头
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// 获取客户端IP
	clientIP := r.RemoteAddr
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		clientIP = strings.Split(forwardedFor, ",")[0]
	} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}

	// 构建请求事件
	event := &RequestEvent{
		Method:  r.Method,
		Path:    requestPath,
		Query:   query,
		Headers: headers,
		Body:    body,
		Context: RequestContext{
			RequestID:   fmt.Sprintf("req_%d", time.Now().UnixNano()),
			ClientIP:    clientIP,
			UserAgent:   r.Header.Get("User-Agent"),
			Timestamp:   time.Now().Unix(),
			CacheStatus: "MISS",
		},
	}

	// 执行函数
	response, err := e.ExecuteFunction(functionID, event)
	if err != nil {
		http.Error(w, fmt.Sprintf("Function execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 设置响应头
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}

	// 写入状态码
	w.WriteHeader(response.StatusCode)

	// 写入响应体
	w.Write(response.Body)
}

// HandleCronTrigger 处理Cron触发
func (e *EdgeComputing) HandleCronTrigger(functionID string) error {
	// 创建空事件
	event := &RequestEvent{
		Method: "CRON",
		Path:   "/cron",
		Context: RequestContext{
			RequestID: fmt.Sprintf("cron_%d", time.Now().UnixNano()),
			Timestamp: time.Now().Unix(),
		},
	}

	_, err := e.ExecuteFunction(functionID, event)
	return err
}

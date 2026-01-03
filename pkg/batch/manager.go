package batch

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BatchManager 批量操作管理器
type BatchManager struct {
	config     *BatchConfig
	operations map[string]*BatchOperation
	tasks      map[string]*BatchTask
	executors  map[string]OperationExecutor
	mu         sync.RWMutex
	stats      *BatchStats
	ctx        context.Context
	cancel     context.CancelFunc
}

// BatchConfig 批量操作配置
type BatchConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 并发配置
	ConcurrencyConfig *ConcurrencyConfig `yaml:"concurrency_config"`

	// 进度配置
	ProgressConfig *ProgressConfig `yaml:"progress_config"`

	// 错误处理
	ErrorConfig *ErrorConfig `yaml:"error_config"`

	// 超时配置
	TimeoutConfig *TimeoutConfig `yaml:"timeout_config"`

	// 重试配置
	RetryConfig *RetryConfig `yaml:"retry_config"`
}

// ConcurrencyConfig 并发配置
type ConcurrencyConfig struct {
	// 全局并发数
	GlobalConcurrency int `yaml:"global_concurrency"`

	// 每种操作的并发数
	PerOperationConcurrency int `yaml:"per_operation_concurrency"`

	// 队列大小
	QueueSize int `yaml:"queue_size"`

	// 批次大小
	BatchSize int `yaml:"batch_size"`

	// 批次间隔
	BatchInterval time.Duration `yaml:"batch_interval"`
}

// ProgressConfig 进度配置
type ProgressConfig struct {
	// 启用进度跟踪
	Enabled bool `yaml:"enabled"`

	// 进度更新间隔
	UpdateInterval time.Duration `yaml:"update_interval"`

	// 存储进度
	PersistProgress bool `yaml:"persist_progress"`

	// 存储路径
	StoragePath string `yaml:"storage_path"`
}

// ErrorConfig 错误处理配置
type ErrorConfig struct {
	// 错误处理策略
	Strategy string `json:"strategy"` // "stop", "continue", "retry"

	// 最大错误数
	MaxErrors int `json:"max_errors"`

	// 错误率阈值
	ErrorRateThreshold float64 `json:"error_rate_threshold"`

	// 错误收集
	ErrorCollection bool `json:"error_collection"`

	// 错误存储路径
	ErrorStoragePath string `json:"error_storage_path"`
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	// 全局超时
	GlobalTimeout time.Duration `json:"global_timeout"`

	// 单项超时
	PerItemTimeout time.Duration `json:"per_item_timeout"`

	// 空闲超时
	IdleTimeout time.Duration `json:"idle_timeout"`
}

// RetryConfig 重试配置
type RetryConfig struct {
	// 启用重试
	Enabled bool `json:"enabled"`

	// 最大重试次数
	MaxRetries int `json:"max_retries"`

	// 重试间隔
	Interval time.Duration `json:"interval"`

	// 指数退避
	ExponentialBackoff bool `json:"exponential_backoff"`

	// 最大间隔
	MaxInterval time.Duration `json:"max_interval"`
}

// OperationExecutor 操作执行器接口
type OperationExecutor interface {
	Execute(ctx context.Context, item *OperationItem) *OperationResult
	GetOperationType() string
}

// BatchOperation 批量操作
type BatchOperation struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`

	// 参数
	Params map[string]interface{} `json:"params"`

	// 目标列表
	Targets []*OperationTarget `json:"targets"`

	// 配置
	Config *OperationConfig `json:"config"`

	// 状态
	Status string `json:"status"` // "pending", "running", "paused", "completed", "failed"

	// 进度
	Progress *OperationProgress `json:"progress"`

	// 结果
	Result *OperationSummary `json:"result"`

	// 错误
	Errors []*OperationError `json:"errors"`

	// 时间
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	CreatedBy   string     `json:"created_by"`
}

// OperationTarget 操作目标
type OperationTarget struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`       // "node", "domain", "config", "user"
	Identifier string                 `json:"identifier"` // ID或名称
	Metadata   map[string]interface{} `json:"metadata"`
}

// OperationConfig 操作配置
type OperationConfig struct {
	// 并发数
	Concurrency int `json:"concurrency"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 重试次数
	Retries int `json:"retries"`

	// 验证
	Validation *ValidationConfig `json:"validation"`
}

// ValidationConfig 验证配置
type ValidationConfig struct {
	// 启用验证
	Enabled bool `json:"enabled"`

	// 验证类型
	Type string `json:"type"` // "pre", "post", "both"

	// 验证规则
	Rules []ValidationRule `json:"rules"`
}

// ValidationRule 验证规则
type ValidationRule struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "eq", "ne", "gt", "lt", "in", "regex"
	Value    interface{} `json:"value"`
	Message  string      `json:"message"`
}

// OperationProgress 操作进度
type OperationProgress struct {
	TotalItems     int `json:"total_items"`
	ProcessedItems int `json:"processed_items"`
	SuccessItems   int `json:"success_items"`
	FailedItems    int `json:"failed_items"`
	SkippedItems   int `json:"skipped_items"`

	// 进度百分比
	Percentage float64 `json:"percentage"`

	// 状态
	Status string `json:"status"`

	// 当前处理
	CurrentItem string `json:"current_item"`

	// 开始时间
	StartTime time.Time `json:"start_time"`

	// 最后更新
	LastUpdate time.Time `json:"last_update"`

	// 预计剩余时间
	EstimatedRemaining time.Duration `json:"estimated_remaining"`

	// 速度
	ItemsPerSecond float64 `json:"items_per_second"`

	mu sync.RWMutex
}

// OperationSummary 操作结果
type OperationSummary struct {
	// 总体结果
	Success bool `json:"success"`

	// 统计
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`

	// 执行时间
	ExecutionTime time.Duration `json:"execution_time"`

	// 平均处理时间
	AvgProcessingTime time.Duration `json:"avg_processing_time"`

	// 输出
	Output []*OperationOutput `json:"output"`

	// 摘要
	Summary string `json:"summary"`
}

// OperationOutput 操作输出
type OperationOutput struct {
	TargetID string                 `json:"target_id"`
	Success  bool                   `json:"success"`
	Data     map[string]interface{} `json:"data"`
	Error    string                 `json:"error"`
}

// OperationError 操作错误
type OperationError struct {
	TargetID   string    `json:"target_id"`
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details"`
	OccurredAt time.Time `json:"occurred_at"`
}

// OperationItem 操作项
type OperationItem struct {
	ID         string                 `json:"id"`
	Target     *OperationTarget       `json:"target"`
	Params     map[string]interface{} `json:"params"`
	RetryCount int                    `json:"retry_count"`
	Priority   int                    `json:"priority"` // 0-100, 越高越优先
}

// OperationResult 单项操作结果
type OperationResult struct {
	Success  bool            `json:"success"`
	Data     interface{}     `json:"data"`
	Error    *OperationError `json:"error"`
	Duration time.Duration   `json:"duration"`
}

// BatchTask 批量任务
type BatchTask struct {
	ID          string        `json:"id"`
	OperationID string        `json:"operation_id"`
	Status      string        `json:"status"` // "pending", "running", "completed", "failed"
	Items       []*TaskItem   `json:"items"`
	Progress    *TaskProgress `json:"progress"`
	CreatedAt   time.Time     `json:"created_at"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
}

// TaskItem 任务项
type TaskItem struct {
	ID      string           `json:"id"`
	Target  string           `json:"target"`
	Status  string           `json:"status"` // "pending", "running", "completed", "failed"
	Retries int              `json:"retries"`
	Result  *OperationResult `json:"result"`
}

// TaskProgress 任务进度
type TaskProgress struct {
	Total     int    `json:"total"`
	Completed int    `json:"completed"`
	Failed    int    `json:"failed"`
	Current   string `json:"current"`
}

// BatchStats 批量操作统计
type BatchStats struct {
	TotalOperations     int64            `json:"total_operations"`
	RunningOperations   int64            `json:"running_operations"`
	CompletedOperations int64            `json:"completed_operations"`
	FailedOperations    int64            `json:"failed_operations"`
	TotalItems          int64            `json:"total_items"`
	ProcessedItems      int64            `json:"processed_items"`
	SuccessRate         float64          `json:"success_rate"`
	AverageDuration     time.Duration    `json:"average_duration"`
	OperationsByType    map[string]int64 `json:"operations_by_type"`
	mu                  sync.RWMutex
}

// NodeBatchExecutor 节点批量执行器
type NodeBatchExecutor struct {
	config *ExecutorConfig
}

// ExecutorConfig 执行器配置
type ExecutorConfig struct {
	BatchSize   int           `json:"batch_size"`
	Timeout     time.Duration `json:"timeout"`
	MaxRetries  int           `json:"max_retries"`
	Parallelism int           `json:"parallelism"`
}

// Execute 执行操作
func (e *NodeBatchExecutor) Execute(ctx context.Context, item *OperationItem) *OperationResult {
	return &OperationResult{
		Success:  true,
		Duration: time.Millisecond * 100,
	}
}

// GetOperationType 获取操作类型
func (e *NodeBatchExecutor) GetOperationType() string {
	return "node"
}

// DomainBatchExecutor 域名批量执行器
type DomainBatchExecutor struct {
	config *ExecutorConfig
}

// Execute 执行操作
func (e *DomainBatchExecutor) Execute(ctx context.Context, item *OperationItem) *OperationResult {
	return &OperationResult{
		Success:  true,
		Duration: time.Millisecond * 100,
	}
}

// GetOperationType 获取操作类型
func (e *DomainBatchExecutor) GetOperationType() string {
	return "domain"
}

// ConfigBatchExecutor 配置批量执行器
type ConfigBatchExecutor struct {
	config *ExecutorConfig
}

// Execute 执行操作
func (e *ConfigBatchExecutor) Execute(ctx context.Context, item *OperationItem) *OperationResult {
	return &OperationResult{
		Success:  true,
		Duration: time.Millisecond * 50,
	}
}

// GetOperationType 获取操作类型
func (e *ConfigBatchExecutor) GetOperationType() string {
	return "config"
}

// NewBatchManager 创建批量操作管理器
func NewBatchManager(config *BatchConfig) *BatchManager {
	if config == nil {
		config = &BatchConfig{
			Enabled: true,
			ConcurrencyConfig: &ConcurrencyConfig{
				GlobalConcurrency:       10,
				PerOperationConcurrency: 5,
				QueueSize:               1000,
				BatchSize:               100,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &BatchManager{
		config:     config,
		operations: make(map[string]*BatchOperation),
		tasks:      make(map[string]*BatchTask),
		executors:  make(map[string]OperationExecutor),
		stats:      &BatchStats{OperationsByType: make(map[string]int64)},
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterExecutor 注册执行器
func (m *BatchManager) RegisterExecutor(executor OperationExecutor) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.executors[executor.GetOperationType()] = executor
}

// CreateOperation 创建批量操作
func (m *BatchManager) CreateOperation(operation *BatchOperation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	operation.ID = fmt.Sprintf("batch_%d", time.Now().UnixNano())
	operation.CreatedAt = time.Now()
	operation.Status = "pending"
	operation.Progress = &OperationProgress{
		TotalItems: len(operation.Targets),
		Status:     "pending",
		StartTime:  time.Now(),
	}

	m.operations[operation.ID] = operation

	m.stats.mu.Lock()
	m.stats.TotalOperations++
	m.stats.OperationsByType[operation.Type]++
	m.mu.Unlock()

	return nil
}

// StartOperation 启动批量操作
func (m *BatchManager) StartOperation(operationID string) error {
	m.mu.RLock()
	operation, ok := m.operations[operationID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("操作不存在: %s", operationID)
	}

	// 获取执行器
	m.mu.RLock()
	executor, ok := m.executors[operation.Type]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("没有找到执行器: %s", operation.Type)
	}

	// 更新状态
	m.mu.Lock()
	operation.Status = "running"
	now := time.Now()
	operation.StartedAt = &now
	m.mu.Unlock()

	// 异步执行
	go m.executeOperation(operation, executor)

	return nil
}

// executeOperation 执行批量操作
func (m *BatchManager) executeOperation(operation *BatchOperation, executor OperationExecutor) {
	ctx, cancel := context.WithTimeout(context.Background(), operation.Config.Timeout)
	defer cancel()

	startTime := time.Now()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, operation.Config.Concurrency)
	results := make(chan *OperationResult, len(operation.Targets))

	// 更新统计
	m.stats.mu.Lock()
	m.stats.RunningOperations++
	m.mu.Unlock()

	// 执行每个目标
	for i, target := range operation.Targets {
		wg.Add(1)

		go func(t *OperationTarget, idx int) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			item := &OperationItem{
				ID:       fmt.Sprintf("%s_%d", operation.ID, idx),
				Target:   t,
				Params:   operation.Params,
				Priority: 50,
			}

			result := executor.Execute(ctx, item)
			results <- result
		}(target, i)
	}

	wg.Wait()
	close(results)

	// 收集结果
	m.mu.Lock()
	for result := range results {
		if result.Success {
			operation.Progress.SuccessItems++
		} else {
			operation.Progress.FailedItems++
			operation.Errors = append(operation.Errors, &OperationError{
				TargetID:   result.Error.TargetID,
				Code:       result.Error.Code,
				Message:    result.Error.Message,
				OccurredAt: time.Now(),
			})
		}
		operation.Progress.ProcessedItems++
	}

	// 更新进度
	operation.Progress.Percentage = float64(operation.Progress.ProcessedItems) / float64(operation.Progress.TotalItems) * 100
	operation.Progress.LastUpdate = time.Now()

	// 计算执行时间
	executionTime := time.Since(startTime)
	operation.Progress.EstimatedRemaining = time.Duration(float64(executionTime) / float64(operation.Progress.ProcessedItems) * float64(operation.Progress.TotalItems-operation.Progress.ProcessedItems))

	// 更新结果
	operation.Result = &OperationSummary{
		Success:           operation.Progress.FailedItems == 0,
		Total:             operation.Progress.TotalItems,
		Succeeded:         operation.Progress.SuccessItems,
		Failed:            operation.Progress.FailedItems,
		Skipped:           operation.Progress.SkippedItems,
		ExecutionTime:     executionTime,
		AvgProcessingTime: executionTime / time.Duration(operation.Progress.ProcessedItems),
	}

	// 更新状态
	if operation.Progress.FailedItems > 0 && m.config.ErrorConfig.Strategy == "stop" {
		operation.Status = "failed"
		m.stats.mu.Lock()
		m.stats.FailedOperations++
		m.mu.Unlock()
	} else {
		operation.Status = "completed"
		m.stats.mu.Lock()
		m.stats.CompletedOperations++
		m.mu.Unlock()
	}

	now := time.Now()
	operation.CompletedAt = &now
	m.mu.Unlock()

	// 更新统计
	m.stats.mu.Lock()
	m.stats.RunningOperations--
	m.stats.TotalItems += int64(operation.Progress.TotalItems)
	m.stats.ProcessedItems += int64(operation.Progress.ProcessedItems)

	if m.stats.TotalOperations > 0 {
		m.stats.SuccessRate = float64(m.stats.CompletedOperations) / float64(m.stats.TotalOperations) * 100
	}
	m.mu.Unlock()
}

// PauseOperation 暂停操作
func (m *BatchManager) PauseOperation(operationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	operation, ok := m.operations[operationID]
	if !ok {
		return fmt.Errorf("操作不存在: %s", operationID)
	}

	if operation.Status != "running" {
		return fmt.Errorf("操作未在运行中")
	}

	operation.Status = "paused"

	return nil
}

// ResumeOperation 恢复操作
func (m *BatchManager) ResumeOperation(operationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	operation, ok := m.operations[operationID]
	if !ok {
		return fmt.Errorf("操作不存在: %s", operationID)
	}

	if operation.Status != "paused" {
		return fmt.Errorf("操作未暂停")
	}

	operation.Status = "running"

	// 重新执行
	go m.executeOperation(operation, nil)

	return nil
}

// CancelOperation 取消操作
func (m *BatchManager) CancelOperation(operationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	operation, ok := m.operations[operationID]
	if !ok {
		return fmt.Errorf("操作不存在: %s", operationID)
	}

	operation.Status = "failed"

	return nil
}

// GetOperation 获取操作
func (m *BatchManager) GetOperation(operationID string) (*BatchOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	operation, ok := m.operations[operationID]
	if !ok {
		return nil, fmt.Errorf("操作不存在: %s", operationID)
	}

	return operation, nil
}

// ListOperations 列出操作
func (m *BatchManager) ListOperations(status string, page, pageSize int) ([]*BatchOperation, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var operations []*BatchOperation
	for _, op := range m.operations {
		if status == "" || op.Status == status {
			operations = append(operations, op)
		}
	}

	total := int64(len(operations))
	start := (page - 1) * pageSize
	end := start + pageSize

	if start > len(operations) {
		return nil, total
	}

	if end > len(operations) {
		end = len(operations)
	}

	return operations[start:end], total
}

// GetProgress 获取操作进度
func (m *BatchManager) GetProgress(operationID string) (*OperationProgress, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	operation, ok := m.operations[operationID]
	if !ok {
		return nil, fmt.Errorf("操作不存在: %s", operationID)
	}

	return operation.Progress, nil
}

// GetStats 获取统计
func (m *BatchManager) GetStats() *BatchStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return m.stats
}

// BatchNodeOperation 批量节点操作
func (m *BatchManager) BatchNodeOperation(operation string, nodeIDs []string, params map[string]interface{}) error {
	targets := make([]*OperationTarget, len(nodeIDs))

	for i, nodeID := range nodeIDs {
		targets[i] = &OperationTarget{
			ID:         nodeID,
			Type:       "node",
			Identifier: nodeID,
		}
	}

	batchOp := &BatchOperation{
		Name:        fmt.Sprintf("批量%s", operation),
		Type:        "node",
		Description: fmt.Sprintf("批量执行节点%s操作", operation),
		Targets:     targets,
		Params:      params,
		Config: &OperationConfig{
			Concurrency: m.config.ConcurrencyConfig.PerOperationConcurrency,
			Timeout:     m.config.TimeoutConfig.GlobalTimeout,
			Retries:     m.config.RetryConfig.MaxRetries,
		},
		CreatedBy: "system",
	}

	return m.CreateOperation(batchOp)
}

// BatchDomainOperation 批量域名操作
func (m *BatchManager) BatchDomainOperation(operation string, domainIDs []string, params map[string]interface{}) error {
	targets := make([]*OperationTarget, len(domainIDs))

	for i, domainID := range domainIDs {
		targets[i] = &OperationTarget{
			ID:         domainID,
			Type:       "domain",
			Identifier: domainID,
		}
	}

	batchOp := &BatchOperation{
		Name:        fmt.Sprintf("批量%s", operation),
		Type:        "domain",
		Description: fmt.Sprintf("批量执行域名%s操作", operation),
		Targets:     targets,
		Params:      params,
		Config: &OperationConfig{
			Concurrency: m.config.ConcurrencyConfig.PerOperationConcurrency,
			Timeout:     m.config.TimeoutConfig.GlobalTimeout,
			Retries:     m.config.RetryConfig.MaxRetries,
		},
		CreatedBy: "system",
	}

	return m.CreateOperation(batchOp)
}

// ExportOperationResult 导出操作结果
func (m *BatchManager) ExportOperationResult(operationID string, format string) (string, error) {
	operation, err := m.GetOperation(operationID)
	if err != nil {
		return "", err
	}

	// 生成输出目录
	outputDir := filepath.Join("exports", "batch")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("创建导出目录失败: %w", err)
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("batch_%s_%s", operationID, timestamp)
	var outputPath string

	switch format {
	case "json":
		outputPath = filepath.Join(outputDir, filename+".json")
		err = m.exportToJSON(operation, outputPath)
	case "csv":
		outputPath = filepath.Join(outputDir, filename+".csv")
		err = m.exportToCSV(operation, outputPath)
	case "xml":
		outputPath = filepath.Join(outputDir, filename+".xml")
		err = m.exportToXML(operation, outputPath)
	case "txt":
		outputPath = filepath.Join(outputDir, filename+".txt")
		err = m.exportToTXT(operation, outputPath)
	default:
		outputPath = filepath.Join(outputDir, filename+".json")
		err = m.exportToJSON(operation, outputPath)
	}

	if err != nil {
		return "", fmt.Errorf("导出失败: %w", err)
	}

	return outputPath, nil
}

// exportToJSON 导出为JSON格式
func (m *BatchManager) exportToJSON(operation *BatchOperation, outputPath string) error {
	data := map[string]interface{}{
		"operation_id":   operation.ID,
		"operation_name": operation.Name,
		"type":           operation.Type,
		"status":         operation.Status,
		"created_at":     operation.CreatedAt,
		"started_at":     operation.StartedAt,
		"completed_at":   operation.CompletedAt,
		"progress": map[string]interface{}{
			"total_items":      operation.Progress.TotalItems,
			"processed_items":  operation.Progress.ProcessedItems,
			"success_items":    operation.Progress.SuccessItems,
			"failed_items":     operation.Progress.FailedItems,
			"skipped_items":    operation.Progress.SkippedItems,
			"percentage":       operation.Progress.Percentage,
			"items_per_second": operation.Progress.ItemsPerSecond,
		},
		"result": operation.Result,
		"errors": operation.Errors,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %w", err)
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}

// exportToCSV 导出为CSV格式
func (m *BatchManager) exportToCSV(operation *BatchOperation, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{
		"OperationID", "OperationName", "Type", "Status",
		"TotalItems", "ProcessedItems", "SuccessItems", "FailedItems", "SkippedItems",
		"Percentage", "CreatedAt", "StartedAt", "CompletedAt",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %w", err)
	}

	var formatTimePtr func(*time.Time) string
	formatTimePtr = func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format("2006-01-02 15:04:05")
	}

	row := []string{
		operation.ID, operation.Name, operation.Type, operation.Status,
		fmt.Sprintf("%d", operation.Progress.TotalItems),
		fmt.Sprintf("%d", operation.Progress.ProcessedItems),
		fmt.Sprintf("%d", operation.Progress.SuccessItems),
		fmt.Sprintf("%d", operation.Progress.FailedItems),
		fmt.Sprintf("%d", operation.Progress.SkippedItems),
		fmt.Sprintf("%.2f%%", operation.Progress.Percentage),
		formatTimePtr(&operation.CreatedAt),
		formatTimePtr(operation.StartedAt),
		formatTimePtr(operation.CompletedAt),
	}
	if err := writer.Write(row); err != nil {
		return fmt.Errorf("写入数据失败: %w", err)
	}

	if len(operation.Errors) > 0 {
		writer.Write([]string{})
		writer.Write([]string{"Error Details"})
		writer.Write([]string{"TargetID", "Code", "Message", "OccurredAt"})
		for _, err := range operation.Errors {
			row := []string{err.TargetID, err.Code, err.Message, err.OccurredAt.Format("2006-01-02 15:04:05")}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("写入错误详情失败: %w", err)
			}
		}
	}

	return nil
}

// exportToXML 导出为XML格式
func (m *BatchManager) exportToXML(operation *BatchOperation, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	type SerializableError struct {
		TargetID string `xml:"target_id"`
		Code     string `xml:"code"`
		Message  string `xml:"message"`
		Occurred string `xml:"occurred_at"`
	}

	type SerializableProgress struct {
		TotalItems     int     `xml:"total_items"`
		ProcessedItems int     `xml:"processed_items"`
		SuccessItems   int     `xml:"success_items"`
		FailedItems    int     `xml:"failed_items"`
		SkippedItems   int     `xml:"skipped_items"`
		Percentage     float64 `xml:"percentage"`
	}

	type SerializableOperation struct {
		ID          string               `xml:"id"`
		Name        string               `xml:"name"`
		Type        string               `xml:"type"`
		Status      string               `xml:"status"`
		Progress    SerializableProgress `xml:"progress"`
		CreatedAt   string               `xml:"created_at"`
		StartedAt   string               `xml:"started_at,omitempty"`
		CompletedAt string               `xml:"completed_at,omitempty"`
		Errors      []SerializableError  `xml:"errors>error"`
	}

	startedAt, completedAt := "", ""
	if operation.StartedAt != nil {
		startedAt = operation.StartedAt.Format("2006-01-02 15:04:05")
	}
	if operation.CompletedAt != nil {
		completedAt = operation.CompletedAt.Format("2006-01-02 15:04:05")
	}

	errors := make([]SerializableError, 0, len(operation.Errors))
	for _, err := range operation.Errors {
		errors = append(errors, SerializableError{
			TargetID: err.TargetID,
			Code:     err.Code,
			Message:  err.Message,
			Occurred: err.OccurredAt.Format("2006-01-02 15:04:05"),
		})
	}

	data := SerializableOperation{
		ID:     operation.ID,
		Name:   operation.Name,
		Type:   operation.Type,
		Status: operation.Status,
		Progress: SerializableProgress{
			TotalItems:     operation.Progress.TotalItems,
			ProcessedItems: operation.Progress.ProcessedItems,
			SuccessItems:   operation.Progress.SuccessItems,
			FailedItems:    operation.Progress.FailedItems,
			SkippedItems:   operation.Progress.SkippedItems,
			Percentage:     operation.Progress.Percentage,
		},
		CreatedAt:   operation.CreatedAt.Format("2006-01-02 15:04:05"),
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Errors:      errors,
	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("XML编码失败: %w", err)
	}

	return nil
}

// exportToTXT 导出为TXT格式
func (m *BatchManager) exportToTXT(operation *BatchOperation, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	var sb strings.Builder

	sb.WriteString("=================================================\n")
	sb.WriteString("           Batch Operation Export Report\n")
	sb.WriteString("=================================================\n\n")

	sb.WriteString(fmt.Sprintf("Operation ID:      %s\n", operation.ID))
	sb.WriteString(fmt.Sprintf("Operation Name:    %s\n", operation.Name))
	sb.WriteString(fmt.Sprintf("Type:              %s\n", operation.Type))
	sb.WriteString(fmt.Sprintf("Status:            %s\n", operation.Status))
	sb.WriteString(fmt.Sprintf("Created At:        %s\n", operation.CreatedAt.Format("2006-01-02 15:04:05")))

	if operation.StartedAt != nil {
		sb.WriteString(fmt.Sprintf("Started At:        %s\n", operation.StartedAt.Format("2006-01-02 15:04:05")))
	}
	if operation.CompletedAt != nil {
		sb.WriteString(fmt.Sprintf("Completed At:      %s\n", operation.CompletedAt.Format("2006-01-02 15:04:05")))
	}

	sb.WriteString("\n------------------- Progress -------------------\n")
	sb.WriteString(fmt.Sprintf("Total Items:       %d\n", operation.Progress.TotalItems))
	sb.WriteString(fmt.Sprintf("Processed Items:   %d\n", operation.Progress.ProcessedItems))
	sb.WriteString(fmt.Sprintf("Success Items:     %d\n", operation.Progress.SuccessItems))
	sb.WriteString(fmt.Sprintf("Failed Items:      %d\n", operation.Progress.FailedItems))
	sb.WriteString(fmt.Sprintf("Progress:          %.2f%%\n", operation.Progress.Percentage))

	if len(operation.Errors) > 0 {
		sb.WriteString("\n------------------- Errors -------------------\n")
		for i, err := range operation.Errors {
			sb.WriteString(fmt.Sprintf("[%d] %s - %s: %s\n", i+1, err.OccurredAt.Format("15:04:05"), err.TargetID, err.Message))
		}
	}

	sb.WriteString("\n=================================================\n")

	_, err = file.WriteString(sb.String())
	return err
}

// ExportAs 导出操作结果（别名方法）
func (m *BatchManager) ExportAs(operationID string, format string) (string, error) {
	return m.ExportOperationResult(operationID, format)
}

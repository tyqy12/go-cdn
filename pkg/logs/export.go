package logs

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogExporter 日志导出服务
type LogExporter struct {
	config     *ExportConfig
	processors []ExportProcessor
	storage    LogStorage
	mu         sync.RWMutex
	stats      *ExportStats
	ctx        context.Context
	cancel     context.CancelFunc
}

// ExportConfig 导出配置
type ExportConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 日志目录
	LogDir string `yaml:"log_dir"`

	// 导出格式
	Format string `yaml:"format"` // "json", "csv", "tsv", "ltsv"

	// 导出压缩
	Compress bool `yaml:"compress"`

	// 压缩格式
	CompressType string `yaml:"compress_type"` // "gzip", "zip"

	// 分片大小
	ChunkSize int64 `yaml:"chunk_size"` // 单位: bytes, 默认100MB

	// 保留时间
	Retention time.Duration `yaml:"retention"`

	// 最大导出数量
	MaxExportCount int `yaml:"max_export_count"`

	// 导出队列
	ExportQueue int `yaml:"export_queue"`

	// 实时日志
	RealtimeConfig RealtimeConfig `yaml:"realtime_config"`
}

// RealtimeConfig 实时日志配置
type RealtimeConfig struct {
	// 启用实时日志
	Enabled bool `yaml:"enabled"`

	// WebSocket端口
	WSAddr string `yaml:"ws_addr"`

	// 最大连接数
	MaxConnections int `yaml:"max_connections"`

	// 批量推送间隔
	BatchInterval time.Duration `yaml:"batch_interval"`

	// 批量推送数量
	BatchSize int `yaml:"batch_size"`
}

// ExportProcessor 日志处理器
type ExportProcessor interface {
	Process(log *AccessLog) error
	Flush() error
	Close() error
}

// LogStorage 日志存储接口
type LogStorage interface {
	Store(logs []*AccessLog) error
	Query(query *LogQuery) ([]*AccessLog, error)
	Delete(before time.Time) error
	GetStats() (*StorageStats, error)
}

// AccessLog 访问日志
type AccessLog struct {
	// 基础信息
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id"`
	TraceID   string    `json:"trace_id"`

	// 客户端信息
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent"`
	Referer   string `json:"referer"`
	Country   string `json:"country"`
	Region    string `json:"region"`
	City      string `json:"city"`
	ISP       string `json:"isp"`

	// 请求信息
	Method   string `json:"method"`
	URL      string `json:"url"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Protocol string `json:"protocol"`

	// 响应信息
	StatusCode    int    `json:"status_code"`
	ContentType   string `json:"content_type"`
	ContentLength int64  `json:"content_length"`

	// 性能信息
	Latency      time.Duration `json:"latency"`
	UpstreamTime time.Duration `json:"upstream_time"`
	TransferTime time.Duration `json:"transfer_time"`

	// 缓存信息
	CacheStatus string `json:"cache_status"`
	CacheHit    bool   `json:"cache_hit"`

	// 错误信息
	ErrorMessage string `json:"error_message"`
	ErrorCode    string `json:"error_code"`

	// 节点信息
	NodeID     string `json:"node_id"`
	NodeRegion string `json:"node_region"`

	// 用户信息
	UserID string `json:"user_id"`
	PlanID string `json:"plan_id"`

	// 其他信息
	Headers  map[string]string      `json:"headers"`
	Metadata map[string]interface{} `json:"metadata"`
}

// LogQuery 日志查询
type LogQuery struct {
	// 时间范围
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// 筛选条件
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Method     string `json:"method"`
	NodeID     string `json:"node_id"`
	UserID     string `json:"user_id"`

	// 过滤规则
	Filters []*FilterRule `json:"filters"`

	// 分页
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Limit    int `json:"limit"`

	// 排序
	SortBy    string `json:"sort_by"`    // "timestamp", "latency", "status_code"
	SortOrder string `json:"sort_order"` // "asc", "desc"
}

// ExportStats 导出统计
type ExportStats struct {
	TotalLogs        int64 `json:"total_logs"`
	ExportedLogs     int64 `json:"exported_logs"`
	ExportedSize     int64 `json:"exported_size"`
	ExportCount      int64 `json:"export_count"`
	FailedExports    int64 `json:"failed_exports"`
	StorageUsed      int64 `json:"storage_used"`
	RealtimeSessions int   `json:"realtime_sessions"`
	mu               sync.RWMutex
}

// StorageStats 存储统计
type StorageStats struct {
	TotalLogs int64     `json:"total_logs"`
	TotalSize int64     `json:"total_size"`
	OldestLog time.Time `json:"oldest_log"`
	NewestLog time.Time `json:"newest_log"`
	IndexSize int64     `json:"index_size"`
}

// CSVProcessor CSV日志处理器
type CSVProcessor struct {
	writer   *csv.Writer
	file     *os.File
	filename string
	mu       sync.Mutex
}

// JSONProcessor JSON日志处理器
type JSONProcessor struct {
	buffer   bytes.Buffer
	filename string
	file     *os.File
	mu       sync.Mutex
}

// NewLogExporter 创建日志导出服务
func NewLogExporter(config *ExportConfig) *LogExporter {
	if config == nil {
		config = &ExportConfig{
			Enabled:   true,
			LogDir:    "/var/log/cdn",
			Format:    "json",
			Compress:  true,
			ChunkSize: 100 * 1024 * 1024,  // 100MB
			Retention: 7 * 24 * time.Hour, // 7天
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &LogExporter{
		config:     config,
		processors: make([]ExportProcessor, 0),
		ctx:        ctx,
		cancel:     cancel,
		stats:      &ExportStats{},
	}
}

// Start 启动日志导出服务
func (e *LogExporter) Start() error {
	// 创建日志目录
	if err := os.MkdirAll(e.config.LogDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}

	// 启动定期清理
	go e.cleanupExpiredLogs()

	return nil
}

// ProcessLog 处理日志
func (e *LogExporter) ProcessLog(log *AccessLog) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 更新统计
	e.stats.mu.Lock()
	e.stats.TotalLogs++
	e.stats.mu.Unlock()

	// 处理日志
	for _, processor := range e.processors {
		if err := processor.Process(log); err != nil {
			return err
		}
	}

	return nil
}

// Export 导出日志
func (e *LogExporter) Export(query *LogQuery) (*ExportResult, error) {
	e.stats.mu.Lock()
	e.stats.ExportCount++
	e.stats.mu.Unlock()

	result := &ExportResult{
		ID:        generateExportID(),
		CreatedAt: time.Now(),
		Status:    "processing",
	}

	// 异步执行导出
	go func() {
		err := e.performExport(query, result)
		if err != nil {
			result.Status = "failed"
			result.Error = err.Error()

			e.stats.mu.Lock()
			e.stats.FailedExports++
			e.stats.mu.Unlock()
		} else {
			result.Status = "completed"

			e.stats.mu.Lock()
			e.stats.ExportedLogs += result.LogCount
			e.stats.ExportedSize += result.FileSize
			e.stats.mu.Unlock()
		}
	}()

	return result, nil
}

// performExport 执行导出
func (e *LogExporter) performExport(query *LogQuery, result *ExportResult) error {
	// 从存储查询日志
	logs, err := e.storage.Query(query)
	if err != nil {
		return err
	}

	result.LogCount = int64(len(logs))

	if len(logs) == 0 {
		result.Status = "completed"
		result.FileSize = 0
		return nil
	}

	// 创建导出文件
	filename := fmt.Sprintf("cdn_logs_%s_%s.%s",
		query.StartTime.Format("20060102"),
		query.EndTime.Format("20060102"),
		e.config.Format,
	)

	filePath := filepath.Join(e.config.LogDir, filename)

	// 根据格式导出
	switch e.config.Format {
	case "csv":
		err = e.exportToCSV(filePath, logs)
	case "json":
		err = e.exportToJSON(filePath, logs)
	default:
		err = e.exportToJSON(filePath, logs)
	}

	if err != nil {
		return err
	}

	// 压缩文件
	if e.config.Compress {
		compressedPath := filePath + "." + e.config.CompressType
		err = e.compressFile(filePath, compressedPath)
		if err != nil {
			return err
		}
		// 删除原始文件
		os.Remove(filePath)
		filePath = compressedPath
	}

	// 获取文件大小
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	result.FilePath = filePath
	result.FileName = filepath.Base(filePath)
	result.FileSize = fileInfo.Size()
	result.DownloadURL = fmt.Sprintf("/api/v1/logs/download/%s", result.ID)

	return nil
}

// exportToCSV 导出为CSV
func (e *LogExporter) exportToCSV(filePath string, logs []*AccessLog) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{
		"timestamp", "request_id", "client_ip", "method", "url", "status_code",
		"latency", "content_length", "cache_status", "user_agent", "referer",
		"country", "region", "city", "isp", "node_id",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 写入数据
	for _, log := range logs {
		record := []string{
			log.Timestamp.Format(time.RFC3339),
			log.RequestID,
			log.ClientIP,
			log.Method,
			log.URL,
			fmt.Sprintf("%d", log.StatusCode),
			fmt.Sprintf("%d", log.Latency.Milliseconds()),
			fmt.Sprintf("%d", log.ContentLength),
			log.CacheStatus,
			log.UserAgent,
			log.Referer,
			log.Country,
			log.Region,
			log.City,
			log.ISP,
			log.NodeID,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// exportToJSON 导出为JSON
func (e *LogExporter) exportToJSON(filePath string, logs []*AccessLog) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(logs)
}

// compressFile 压缩文件
func (e *LogExporter) compressFile(srcPath, dstPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	var writer io.Writer
	switch e.config.CompressType {
	case "gzip":
		writer = gzip.NewWriter(dstFile)
	case "zip":
		return e.compressToZIP(srcPath, dstPath)
	default:
		writer = dstFile
	}

	_, err = io.Copy(writer, srcFile)
	if err != nil {
		return err
	}

	// 关闭writer
	if closer, ok := writer.(io.Closer); ok {
		closer.Close()
	}

	return nil
}

// cleanupExpiredLogs 清理过期日志
func (e *LogExporter) cleanupExpiredLogs() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.storage.Delete(time.Now().Add(-e.config.Retention))
		}
	}
}

// ExportResult 导出结果
type ExportResult struct {
	ID          string    `json:"id"`
	FilePath    string    `json:"file_path"`
	FileName    string    `json:"file_name"`
	FileSize    int64     `json:"file_size"`
	LogCount    int64     `json:"log_count"`
	DownloadURL string    `json:"download_url"`
	Status      string    `json:"status"` // "processing", "completed", "failed"
	Error       string    `json:"error"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiredAt   time.Time `json:"expired_at"`
}

// generateExportID 生成导出ID
func generateExportID() string {
	return fmt.Sprintf("exp_%d_%s", time.Now().UnixNano(), randomString(8))
}

// randomString 生成随机字符串
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// GetStats 获取统计
func (e *LogExporter) GetStats() *ExportStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	return e.stats
}

// compressToZIP 压缩为ZIP
func (e *LogExporter) compressToZIP(srcPath, dstPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	zipWriter := zip.NewWriter(dstFile)
	defer zipWriter.Close()

	writer, err := zipWriter.Create(filepath.Base(srcPath))
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, srcFile)
	return err
}

// DownloadExport 下载导出文件
func (e *LogExporter) DownloadExport(exportID string) (*os.File, error) {
	// 在日志目录中查找对应的导出文件
	entries, err := os.ReadDir(e.config.LogDir)
	if err != nil {
		return nil, fmt.Errorf("读取日志目录失败: %w", err)
	}

	// 构建可能的前缀
	prefix := fmt.Sprintf("cdn_logs_%s", exportID)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, prefix) || strings.Contains(name, exportID) {
			filePath := filepath.Join(e.config.LogDir, name)
			return os.Open(filePath)
		}
	}

	return nil, fmt.Errorf("导出文件不存在: %s", exportID)
}

// ExportRecord 导出记录
type ExportRecord struct {
	ID        string    `json:"id"`
	FileName  string    `json:"file_name"`
	FileSize  int64     `json:"file_size"`
	LogCount  int64     `json:"log_count"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

// ListExports 列出导出记录
func (e *LogExporter) ListExports(page, pageSize int) ([]*ExportRecord, int64) {
	entries, err := os.ReadDir(e.config.LogDir)
	if err != nil {
		return make([]*ExportRecord, 0), 0
	}

	var records []*ExportRecord
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// 只处理日志导出文件
		name := entry.Name()
		if !strings.HasPrefix(name, "cdn_logs_") {
			continue
		}

		info, _ := entry.Info()
		rec := &ExportRecord{
			FileName:  name,
			FileSize:  info.Size(),
			CreatedAt: info.ModTime(),
		}
		// 解析导出ID
		if strings.Contains(name, "exp_") {
			idx := strings.Index(name, "exp_")
			if idx >= 0 {
				rec.ID = name[idx:]
			}
		}
		rec.ExpiredAt = rec.CreatedAt.Add(e.config.Retention)
		rec.Status = "completed"

		records = append(records, rec)
	}

	// 按时间排序
	sort.Slice(records, func(i, j int) bool {
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})

	// 计算总数
	total := int64(len(records))

	// 分页
	if pageSize <= 0 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start > len(records) {
		return make([]*ExportRecord, 0), total
	}
	end := start + pageSize
	if end > len(records) {
		end = len(records)
	}

	if start >= end {
		return make([]*ExportRecord, 0), total
	}

	return records[start:end], total
}

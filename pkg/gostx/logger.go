package gostx

import (
	"sync"

	"github.com/go-gost/core/logger"
)

// CDNLoggerAdapter gost Logger 接口适配 CDN 日志系统
type CDNLoggerAdapter struct {
	mu       sync.Mutex
	prefix   string
	level    logger.LogLevel
	output   LoggerOutput
	fields   map[string]any
}

// LoggerOutput 日志输出接口
type LoggerOutput interface {
	Write(level logger.LogLevel, format string, args ...interface{})
}

// ConsoleOutput 控制台输出
type ConsoleOutput struct{}

func (o *ConsoleOutput) Write(level logger.LogLevel, format string, args ...interface{}) {
	// 使用标准日志输出
	levelStr := [...]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}[levelIndex(level)]
	println("[" + levelStr + "] " + format)
}

// levelIndex 将 LogLevel 转换为索引
func levelIndex(level logger.LogLevel) int {
	switch level {
	case logger.TraceLevel:
		return 0
	case logger.DebugLevel:
		return 1
	case logger.InfoLevel:
		return 2
	case logger.WarnLevel:
		return 3
	case logger.ErrorLevel:
		return 4
	case logger.FatalLevel:
		return 5
	default:
		return 2
	}
}

// FileOutput 文件输出 (预留)
type FileOutput struct {
	path string
}

func NewFileOutput(path string) *FileOutput {
	return &FileOutput{path: path}
}

func (o *FileOutput) Write(level logger.LogLevel, format string, args ...interface{}) {
	// 预留：文件输出实现
}

// NewCDNLoggerAdapter 创建日志适配器
func NewCDNLoggerAdapter() *CDNLoggerAdapter {
	return &CDNLoggerAdapter{
		output: &ConsoleOutput{},
		level:  logger.InfoLevel,
		fields: make(map[string]any),
	}
}

// WithFields 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) WithFields(fields map[string]any) logger.Logger {
	newAdapter := &CDNLoggerAdapter{
		prefix:   l.prefix,
		level:    l.level,
		output:   l.output,
		fields:   make(map[string]any),
	}
	for k, v := range l.fields {
		newAdapter.fields[k] = v
	}
	for k, v := range fields {
		newAdapter.fields[k] = v
	}
	return newAdapter
}

// Trace 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Trace(args ...interface{}) {
	l.log(logger.TraceLevel, formatMessage(args...), args...)
}

// Tracef 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Tracef(format string, args ...interface{}) {
	l.log(logger.TraceLevel, format, args...)
}

// Debug 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Debug(args ...interface{}) {
	l.log(logger.DebugLevel, formatMessage(args...), args...)
}

// Debugf 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Debugf(format string, args ...interface{}) {
	l.log(logger.DebugLevel, format, args...)
}

// Info 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Info(args ...interface{}) {
	l.log(logger.InfoLevel, formatMessage(args...), args...)
}

// Infof 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Infof(format string, args ...interface{}) {
	l.log(logger.InfoLevel, format, args...)
}

// Warn 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Warn(args ...interface{}) {
	l.log(logger.WarnLevel, formatMessage(args...), args...)
}

// Warnf 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Warnf(format string, args ...interface{}) {
	l.log(logger.WarnLevel, format, args...)
}

// Error 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Error(args ...interface{}) {
	l.log(logger.ErrorLevel, formatMessage(args...), args...)
}

// Errorf 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Errorf(format string, args ...interface{}) {
	l.log(logger.ErrorLevel, format, args...)
}

// Fatal 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Fatal(args ...interface{}) {
	l.log(logger.FatalLevel, formatMessage(args...), args...)
}

// Fatalf 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) Fatalf(format string, args ...interface{}) {
	l.log(logger.FatalLevel, format, args...)
}

// GetLevel 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) GetLevel() logger.LogLevel {
	return l.level
}

// IsLevelEnabled 实现 logger.Logger 接口
func (l *CDNLoggerAdapter) IsLevelEnabled(level logger.LogLevel) bool {
	return level >= l.level
}

// log 内部日志方法
func (l *CDNLoggerAdapter) log(level logger.LogLevel, msg string, args ...interface{}) {
	if !l.IsLevelEnabled(level) {
		return
	}
	l.output.Write(level, msg, args...)
}

// formatMessage 格式化消息
func formatMessage(args ...interface{}) string {
	if len(args) == 0 {
		return ""
	}
	if len(args) == 1 {
		if s, ok := args[0].(string); ok {
			return s
		}
	}
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		result += toString(arg)
	}
	return result
}

// toString 转换为字符串
func toString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	case fmtStringer:
		return x.String()
	default:
		return sprintf("%v", x)
	}
}

type fmtStringer interface {
	String() string
}

func sprintf(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return format + " " + toString(args[0])
}

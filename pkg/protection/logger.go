package protection

import (
	"fmt"
)

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ConsoleLogger 控制台日志实现
type ConsoleLogger struct{}

func NewConsoleLogger() *ConsoleLogger {
	return &ConsoleLogger{}
}

func (l *ConsoleLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

func (l *ConsoleLogger) Infof(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (l *ConsoleLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (l *ConsoleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}

// NullLogger 空日志实现
type NullLogger struct{}

func NewNullLogger() *NullLogger {
	return &NullLogger{}
}

func (l *NullLogger) Debugf(format string, args ...interface{}) {}
func (l *NullLogger) Infof(format string, args ...interface{})  {}
func (l *NullLogger) Warnf(format string, args ...interface{})  {}
func (l *NullLogger) Errorf(format string, args ...interface{}) {}

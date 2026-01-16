package tunnel

import (
	"sync/atomic"
	"time"
)

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// TunnelConfig 隧道配置
type TunnelConfig struct {
	Name       string
	ListenAddr string
	ListenPort int
	Protocol   string

	ForwardAddr string
	ForwardPort int

	ForwardConfig *ForwardConfig

	HealthCheck *HealthCheckConfig

	MaxConnections int
	IdleTimeout    time.Duration
	BufferSize     int
}

// ForwardConfig 转发配置
type ForwardConfig struct {
	DialTimeout   time.Duration
	KeepAlive     bool
	KeepAliveIdle time.Duration
	KeepAliveIntv time.Duration
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Enabled       bool
	Interval      time.Duration
	Timeout       time.Duration
	Unhealthy     int
	HealthyThresh int
}

// TunnelMetrics 隧道实时指标
type TunnelMetrics struct {
	ConnectionCount  atomic.Int64
	BytesTransferred atomic.Uint64
	RequestCount     atomic.Uint64
	ErrorCount       atomic.Uint64
	LatencySum       atomic.Int64
	LatencyCount     atomic.Int64
	HealthScore      atomic.Int64
}

// TunnelStats 隧道统计信息
type TunnelStats struct {
	ID               string
	Name             string
	Status           TunnelState
	ConnectionCount  int64
	BytesTransferred uint64
	RequestCount     uint64
	ErrorCount       uint64
	LatencyP50       time.Duration
	LatencyP99       time.Duration
	HealthScore      float64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PoolStats 连接池统计
type PoolStats struct {
	MaxConns       int
	ActiveConns    int
	TotalConns     int64
	AvailableConns int
}

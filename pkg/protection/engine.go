package protection

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ProtectionEngine 连接保护引擎
type ProtectionEngine struct {
	config           *ProtectionConfig
	globalLimiter    *RateLimiter
	clientLimiters   *sync.Map
	slowConnDetector *SlowConnectionDetector
	resourceMonitor  *ResourceMonitor

	logger Logger

	stats *ProtectionStats
}

// ProtectionConfig 保护配置
type ProtectionConfig struct {
	GlobalMaxConnections int
	GlobalMaxConnRate    int

	PerClientMaxConnections int
	PerClientMaxRate        int

	SlowConnectionThreshold time.Duration
	SlowReadThreshold       time.Duration
	SlowWriteThreshold      time.Duration

	MaxHeaderSize      int64
	MaxHeadersCount    int
	MaxRequestBodySize int64

	ResourceMonitorInterval time.Duration
}

// ProtectionStats 保护统计
type ProtectionStats struct {
	TotalConnections     atomic.Int64
	ProtectedConnections atomic.Int64
	BlockedConnections   atomic.Int64
	SlowConnections      atomic.Int64
	LargeConnections     atomic.Int64
	HeaderViolations     atomic.Int64
}

// NewProtectionEngine 创建保护引擎
func NewProtectionEngine(config *ProtectionConfig, logger Logger) *ProtectionEngine {
	if config == nil {
		config = &ProtectionConfig{
			GlobalMaxConnections:    100000,
			GlobalMaxConnRate:       10000,
			PerClientMaxConnections: 100,
			PerClientMaxRate:        100,
			SlowConnectionThreshold: 5 * time.Second,
			SlowReadThreshold:       10 * time.Second,
			SlowWriteThreshold:      10 * time.Second,
			MaxHeaderSize:           8192,
			MaxHeadersCount:         100,
			MaxRequestBodySize:      10485760, // 10MB
			ResourceMonitorInterval: 1 * time.Second,
		}
	}

	if logger == nil {
		logger = NewConsoleLogger()
	}

	pe := &ProtectionEngine{
		config:           config,
		globalLimiter:    NewRateLimiter(config.GlobalMaxConnRate, 1*time.Second),
		clientLimiters:   &sync.Map{},
		slowConnDetector: NewSlowConnectionDetector(config.SlowConnectionThreshold),
		resourceMonitor:  NewResourceMonitor(),
		logger:           logger,
		stats:            &ProtectionStats{},
	}

	return pe
}

// ProtectConnection 保护连接
func (pe *ProtectionEngine) ProtectConnection(conn net.Conn) (net.Conn, error) {
	clientIP := getClientIP(conn)

	if !pe.globalLimiter.Allow() {
		pe.stats.BlockedConnections.Add(1)
		pe.logger.Warnf("global connection limit exceeded, blocking %s", clientIP)
		return nil, fmt.Errorf("global connection rate limit exceeded")
	}

	clientLimiter, _ := pe.getClientLimiter(clientIP)
	if !clientLimiter.Allow() {
		pe.stats.BlockedConnections.Add(1)
		pe.logger.Warnf("client %s connection rate limit exceeded", clientIP)
		return nil, fmt.Errorf("client connection rate limit exceeded")
	}

	pe.stats.TotalConnections.Add(1)

	protectedConn := &ProtectedConnection{
		conn:             conn,
		protectionEngine: pe,
		startTime:        time.Now(),
		bytesRead:        0,
		bytesWritten:     0,
		clientIP:         clientIP,
	}

	pe.logger.Debugf("connection %s protected", clientIP)

	return protectedConn, nil
}

// getClientLimiter 获取客户端限流器
func (pe *ProtectionEngine) getClientLimiter(clientIP string) (*RateLimiter, bool) {
	limiter, ok := pe.clientLimiters.Load(clientIP)
	if !ok {
		newLimiter := NewRateLimiter(pe.config.PerClientMaxRate, 1*time.Second)
		limiter, _ = pe.clientLimiters.LoadOrStore(clientIP, newLimiter)
	}
	return limiter.(*RateLimiter), ok
}

// RemoveClientLimiter 移除客户端限流器
func (pe *ProtectionEngine) RemoveClientLimiter(clientIP string) {
	pe.clientLimiters.Delete(clientIP)
}

// GetStats 获取统计信息
func (pe *ProtectionEngine) GetStats() *ProtectionStats {
	return &ProtectionStats{
		TotalConnections:     atomic.Int64(pe.stats.TotalConnections),
		ProtectedConnections: atomic.Int64(pe.stats.ProtectedConnections),
		BlockedConnections:   atomic.Int64(pe.stats.BlockedConnections),
		SlowConnections:      atomic.Int64(pe.stats.SlowConnections),
		LargeConnections:     atomic.Int64(pe.stats.LargeConnections),
		HeaderViolations:     atomic.Int64(pe.stats.HeaderViolations),
	}
}

// Start 启动保护引擎
func (pe *ProtectionEngine) Start(ctx context.Context) error {
	go pe.resourceMonitor.Run(ctx, pe.config.ResourceMonitorInterval)

	pe.logger.Infof("protection engine started: max_conn=%d, max_rate=%d",
		pe.config.GlobalMaxConnections, pe.config.GlobalMaxConnRate)

	return nil
}

// Stop 停止保护引擎
func (pe *ProtectionEngine) Stop() {
	pe.logger.Infof("protection engine stopped")
}

// ProtectedConnection 受保护的连接
type ProtectedConnection struct {
	conn             net.Conn
	protectionEngine *ProtectionEngine
	startTime        time.Time
	bytesRead        int64
	bytesWritten     int64
	mu               sync.Mutex
	clientIP         string
	closed           bool
}

func (pc *ProtectedConnection) Read(b []byte) (n int, err error) {
	if pc.closed {
		return 0, net.ErrClosed
	}

	start := time.Now()
	n, err = pc.conn.Read(b)

	pc.mu.Lock()
	pc.bytesRead += int64(n)
	elapsed := time.Since(start)
	pc.mu.Unlock()

	if err != nil {
		return n, err
	}

	if elapsed > pc.protectionEngine.config.SlowReadThreshold {
		pc.protectionEngine.stats.SlowConnections.Add(1)
		pc.protectionEngine.logger.Debugf("slow read detected for %s: %v", pc.clientIP, elapsed)
	}

	return n, nil
}

func (pc *ProtectedConnection) Write(b []byte) (n int, err error) {
	if pc.closed {
		return 0, net.ErrClosed
	}

	if int64(len(b)) > pc.protectionEngine.config.MaxRequestBodySize {
		pc.protectionEngine.stats.LargeConnections.Add(1)
		pc.protectionEngine.logger.Warnf("large write detected for %s: %d bytes", pc.clientIP, len(b))
		return 0, fmt.Errorf("request body too large")
	}

	start := time.Now()
	n, err = pc.conn.Write(b)

	pc.mu.Lock()
	pc.bytesWritten += int64(n)
	elapsed := time.Since(start)
	pc.mu.Unlock()

	if err != nil {
		return n, err
	}

	if elapsed > pc.protectionEngine.config.SlowWriteThreshold {
		pc.protectionEngine.stats.SlowConnections.Add(1)
		pc.protectionEngine.logger.Debugf("slow write detected for %s: %v", pc.clientIP, elapsed)
	}

	return n, nil
}

func (pc *ProtectedConnection) Close() error {
	if pc.closed {
		return nil
	}

	pc.closed = true
	err := pc.conn.Close()

	duration := time.Since(pc.startTime)
	if duration > pc.protectionEngine.config.SlowConnectionThreshold {
		pc.protectionEngine.stats.SlowConnections.Add(1)
		pc.protectionEngine.logger.Debugf("slow connection detected for %s: %v", pc.clientIP, duration)
	}

	pc.protectionEngine.RemoveClientLimiter(pc.clientIP)

	return err
}

func (pc *ProtectedConnection) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

func (pc *ProtectedConnection) RemoteAddr() net.Addr {
	return pc.conn.RemoteAddr()
}

func (pc *ProtectedConnection) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

func (pc *ProtectedConnection) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

func (pc *ProtectedConnection) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}

func getClientIP(conn net.Conn) string {
	addr := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

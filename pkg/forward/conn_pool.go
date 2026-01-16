package forward

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/logger"
)

// ConnPool 连接池
type ConnPool struct {
	mu           sync.RWMutex
	connPools        map[string]*connPool
	maxIdleConns int
	maxConnsPer  int
	idleTimeout  time.Duration
	logger       logger.Logger
}

// connPool 连接池实例
type connPool struct {
	mu          sync.RWMutex
	addr        string
	conns       chan net.Conn
	active      int64
	maxIdle     int
	maxTotal    int
	idleTimeout time.Duration
	logger      logger.Logger
}

// PoolConfig 连接池配置
type PoolConfig struct {
	MaxIdleConns    int
	MaxConnsPerAddr int
	IdleTimeout     time.Duration
}

// NewConnPool 创建连接池
func NewConnPool(opts ...ConnPoolOption) *ConnPool {
	p := &ConnPool{
		connPools:        make(map[string]*connPool),
		maxIdleConns: 100,
		maxConnsPer:  1000,
		idleTimeout:  90 * time.Second,
		logger:       logger.Default(),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// ConnPoolOption 连接池选项
type ConnPoolOption func(*ConnPool)

// WithConnPoolMaxIdleConns 设置最大空闲连接数
func WithConnPoolMaxIdleConns(n int) ConnPoolOption {
	return func(p *ConnPool) {
		p.maxIdleConns = n
	}
}

// WithConnPoolMaxConnsPer 设置每地址最大连接数
func WithConnPoolMaxConnsPer(n int) ConnPoolOption {
	return func(p *ConnPool) {
		p.maxConnsPer = n
	}
}

// WithConnPoolIdleTimeout 设置空闲超时
func WithConnPoolIdleTimeout(d time.Duration) ConnPoolOption {
	return func(p *ConnPool) {
		p.idleTimeout = d
	}
}

// WithConnPoolLogger 设置日志
func WithConnPoolLogger(l logger.Logger) ConnPoolOption {
	return func(p *ConnPool) {
		p.logger = l
	}
}

// Get 获取连接
func (p *ConnPool) Get(ctx context.Context, network, addr string) (net.Conn, error) {
	p.mu.RLock()
	pool, ok := p.connPools[addr]
	p.mu.RUnlock()

	if !ok {
		// 创建新连接池
		p.mu.Lock()
		if pool, ok = p.connPools[addr]; !ok {
			pool = &connPool{
				addr:        addr,
				conns:       make(chan net.Conn, p.maxIdleConns),
				maxIdle:     p.maxIdleConns,
				maxTotal:    p.maxConnsPer,
				idleTimeout: p.idleTimeout,
				logger:      p.logger,
			}
			p.connPools[addr] = pool
		}
		p.mu.Unlock()
	}

	return pool.Get(ctx, network)
}

// Put 放回连接
func (p *ConnPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	addr := conn.RemoteAddr().String()
	p.mu.RLock()
	pool, ok := p.connPools[addr]
	p.mu.RUnlock()

	if ok {
		pool.Put(conn)
	} else {
		conn.Close()
	}
}

// Close 关闭连接池
func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pool := range p.connPools {
		pool.Close()
	}
	p.connPools = make(map[string]*connPool)
}

// Stats 获取统计信息
func (p *ConnPool) Stats() ConnPoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := ConnPoolStats{
		Pools: make([]PoolStats, 0, len(p.connPools)),
	}

	for _, pool := range p.connPools {
		ps := pool.Stats()
		stats.Pools = append(stats.Pools, ps)
		stats.TotalIdle += int(ps.Idle)
		stats.TotalActive += int(ps.Active)
	}

	return stats
}

// PoolStats 连接池统计
type PoolStats struct {
	Addr    string
	Idle    int64
	Active  int64
	Waiters int64
}

// ConnPoolStats 连接池总体统计
type ConnPoolStats struct {
	TotalIdle   int
	TotalActive int
	Pools       []PoolStats
}

// Get 获取连接
func (p *connPool) Get(ctx context.Context, network string) (net.Conn, error) {
	// 尝试从空闲连接中获取
	select {
	case conn := <-p.conns:
		if conn == nil {
			return nil, ErrPoolClosed
		}
		// 检查连接是否过期
		if !p.isIdleConnValid(conn) {
			conn.Close()
			return p.Get(ctx, network)
		}
		atomic.AddInt64(&p.active, 1)
		return conn, nil
	default:
		// 没有空闲连接，创建新连接
	}

	// 检查是否达到最大连接数
	if atomic.LoadInt64(&p.active) >= int64(p.maxTotal) {
		// 等待空闲连接
		select {
		case conn := <-p.conns:
			if conn == nil {
				return nil, ErrPoolClosed
			}
			atomic.AddInt64(&p.active, 1)
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 创建新连接
	conn, err := net.DialTimeout(network, p.addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&p.active, 1)
	return &connPoolConn{
		Conn:   conn,
		connPool:   p,
		closed: atomic.Bool{},
	}, nil
}

// Put 放回连接
func (p *connPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conns == nil {
		conn.Close()
		return
	}

	select {
	case p.conns <- conn:
		atomic.AddInt64(&p.active, -1)
	default:
		// 空闲池已满，关闭连接
		conn.Close()
		atomic.AddInt64(&p.active, -1)
	}
}

// Close 关闭连接池
func (p *connPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conns == nil {
		return
	}

	close(p.conns)
	for conn := range p.conns {
		conn.Close()
		atomic.AddInt64(&p.active, -1)
	}

	p.conns = nil
}

// Stats 获取统计信息
func (p *connPool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return PoolStats{
		Addr:    p.addr,
		Idle:    int64(len(p.conns)),
		Active:  atomic.LoadInt64(&p.active),
		Waiters: 0,
	}
}

// isIdleConnValid 检查空闲连接是否有效
func (p *connPool) isIdleConnValid(conn net.Conn) bool {
	// 检查连接是否已关闭
	if conn == nil {
		return false
	}

	// 检查连接是否过期
	if p.idleTimeout > 0 {
		// 这里可以检查连接的最后使用时间
		// 简化处理，通过读写测试
		conn.SetReadDeadline(time.Now())
		b := make([]byte, 1)
		_, err := conn.Read(b)
		if err != nil {
			return false
		}
	}

	return true
}

// connPoolConn 连接包装器
type connPoolConn struct {
	net.Conn
	connPool   *connPool
	closed atomic.Bool
}

// Close 关闭连接
func (c *connPoolConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.connPool.Put(c.Conn)
	}
	return nil
}

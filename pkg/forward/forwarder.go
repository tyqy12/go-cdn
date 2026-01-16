package forward

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Forwarder 转发器
type Forwarder struct {
	config       *ForwardConfig
	connPool     *ConnPool
	loadBalancer *LoadBalancer
	clusters     map[string]*Cluster
	stopChan     chan struct{}
	wg           sync.WaitGroup
	logger       Logger
}

// ForwardConfig 转发配置
type ForwardConfig struct {
	// 基本配置
	ListenAddr  string
	ListenPort  int
	Mode        string // http, https, tcp

	// 集群配置
	ClusterName   string
	UpstreamAddrs []string
	UpstreamPort  int
	PathPrefix    string

	// 负载均衡配置
	LBStrategy string
	Sticky     bool
	StickyMode string // cookie, ip_hash

	// 连接池配置
	MaxIdleConns    int
	MaxConnsPerAddr int
	IdleTimeout     time.Duration

	// 健康检查配置
	HealthCheckEnabled   bool
	HealthCheckInterval  time.Duration
	HealthCheckTimeout   time.Duration
	HealthCheckUnhealthy int
	HealthCheckHealthy   int

	// TLS 配置
	TLSCertFile string
	TLSKeyFile  string
	TLSAutoGen  bool
	TLSDomain   string
}

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ConsoleLogger 控制台日志实现
type ConsoleLogger struct{}

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

// ForwarderOption 转发器选项
type ForwarderOption func(*Forwarder)

// WithForwarderLogger 设置日志
func WithForwarderLogger(l Logger) ForwarderOption {
	return func(f *Forwarder) {
		f.logger = l
	}
}

// WithForwarderConnPool 设置连接池
func WithForwarderConnPool(pool *ConnPool) ForwarderOption {
	return func(f *Forwarder) {
		f.connPool = pool
	}
}

// WithForwarderLoadBalancer 设置负载均衡器
func WithForwarderLoadBalancer(lb *LoadBalancer) ForwarderOption {
	return func(f *Forwarder) {
		f.loadBalancer = lb
	}
}

// NewForwarder 创建转发器
func NewForwarder(opts ...ForwarderOption) *Forwarder {
	f := &Forwarder{
		config:    &ForwardConfig{},
		clusters:  make(map[string]*Cluster),
		stopChan:  make(chan struct{}),
		logger:    &ConsoleLogger{},
	}

	for _, opt := range opts {
		opt(f)
	}

	// 如果没有提供连接池，创建默认连接池
	if f.connPool == nil {
		f.connPool = NewConnPool()
	}

	// 如果没有提供负载均衡器，创建默认负载均衡器
	if f.loadBalancer == nil {
		f.loadBalancer = NewLoadBalancer()
	}

	return f
}

// mapLBStrategy 映射负载均衡策略字符串到类型
func mapLBStrategy(strategy string) LBStrategy {
	switch strings.ToLower(strategy) {
	case "round_robin":
		return LBStrategyRoundRobin
	case "weighted":
		return LBStrategyWeighted
	case "least_conn", "leastconn":
		return LBStrategyLeastConn
	case "ip_hash", "iphash":
		return LBStrategyIPHash
	case "random":
		return LBStrategyRandom
	case "url_hash", "urlhash":
		return LBStrategyURLHash
	default:
		return LBStrategyRoundRobin
	}
}

// Start 启动转发器
func (f *Forwarder) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", f.config.ListenAddr, f.config.ListenPort)

	var listener net.Listener
	var err error

	if f.config.TLSCertFile != "" && f.config.TLSKeyFile != "" {
		// HTTPS 模式
		cert, err := tls.LoadX509KeyPair(f.config.TLSCertFile, f.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		listener, err = tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		f.logger.Infof("forwarder: listening on https://%s", addr)
	} else {
		// HTTP 模式
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		f.logger.Infof("forwarder: listening on http://%s", addr)
	}

	// 启动接受循环
	f.wg.Add(1)
	go f.acceptLoop(ctx, listener)

	return nil
}

// Stop 停止转发器
func (f *Forwarder) Stop() {
	close(f.stopChan)
	f.wg.Wait()
	f.connPool.Close()
}

// acceptLoop 接受连接循环
func (f *Forwarder) acceptLoop(ctx context.Context, listener net.Listener) {
	defer f.wg.Done()

	for {
		select {
		case <-f.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					continue
				}
				f.logger.Warnf("forwarder: accept error: %v", err)
				continue
			}

			f.wg.Add(1)
			go f.handleConnection(ctx, conn)
		}
	}
}

// handleConnection 处理连接
func (f *Forwarder) handleConnection(ctx context.Context, conn net.Conn) {
	defer f.wg.Done()
	defer conn.Close()

	f.logger.Debugf("forwarder: new connection from %s", conn.RemoteAddr().String())

	// 根据模式处理连接
	switch f.config.Mode {
	case "tcp":
		f.handleTCP(ctx, conn)
	default:
		f.handleHTTP(ctx, conn)
	}
}

// handleHTTP 处理 HTTP 连接
func (f *Forwarder) handleHTTP(ctx context.Context, conn net.Conn) {
	// 读取请求
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		f.logger.Warnf("forwarder: read request error: %v", err)
		return
	}
	defer req.Body.Close()

	// 移除路径前缀
	path := req.URL.Path
	if f.config.PathPrefix != "" && strings.HasPrefix(path, f.config.PathPrefix) {
		path = strings.TrimPrefix(path, f.config.PathPrefix)
		if path == "" {
			path = "/"
		}
		req.URL.Path = path
	}

	// 选择后端
	cluster, ok := f.clusters["default"]
	if !ok {
		f.writeError(conn, "No upstream servers", http.StatusBadGateway)
		return
	}

	lbReq := &Request{
		IP:     getClientIP(req),
		URL:    req.URL.String(),
		Method: req.Method,
	}

	backend, err := cluster.Select(ctx, lbReq)
	if err != nil {
		f.logger.Warnf("forwarder: no backend available: %v", err)
		f.writeError(conn, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	// 更新连接数
	cluster.UpdateBackendConns(backend.addr, backend.port, 1)

	// 转发请求
	req.URL.Scheme = "http"
	req.URL.Host = backend.Addr()

	// 移除 hop-by-hop 头
	removeHopByHopHeaders(req.Header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.logger.Warnf("forwarder: forward request error: %v", err)
		cluster.UpdateBackendConns(backend.addr, backend.port, -1)
		f.writeError(conn, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 移除 hop-by-hop 头
	removeHopByHopHeaders(resp.Header)

	// 转发响应
	resp.Write(conn)

	// 更新连接数
	cluster.UpdateBackendConns(backend.addr, backend.port, -1)
}

// handleTCP 处理 TCP 连接
func (f *Forwarder) handleTCP(ctx context.Context, conn net.Conn) {
	cluster, ok := f.clusters["default"]
	if !ok {
		conn.Close()
		return
	}

	backends := cluster.GetBackends()
	if len(backends) == 0 {
		conn.Close()
		return
	}

	backend := backends[0]
	target, err := net.DialTimeout("tcp", backend.Addr(), 10*time.Second)
	if err != nil {
		f.logger.Warnf("forwarder: dial error: %v", err)
		conn.Close()
		return
	}
	defer target.Close()

	cluster.UpdateBackendConns(backend.addr, backend.port, 1)

	// 双向转发
	go func() {
		io.Copy(target, conn)
		cluster.UpdateBackendConns(backend.addr, backend.port, -1)
	}()
	io.Copy(conn, target)
	cluster.UpdateBackendConns(backend.addr, backend.port, -1)
}

// writeError 写入 HTTP 错误响应
func (f *Forwarder) writeError(conn net.Conn, message string, statusCode int) {
	conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, http.StatusText(statusCode), len(message), message)))
}

// getClientIP 获取客户端 IP
func getClientIP(req *http.Request) net.IP {
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := net.ParseIP(strings.TrimSpace(parts[0]))
		if ip != nil {
			return ip
		}
	}

	xri := req.Header.Get("X-Real-IP")
	if xri != "" {
		ip := net.ParseIP(xri)
		if ip != nil {
			return ip
		}
	}

	addr, _, _ := net.SplitHostPort(req.RemoteAddr)
	return net.ParseIP(addr)
}

// removeHopByHopHeaders 移除 hop-by-hop 头
func removeHopByHopHeaders(header http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// AddCluster 添加集群
func (f *Forwarder) AddCluster(name string, servers []string, port int, strategy LBStrategy) error {
	cluster, err := f.loadBalancer.CreateCluster(name, WithLBStrategy(strategy))
	if err != nil {
		return err
	}

	for _, server := range servers {
		cluster.AddBackend(server, port, 1)
	}

	f.clusters[name] = cluster
	return nil
}

// SetupCluster 设置上游集群
func (f *Forwarder) SetupCluster(cfg *ForwardConfig) error {
	clusterName := cfg.ClusterName
	if clusterName == "" {
		clusterName = "default"
	}

	strategy := mapLBStrategy(cfg.LBStrategy)
	cluster, err := f.loadBalancer.CreateCluster(clusterName, WithLBStrategy(strategy))
	if err != nil {
		return err
	}

	for _, addr := range cfg.UpstreamAddrs {
		cluster.AddBackend(addr, cfg.UpstreamPort, 1)
	}

	f.clusters[clusterName] = cluster
	return nil
}

// GetCluster 获取集群
func (f *Forwarder) GetCluster(name string) (*Cluster, bool) {
	cluster, ok := f.clusters[name]
	return cluster, ok
}

// SetBackendHealthy 设置后端健康状态
func (f *Forwarder) SetBackendHealthy(clusterName string, addr string, port int, healthy bool) {
	cluster, ok := f.clusters[clusterName]
	if !ok {
		return
	}
	cluster.SetBackendHealthy(addr, port, healthy)
}

// GetStats 获取统计
func (f *Forwarder) GetStats() ForwarderStats {
	stats := ForwarderStats{
		Clusters: make(map[string]ClusterStats),
	}

	for name, cluster := range f.clusters {
		stats.Clusters[name] = cluster.GetStats()
	}

	stats.ConnPool = f.connPool.Stats()

	return stats
}

// ForwarderStats 转发器统计
type ForwarderStats struct {
	Clusters map[string]ClusterStats
	ConnPool ConnPoolStats
}

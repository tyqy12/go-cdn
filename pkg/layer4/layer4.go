package layer4

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SO_REUSEPORT常量（Linux特定）
const SO_REUSEPORT = 15

// Layer4Proxy 四层代理
type Layer4Proxy struct {
	config       *Layer4Config
	listeners    map[string]*ProxyListener
	sessions     map[int64]*ProxySession
	loadBalancer *LoadBalancer
	ipLimiter    *IPConnectionLimiter
	mu           sync.RWMutex
	stats        *Layer4Stats
	ctx          context.Context
	cancel       context.CancelFunc
}

// Layer4Config 四层代理配置
type Layer4Config struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 监听配置
	Listeners []ListenerConfig `yaml:"listeners"`

	// 代理配置
	Proxy *ProxyConfig `yaml:"proxy"`

	// 连接配置
	Connection *ConnectionConfig `yaml:"connection"`

	// 健康检查
	HealthCheck *HealthCheckConfig `yaml:"health_check"`

	// 负载均衡
	LoadBalance *LoadBalanceConfig `yaml:"load_balance"`

	// 连接限制
	ConnectionLimit *ConnectionLimitConfig `yaml:"connection_limit"`

	// 访问控制
	AccessControl *AccessControlConfig `yaml:"access_control"`

	// 日志配置
	Logging *Layer4LoggingConfig `yaml:"logging"`
}

// ListenerConfig 监听器配置
type ListenerConfig struct {
	// 监听名称
	Name string `yaml:"name"`

	// 监听地址
	Addr string `yaml:"addr"`

	// 监听端口
	Port int `yaml:"port"`

	// 协议类型
	Protocol string `yaml:"protocol"` // "tcp", "udp"

	// 是否启用
	Enabled bool `yaml:"enabled"`

	// 最大连接数
	MaxConnections int `yaml:"max_connections"`

	// 连接队列大小
	Backlog int `yaml:"backlog"`

	// SO_REUSEPORT
	ReusePort bool `yaml:"reuse_port"`

	// 读写超时
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`

	// 空闲超时
	IdleTimeout time.Duration `yaml:"idle_timeout"`

	// TLS配置
	TLS *TLSListenerConfig `yaml:"tls"`
}

// TLSListenerConfig TLS监听器配置
type TLSListenerConfig struct {
	// 启用TLS
	Enabled bool `yaml:"enabled"`

	// 证书路径
	CertFile string `yaml:"cert_file"`

	// 密钥路径
	KeyFile string `yaml:"key_file"`

	// CA证书
	CAFile string `yaml:"ca_file"`

	// 协议版本
	MinVersion string `yaml:"min_version"`
	MaxVersion string `yaml:"max_version"`

	// 密码套件
	CipherSuites []string `yaml:"cipher_suites"`

	// 客户端认证
	ClientAuth string `yaml:"client_auth"` // "no", "request", "require"
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	// 代理类型
	Type string `yaml:"type"` // "forward", "reverse", "transparent"

	// 目标地址
	Target string `yaml:"target"`

	// 目标端口
	TargetPort int `yaml:"target_port"`

	// 目标列表
	Targets []TargetConfig `yaml:"targets"`

	// 源地址保持
	PreserveSourceAddr bool `yaml:"preserve_source_addr"`

	// 端口映射
	PortMapping []PortMappingConfig `yaml:"port_mapping"`
}

// TargetConfig 目标配置
type TargetConfig struct {
	// 地址
	Addr string `json:"addr"`

	// 端口
	Port int `json:"port"`

	// 权重
	Weight int `json:"weight"`

	// 健康状态
	Healthy bool `json:"healthy"`

	// 延迟
	Latency time.Duration `json:"latency"`

	// 最大连接数
	MaxConnections int `json:"max_connections"`

	// 当前连接数
	CurrentConnections int64 `json:"current_connections"`
}

// PortMappingConfig 端口映射配置
type PortMappingConfig struct {
	// 源端口
	SourcePort int `yaml:"source_port"`

	// 目标端口
	TargetPort int `yaml:"target_port"`

	// 目标地址
	TargetAddr string `yaml:"target_addr"`

	// 协议
	Protocol string `yaml:"protocol"` // "tcp", "udp"
}

// ConnectionConfig 连接配置
type ConnectionConfig struct {
	// 最大连接数
	MaxConnections int `yaml:"max_connections"`

	// 单IP最大连接数
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip"`

	// 连接超时
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	// 读超时
	ReadTimeout time.Duration `yaml:"read_timeout"`

	// 写超时
	WriteTimeout time.Duration `yaml:"write_timeout"`

	// 空闲超时
	IdleTimeout time.Duration `yaml:"idle_timeout"`

	// 保持连接
	KeepAlive bool `yaml:"keep_alive"`

	// 保持连接间隔
	KeepAliveInterval time.Duration `yaml:"keep_alive_interval"`

	// 最大缓冲区
	MaxBufferSize int `yaml:"max_buffer_size"`

	// 连接速率限制
	RateLimit *RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig 速率限制配置
type RateLimitConfig struct {
	// 启用速率限制
	Enabled bool `yaml:"enabled"`

	// 每秒最大连接数
	MaxConnectionsPerSecond int `yaml:"max_connections_per_second"`

	// 令牌桶大小
	TokenBucketSize int `yaml:"token_bucket_size"`

	// 令牌填充速率
	TokenFillRate int `yaml:"token_fill_rate"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	// 启用健康检查
	Enabled bool `yaml:"enabled"`

	// 检查类型
	Type string `yaml:"type"` // "tcp", "http", "icmp"

	// 检查路径(对于HTTP)
	Path string `yaml:"path"`

	// 检查端口
	Port int `yaml:"port"`

	// 检查间隔
	Interval time.Duration `yaml:"interval"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 不健康阈值
	UnhealthyThreshold int `yaml:"unhealthy_threshold"`

	// 健康阈值
	HealthyThreshold int `yaml:"healthy_threshold"`

	// 预期响应码
	ExpectedStatus int `yaml:"expected_status"`

	// 预期响应体
	ExpectedBody string `yaml:"expected_body"`
}

// LoadBalanceConfig 负载均衡配置
type LoadBalanceConfig struct {
	// 启用负载均衡
	Enabled bool `yaml:"enabled"`

	// 负载均衡算法
	Method string `yaml:"method"` // "round_robin", "least_conn", "ip_hash", "random", "weighted"

	// 哈希键
	HashKey string `yaml:"hash_key"` // "source_ip", "uri"

	// 健康检查
	HealthCheck bool `yaml:"health_check"`

	// 故障转移
	Failover bool `yaml:"failover"`

	// 故障转移超时
	FailoverTimeout time.Duration `yaml:"failover_timeout"`

	// 权重配置
	Weights map[string]int `yaml:"weights"`
}

// ConnectionLimitConfig 连接限制配置
type ConnectionLimitConfig struct {
	// 启用连接限制
	Enabled bool `yaml:"enabled"`

	// 全局最大连接数
	GlobalMaxConnections int `yaml:"global_max_connections"`

	// 单IP最大连接数
	PerIPMaxConnections int `yaml:"per_ip_max_connections"`

	// 单IP最大连接速率
	PerIPMaxConnectionRate int `yaml:"per_ip_max_connection_rate"`

	// 连接速率窗口
	RateWindow time.Duration `yaml:"rate_window"`

	// 封锁时间
	BlockDuration time.Duration `yaml:"block_duration"`
}

// AccessControlConfig 访问控制配置
type AccessControlConfig struct {
	// 启用访问控制
	Enabled bool `yaml:"enabled"`

	// IP白名单
	WhiteList []string `yaml:"white_list"`

	// IP黑名单
	BlackList []string `yaml:"black_list"`

	// 国家代码白名单
	AllowedCountries []string `yaml:"allowed_countries"`

	// 国家代码黑名单
	BlockedCountries []string `yaml:"blocked_countries"`
}

// Layer4LoggingConfig 日志配置
type Layer4LoggingConfig struct {
	// 启用日志
	Enabled bool `yaml:"enabled"`

	// 日志级别
	Level string `yaml:"level"` // "debug", "info", "warn", "error"

	// 日志格式
	Format string `yaml:"format"` // "json", "text"

	// 连接日志
	ConnectionLog bool `yaml:"connection_log"`

	// 流量日志
	TrafficLog bool `yaml:"traffic_log"`

	// 错误日志
	ErrorLog bool `yaml:"error_log"`
}

// ProxyListener 代理监听器
type ProxyListener struct {
	config   *ListenerConfig
	listener interface {
		Accept() (net.Conn, error)
		Close() error
	}
	connChan chan net.Conn
	wg       sync.WaitGroup
	running  bool
	mu       sync.RWMutex
}

// ProxySession 代理会话
type ProxySession struct {
	ID          int64
	SrcConn     net.Conn
	DstConn     net.Conn
	SrcAddr     *net.TCPAddr
	DstAddr     *net.TCPAddr
	Protocol    string
	StartTime   time.Time
	BytesIn     int64
	BytesOut    int64
	ConnectedIP string
	Status      string
	mu          sync.RWMutex
}

// Layer4Stats 四层代理统计
type Layer4Stats struct {
	TotalConnections   int64            `json:"total_connections"`
	ActiveConnections  int64            `json:"active_connections"`
	TotalBytesIn       int64            `json:"total_bytes_in"`
	TotalBytesOut      int64            `json:"total_bytes_out"`
	BlockedConnections int64            `json:"blocked_connections"`
	FailedConnections  int64            `json:"failed_connections"`
	CurrentBandwidth   float64          `json:"current_bandwidth"`
	PeakBandwidth      float64          `json:"peak_bandwidth"`
	ConnectionsPerIP   map[string]int64 `json:"connections_per_ip"`
	TopSourceIPs       []IPStats        `json:"top_source_ips"`
	ByProtocol         map[string]int64 `json:"by_protocol"`
	mu                 sync.RWMutex
}

// IPStats IP统计
type IPStats struct {
	IP           string `json:"ip"`
	Connections  int64  `json:"connections"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	BlockedCount int64  `json:"blocked_count"`
	CurrentConns int64  `json:"current_conns"`
}

// ConnectionInfo 连接信息
type ConnectionInfo struct {
	ID         int64         `json:"id"`
	Protocol   string        `json:"protocol"`
	SourceIP   string        `json:"source_ip"`
	SourcePort int           `json:"source_port"`
	TargetIP   string        `json:"target_ip"`
	TargetPort int           `json:"target_port"`
	BytesIn    int64         `json:"bytes_in"`
	BytesOut   int64         `json:"bytes_out"`
	Duration   time.Duration `json:"duration"`
	Status     string        `json:"status"`
	StartTime  time.Time     `json:"start_time"`
}

// NewLayer4Proxy 创建四层代理
func NewLayer4Proxy(config *Layer4Config) *Layer4Proxy {
	if config == nil {
		config = &Layer4Config{
			Enabled: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &Layer4Proxy{
		config:       config,
		listeners:    make(map[string]*ProxyListener),
		sessions:     make(map[int64]*ProxySession),
		loadBalancer: NewLoadBalancer(config.LoadBalance),
		ipLimiter:    NewIPConnectionLimiter(config.ConnectionLimit),
		stats:        &Layer4Stats{ConnectionsPerIP: make(map[string]int64), ByProtocol: make(map[string]int64)},
		ctx:          ctx,
		cancel:       cancel,
	}

	return proxy
}

// Start 启动四层代理
func (p *Layer4Proxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.config.Enabled {
		return nil
	}

	// 启动监听器
	for _, listenerConfig := range p.config.Listeners {
		if !listenerConfig.Enabled {
			continue
		}

		if err := p.startListener(&listenerConfig); err != nil {
			return fmt.Errorf("启动监听器失败 %s: %v", listenerConfig.Name, err)
		}
	}

	// 启动后台任务
	go p.runBackgroundTasks()

	return nil
}

// startListener 启动监听器
func (p *Layer4Proxy) startListener(config *ListenerConfig) error {
	addr := fmt.Sprintf("%s:%d", config.Addr, config.Port)

	var listener net.Listener
	var err error

	// 根据协议创建监听器
	switch config.Protocol {
	case "tcp":
		listener, err = p.createTCPListener(config)
	case "udp":
		return fmt.Errorf("暂不支持UDP协议: %s", addr)
	default:
		return fmt.Errorf("不支持的协议: %s", config.Protocol)
	}

	if err != nil {
		return err
	}

	proxyListener := &ProxyListener{
		config:   config,
		listener: listener,
		connChan: make(chan net.Conn, config.Backlog),
		running:  true,
	}

	p.listeners[config.Name] = proxyListener

	// 启动接受连接
	go p.acceptConnections(proxyListener)

	// 启动连接处理
	go p.handleConnections(proxyListener)

	return nil
}

// createTCPListener 创建TCP监听器，支持SO_REUSEPORT
func (p *Layer4Proxy) createTCPListener(config *ListenerConfig) (net.Listener, error) {
	// 创建TCP地址
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", config.Addr, config.Port))
	if err != nil {
		return nil, fmt.Errorf("解析TCP地址失败: %w", err)
	}

	var listener net.Listener

	if config.ReusePort {
		// 尝试使用SO_REUSEPORT（仅Linux）
		listener, err = p.createReusePortListener(tcpAddr, config.Backlog)
		if err != nil {
			// 如果SO_REUSEPORT不可用（Windows），回退到普通监听器
			fmt.Printf("SO_REUSEPORT不可用，回退到普通监听器: %v\n", err)
			listener, err = net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				return nil, fmt.Errorf("创建TCP监听器失败: %w", err)
			}
		}
	} else {
		// 普通TCP监听器
		listener, err = net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("创建TCP监听器失败: %w", err)
		}
	}

	return listener, nil
}

// createReusePortListener 创建支持SO_REUSEPORT的监听器（仅Linux）
func (p *Layer4Proxy) createReusePortListener(addr *net.TCPAddr, backlog int) (net.Listener, error) {
	// 检查是否为Linux
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("SO_REUSEPORT仅在Linux上支持，当前平台: %s", runtime.GOOS)
	}

	// 创建socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("创建socket失败: %w", err)
	}

	// 设置SO_REUSEPORT
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_REUSEPORT, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("设置SO_REUSEPORT失败: %w", err)
	}

	// 绑定地址
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{
		Port: addr.Port,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("绑定地址失败: %w", err)
	}

	// 监听
	if err := syscall.Listen(fd, backlog); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("监听失败: %w", err)
	}

	// 转换为net.Listener
	file := os.NewFile(uintptr(fd), "tcp-listener")
	return net.FileListener(file)
}

// CreateMultiAcceptListeners 创建多个支持SO_REUSEPORT的监听器用于内核级别负载均衡
func (p *Layer4Proxy) CreateMultiAcceptListeners(config *ListenerConfig, numListeners int) ([]net.Listener, error) {
	if numListeners <= 0 {
		numListeners = 4 // 默认4个监听器
	}

	if !config.ReusePort {
		// 如果没有启用ReusePort，只创建一个监听器
		listener, err := p.createTCPListener(config)
		if err != nil {
			return nil, err
		}
		return []net.Listener{listener}, nil
	}

	listeners := make([]net.Listener, 0, numListeners)

	for i := 0; i < numListeners; i++ {
		listener, err := p.createTCPListener(config)
		if err != nil {
			// 关闭已创建的监听器
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("创建第%d个监听器失败: %w", i+1, err)
		}
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// acceptConnections 接受连接
func (p *Layer4Proxy) acceptConnections(listener *ProxyListener) {
	listener.wg.Add(1)
	defer listener.wg.Done()

	for {
		listener.mu.RLock()
		if !listener.running {
			listener.mu.RUnlock()
			break
		}
		listener.mu.RUnlock()

		conn, err := listener.listener.Accept()
		if err != nil {
			if listener.mu.TryRLock() {
				if listener.running {
					p.mu.Lock()
					p.stats.FailedConnections++
					p.mu.Unlock()
				}
				listener.mu.RUnlock()
			}
			continue
		}

		// 检查连接限制
		if !p.checkConnectionAllowed(conn) {
			conn.Close()
			continue
		}

		// 发送到连接通道
		select {
		case listener.connChan <- conn:
		default:
			// 队列满，关闭连接
			conn.Close()
		}
	}
}

// checkConnectionAllowed 检查是否允许连接
func (p *Layer4Proxy) checkConnectionAllowed(conn net.Conn) bool {
	// 检查全局连接限制
	p.mu.RLock()
	if p.config.Connection != nil && p.config.Connection.MaxConnections > 0 {
		if int64(len(p.sessions)) >= int64(p.config.Connection.MaxConnections) {
			p.mu.RUnlock()
			return false
		}
	}
	p.mu.RUnlock()

	// 检查IP连接限制
	if p.ipLimiter != nil {
		addr := conn.RemoteAddr().String()
		if !p.ipLimiter.AllowConnection(addr) {
			return false
		}
	}

	// 检查访问控制
	if p.config.AccessControl != nil && p.config.AccessControl.Enabled {
		ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
		if p.isBlockedIP(ip) {
			return false
		}
	}

	return true
}

// isBlockedIP 检查IP是否被封锁
func (p *Layer4Proxy) isBlockedIP(ip string) bool {
	if p.config.AccessControl == nil {
		return false
	}

	for _, blockedIP := range p.config.AccessControl.BlackList {
		if ip == blockedIP {
			return true
		}
	}

	return false
}

// handleConnections 处理连接
func (p *Layer4Proxy) handleConnections(listener *ProxyListener) {
	for conn := range listener.connChan {
		go p.handleConnection(conn, listener)
	}
}

// handleConnection 处理单个连接
func (p *Layer4Proxy) handleConnection(conn net.Conn, listener *ProxyListener) {
	defer conn.Close()

	// 创建会话
	session := &ProxySession{
		ID:        atomic.AddInt64(&sessionID, 1),
		SrcConn:   conn,
		SrcAddr:   conn.RemoteAddr().(*net.TCPAddr),
		Protocol:  listener.config.Protocol,
		StartTime: time.Now(),
		Status:    "connecting",
	}

	// 添加到会话表
	p.mu.Lock()
	p.sessions[session.ID] = session
	p.stats.ActiveConnections++
	p.stats.TotalConnections++
	p.mu.Unlock()

	// 选择目标服务器
	target := p.loadBalancer.Select(session.SrcAddr.IP.String())
	if target == nil {
		p.mu.Lock()
		p.stats.FailedConnections++
		p.stats.ActiveConnections--
		delete(p.sessions, session.ID)
		p.mu.Unlock()
		return
	}

	// 连接到目标
	dstConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Addr, target.Port), p.config.Connection.ConnectTimeout)
	if err != nil {
		p.mu.Lock()
		p.stats.FailedConnections++
		p.stats.ActiveConnections--
		delete(p.sessions, session.ID)
		p.mu.Unlock()
		return
	}

	session.DstConn = dstConn
	session.DstAddr = dstConn.RemoteAddr().(*net.TCPAddr)
	session.Status = "connected"

	// 开始代理数据
	go p.proxyData(session)

	// 更新统计
	p.mu.Lock()
	p.stats.ConnectionsPerIP[session.SrcAddr.IP.String()]++
	p.stats.ByProtocol[session.Protocol]++
	p.mu.Unlock()
}

// proxyData 代理数据
func (p *Layer4Proxy) proxyData(session *ProxySession) {
	defer session.SrcConn.Close()
	defer session.DstConn.Close()

	// 使用buffer转发数据
	buf := make([]byte, 32*1024)

	for {
		session.SrcConn.SetReadDeadline(time.Now().Add(p.config.Connection.ReadTimeout))
		n, err := session.SrcConn.Read(buf)
		if err != nil {
			break
		}

		session.BytesIn += int64(n)

		session.DstConn.SetWriteDeadline(time.Now().Add(p.config.Connection.WriteTimeout))
		_, err = session.DstConn.Write(buf[:n])
		if err != nil {
			break
		}

		session.BytesOut += int64(n)

		// 更新带宽统计
		p.updateBandwidthStats()
	}

	session.mu.Lock()
	session.Status = "closed"
	session.mu.Unlock()
}

// updateBandwidthStats 更新带宽统计
func (p *Layer4Proxy) updateBandwidthStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 简单实现，实际应该计算瞬时带宽
	p.stats.TotalBytesIn = 0
	p.stats.TotalBytesOut = 0

	for _, session := range p.sessions {
		p.stats.TotalBytesIn += session.BytesIn
		p.stats.TotalBytesOut += session.BytesOut
	}
}

// runBackgroundTasks 运行后台任务
func (p *Layer4Proxy) runBackgroundTasks() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanupSessions()
			p.updateStats()
		}
	}
}

// cleanupSessions 清理过期会话
func (p *Layer4Proxy) cleanupSessions() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for id, session := range p.sessions {
		session.mu.RLock()
		// 检查是否空闲超时
		if session.Status == "connected" && now.Sub(session.StartTime) > p.config.Connection.IdleTimeout {
			session.mu.RUnlock()
			session.SrcConn.Close()
			delete(p.sessions, id)
			p.stats.ActiveConnections--
		} else {
			session.mu.RUnlock()
		}
	}
}

// updateStats 更新统计
func (p *Layer4Proxy) updateStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 更新Top源IP
	p.stats.TopSourceIPs = make([]IPStats, 0)
	for ip, count := range p.stats.ConnectionsPerIP {
		p.stats.TopSourceIPs = append(p.stats.TopSourceIPs, IPStats{
			IP:          ip,
			Connections: count,
		})
	}
}

// Stop 停止四层代理
func (p *Layer4Proxy) Stop() {
	p.cancel()

	p.mu.Lock()
	defer p.mu.Unlock()

	// 停止所有监听器
	for name, listener := range p.listeners {
		listener.mu.Lock()
		listener.running = false
		listener.mu.Unlock()

		listener.listener.Close()
		delete(p.listeners, name)
	}

	// 关闭所有会话
	for id, session := range p.sessions {
		session.SrcConn.Close()
		delete(p.sessions, id)
	}
}

// GetStats 获取统计
func (p *Layer4Proxy) GetStats() *Layer4Stats {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()

	return p.stats
}

// GetActiveConnections 获取活动连接
func (p *Layer4Proxy) GetActiveConnections() []*ConnectionInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	connections := make([]*ConnectionInfo, 0)
	for id, session := range p.sessions {
		connections = append(connections, &ConnectionInfo{
			ID:         id,
			Protocol:   session.Protocol,
			SourceIP:   session.SrcAddr.IP.String(),
			SourcePort: session.SrcAddr.Port,
			TargetIP:   session.DstAddr.IP.String(),
			TargetPort: session.DstAddr.Port,
			BytesIn:    session.BytesIn,
			BytesOut:   session.BytesOut,
			Duration:   time.Since(session.StartTime),
			Status:     session.Status,
			StartTime:  session.StartTime,
		})
	}

	return connections
}

// GetListeners 获取监听器列表
func (p *Layer4Proxy) GetListeners() []*ListenerConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	listeners := make([]*ListenerConfig, 0)
	for _, listener := range p.listeners {
		listeners = append(listeners, listener.config)
	}

	return listeners
}

// AddListener 添加监听器
func (p *Layer4Proxy) AddListener(config *ListenerConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.listeners[config.Name]; exists {
		return fmt.Errorf("监听器已存在: %s", config.Name)
	}

	return p.startListener(config)
}

// RemoveListener 移除监听器
func (p *Layer4Proxy) RemoveListener(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	listener, exists := p.listeners[name]
	if !exists {
		return fmt.Errorf("监听器不存在: %s", name)
	}

	listener.mu.Lock()
	listener.running = false
	listener.mu.Unlock()

	listener.listener.Close()
	delete(p.listeners, name)

	return nil
}

var sessionID int64

// LoadBalancer 负载均衡器
type LoadBalancer struct {
	config  *LoadBalanceConfig
	targets []*TargetConfig
	mu      sync.RWMutex
}

// NewLoadBalancer 创建负载均衡器
func NewLoadBalancer(config *LoadBalanceConfig) *LoadBalancer {
	if config == nil {
		config = &LoadBalanceConfig{
			Enabled: true,
			Method:  "round_robin",
		}
	}

	return &LoadBalancer{
		config:  config,
		targets: make([]*TargetConfig, 0),
	}
}

// Select 选择目标
func (lb *LoadBalancer) Select(clientIP string) *TargetConfig {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.targets) == 0 {
		return nil
	}

	switch lb.config.Method {
	case "round_robin":
		return lb.selectRoundRobin()
	case "least_conn":
		return lb.selectLeastConn()
	case "ip_hash":
		return lb.selectIPHash(clientIP)
	case "random":
		return lb.selectRandom()
	case "weighted":
		return lb.selectWeighted()
	default:
		return lb.selectRoundRobin()
	}
}

// selectRoundRobin 轮询选择
func (lb *LoadBalancer) selectRoundRobin() *TargetConfig {
	if len(lb.targets) == 0 {
		return nil
	}
	// 简单实现
	return lb.targets[0]
}

// selectLeastConn 最少连接选择
func (lb *LoadBalancer) selectLeastConn() *TargetConfig {
	var minConn *TargetConfig
	for _, target := range lb.targets {
		if target.Healthy && (minConn == nil || target.CurrentConnections < minConn.CurrentConnections) {
			minConn = target
		}
	}
	return minConn
}

// selectIPHash IP哈希选择
func (lb *LoadBalancer) selectIPHash(clientIP string) *TargetConfig {
	if len(lb.targets) == 0 {
		return nil
	}
	hash := 0
	for _, c := range clientIP {
		hash = hash*31 + int(c)
	}
	return lb.targets[hash%len(lb.targets)]
}

// selectRandom 随机选择
func (lb *LoadBalancer) selectRandom() *TargetConfig {
	if len(lb.targets) == 0 {
		return nil
	}
	return lb.targets[0] // 简化实现
}

// selectWeighted 权重选择
func (lb *LoadBalancer) selectWeighted() *TargetConfig {
	// 简化实现
	return lb.targets[0]
}

// AddTarget 添加目标
func (lb *LoadBalancer) AddTarget(target *TargetConfig) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.targets = append(lb.targets, target)
}

// RemoveTarget 移除目标
func (lb *LoadBalancer) RemoveTarget(addr string, port int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, target := range lb.targets {
		if target.Addr == addr && target.Port == port {
			lb.targets = append(lb.targets[:i], lb.targets[i+1:]...)
			break
		}
	}
}

// SetTargetHealthy 设置目标健康状态
func (lb *LoadBalancer) SetTargetHealthy(addr string, port int, healthy bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for _, target := range lb.targets {
		if target.Addr == addr && target.Port == port {
			target.Healthy = healthy
			break
		}
	}
}

// IPConnectionLimiter IP连接限制器
type IPConnectionLimiter struct {
	config      *ConnectionLimitConfig
	connections map[string][]time.Time
	blockedIPs  map[string]time.Time
	mu          sync.RWMutex
}

// NewIPConnectionLimiter 创建IP连接限制器
func NewIPConnectionLimiter(config *ConnectionLimitConfig) *IPConnectionLimiter {
	if config == nil {
		config = &ConnectionLimitConfig{
			Enabled:             true,
			PerIPMaxConnections: 100,
			RateWindow:          time.Minute,
			BlockDuration:       5 * time.Minute,
		}
	}

	return &IPConnectionLimiter{
		config:      config,
		connections: make(map[string][]time.Time),
		blockedIPs:  make(map[string]time.Time),
	}
}

// AllowConnection 允许连接
func (l *IPConnectionLimiter) AllowConnection(ip string) bool {
	if !l.config.Enabled {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 检查是否被封锁
	if blockedUntil, ok := l.blockedIPs[ip]; ok {
		if time.Now().Before(blockedUntil) {
			return false
		}
		delete(l.blockedIPs, ip)
	}

	// 检查连接数
	conns := l.connections[ip]
	if len(conns) >= l.config.PerIPMaxConnections {
		l.blockedIPs[ip] = time.Now().Add(l.config.BlockDuration)
		return false
	}

	// 检查连接速率
	if l.config.PerIPMaxConnectionRate > 0 {
		now := time.Now()
		windowStart := now.Add(-l.config.RateWindow)
		recentConns := 0
		for _, t := range conns {
			if t.After(windowStart) {
				recentConns++
			}
		}
		if recentConns >= l.config.PerIPMaxConnectionRate {
			l.blockedIPs[ip] = time.Now().Add(l.config.BlockDuration)
			return false
		}
	}

	// 记录连接
	l.connections[ip] = append(l.connections[ip], time.Now())

	return true
}

// RemoveConnection 移除连接
func (l *IPConnectionLimiter) RemoveConnection(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	conns := l.connections[ip]
	if len(conns) > 0 {
		l.connections[ip] = conns[:len(conns)-1]
	}
}

// GetBlockedIPs 获取被封锁的IP列表
func (l *IPConnectionLimiter) GetBlockedIPs() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	blocked := make([]string, 0)
	for ip, until := range l.blockedIPs {
		if time.Now().Before(until) {
			blocked = append(blocked, ip)
		}
	}

	return blocked
}

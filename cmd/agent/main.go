package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/gin-gonic/gin"

	"github.com/ai-cdn-tunnel/agent/config"
	"github.com/ai-cdn-tunnel/agent/heartbeat"
	"github.com/ai-cdn-tunnel/agent/status"
	"github.com/ai-cdn-tunnel/pkg/distribute"
	"github.com/ai-cdn-tunnel/pkg/failover"
	"github.com/ai-cdn-tunnel/pkg/forward"
	"github.com/ai-cdn-tunnel/pkg/health"
	"github.com/ai-cdn-tunnel/pkg/protection"
	cdntls "github.com/ai-cdn-tunnel/pkg/tls"
	pb "github.com/ai-cdn-tunnel/proto/agent"
)

// CDN核心版本
const Version = "2.0.0"

// 全局配置
var GlobalConfig *config.Config

// 全局组件
var (
	// CDN组件
	tlsManager    *cdntls.CertManager
	connPool      *forward.ConnPool
	loadBalancer  *forward.LoadBalancer
	forwarder     *forward.Forwarder
	healthChecker *health.Checker
	failoverMgr   *failover.Manager
	distributor   *distribute.Distributor
	protectionEng *protection.ProtectionEngine

	// HTTP服务
	httpServer  *http.Server
	httpsServer *http.Server

	// Master通信
	masterConn   *grpc.ClientConn
	masterClient pb.AgentServiceClient

	// 节点信息
	nodeID   string
	nodeName string
)

var (
	configPath           string
	insecureMode         bool
	configMutex          sync.RWMutex
	currentConfigVersion int64 = 0
	configApplyHistory   []ConfigApplyRecord
)

// ConfigApplyRecord 配置应用记录
type ConfigApplyRecord struct {
	Version   int64     `json:"version"`
	ApplyTime time.Time `json:"apply_time"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Reloaded  bool      `json:"reloaded"`
}

func init() {
	flag.StringVar(&configPath, "config", "agent.yml", "config file path")
	flag.BoolVar(&insecureMode, "insecure", false, "allow insecure connections (not recommended for production)")
}

func main() {
	flag.Parse()

	// 加载配置
	var err error
	GlobalConfig, err = config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 验证配置
	if err := GlobalConfig.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// 设置节点ID
	if GlobalConfig.Node.ID == "" {
		GlobalConfig.Node.ID = generateNodeID()
	}
	if GlobalConfig.Node.Name == "" {
		GlobalConfig.Node.Name = fmt.Sprintf("%s-%s", GlobalConfig.Node.Type, GlobalConfig.Node.Region)
	}
	nodeID = GlobalConfig.Node.ID
	nodeName = GlobalConfig.Node.Name

	// 设置运行模式
	if GlobalConfig.CDN.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	log.Printf("Starting GoCDN Agent: %s (%s) - v%s", nodeID, nodeName, Version)

	// 创建主上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 初始化组件
	if err := initComponents(ctx); err != nil {
		log.Fatalf("Failed to initialize components: %v", err)
	}

	// 连接Master
	if err := connectMaster(); err != nil {
		log.Printf("Warning: Failed to connect to master: %v", err)
	} else {
		// 注册节点
		if err := registerNode(); err != nil {
			log.Printf("Warning: Failed to register node: %v", err)
		}

		// 启动心跳
		startHeartbeat(ctx)

		// 启动状态上报
		startStatusReporter(ctx)

		// 启动配置监听
		go listenConfig(ctx)
	}

	// 启动CDN服务
	go startHTTPServer(ctx)
	go startHTTPSServer(ctx)
	go startBackgroundServices(ctx)

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down agent...")
	cancel()
	time.Sleep(2 * time.Second)
	stopComponents()
	log.Println("Agent stopped")
}

func initComponents(ctx context.Context) error {
	var err error

	// 1. 初始化TLS证书管理器
	tlsManager = cdntls.NewCertManager(
		cdntls.WithAutoRenewal(true),
	)
	if GlobalConfig.CDN.Server.TLSAutoGen {
		if err := tlsManager.GenerateSelfSigned(GlobalConfig.CDN.Server.TLSDomain); err != nil {
			log.Printf("Warning: failed to generate self-signed cert: %v", err)
		}
	}
	if GlobalConfig.CDN.Server.TLSCertFile != "" && GlobalConfig.CDN.Server.TLSKeyFile != "" {
		if err := tlsManager.LoadCertificate(
			GlobalConfig.CDN.Server.TLSDomain,
			GlobalConfig.CDN.Server.TLSCertFile,
			GlobalConfig.CDN.Server.TLSKeyFile,
		); err != nil {
			log.Printf("Warning: failed to load certificate: %v", err)
		}
	}

	// 2. 初始化连接池
	connPool = forward.NewConnPool(
		forward.WithConnPoolMaxIdleConns(1000),
		forward.WithConnPoolMaxConnsPer(10000),
		forward.WithConnPoolIdleTimeout(90*time.Second),
	)

	// 3. 初始化负载均衡器
	loadBalancer = forward.NewLoadBalancer()

	// 配置默认集群
	cluster, err := loadBalancer.CreateCluster("default")
	if err != nil {
		return fmt.Errorf("create default cluster: %w", err)
	}

	// 设置负载均衡策略
	switch GlobalConfig.CDN.LoadBalance.Strategy {
	case "round_robin":
		cluster.SetStrategy(forward.LBStrategyRoundRobin)
	case "least_conn":
		cluster.SetStrategy(forward.LBStrategyLeastConn)
	case "ip_hash":
		cluster.SetStrategy(forward.LBStrategyIPHash)
	case "weighted":
		cluster.SetStrategy(forward.LBStrategyWeighted)
	case "random":
		cluster.SetStrategy(forward.LBStrategyRandom)
	default:
		cluster.SetStrategy(forward.LBStrategyRoundRobin)
	}

	// 添加上游服务器
	for _, upstream := range GlobalConfig.CDN.Upstreams {
		if upstream.Enabled {
			cluster.AddBackend(upstream.Addr, upstream.Port, upstream.Weight)
			log.Printf("Upstream server added: %s:%d (weight: %d)", upstream.Addr, upstream.Port, upstream.Weight)
		}
	}

	// 会话粘性
	if GlobalConfig.CDN.LoadBalance.Sticky {
		cluster.SetStickyConfig(forward.StickyConfig{
			Enabled:    true,
			Method:     GlobalConfig.CDN.LoadBalance.StickyMode,
			CookieName: GlobalConfig.CDN.LoadBalance.StickyCookie,
			Timeout:    GlobalConfig.CDN.LoadBalance.StickyTimeout,
		})
	}

	// 4. 初始化健康检查器
	healthChecker = health.NewChecker(
		health.WithHCInterval(time.Duration(GlobalConfig.CDN.HealthCheck.Interval)*time.Second),
		health.WithHCTimeout(time.Duration(GlobalConfig.CDN.HealthCheck.Timeout)*time.Second),
		health.WithHCUnhealthyThreshold(GlobalConfig.CDN.HealthCheck.UnhealthyThreshold),
		health.WithHCHealthyThreshold(GlobalConfig.CDN.HealthCheck.HealthyThreshold),
	)

	// 添加健康检查目标
	for _, upstream := range GlobalConfig.CDN.Upstreams {
		if upstream.Enabled {
			if GlobalConfig.CDN.HealthCheck.CheckPath != "" {
				// HTTP健康检查
				httpCheck := health.NewHTTPCheck(
					GlobalConfig.CDN.HealthCheck.CheckPath,
					health.WithHCMethod(GlobalConfig.CDN.HealthCheck.CheckMethod),
					health.WithHCStatus(GlobalConfig.CDN.HealthCheck.ExpectedCodes),
				)
				// 添加HTTP检查器
				healthChecker.AddChecker(httpCheck.Check)
				healthChecker.AddTarget(upstream.Addr, upstream.Addr, upstream.Port, "http")
			} else {
				// TCP健康检查
				healthChecker.AddTarget(upstream.Addr, upstream.Addr, upstream.Port, "tcp")
			}
		}
	}

	// 5. 初始化故障转移管理器
	failoverMgr = failover.NewManager()

	group, err := failoverMgr.CreateGroup("default", &failover.FailoverConfig{
		Strategy:   failover.FailoverStrategy(GlobalConfig.CDN.Failover.Strategy),
		Interval:   time.Duration(GlobalConfig.CDN.HealthCheck.Interval) * time.Second,
		Timeout:    time.Duration(GlobalConfig.CDN.HealthCheck.Timeout) * time.Second,
		MaxRetries: GlobalConfig.CDN.Failover.MaxRetries,
	})
	if err != nil {
		return fmt.Errorf("create failover group: %w", err)
	}

	// 设置主节点
	if len(GlobalConfig.CDN.Upstreams) > 0 && GlobalConfig.CDN.Upstreams[0].Enabled {
		group.SetPrimary(&failover.Node{
			Addr:     GlobalConfig.CDN.Upstreams[0].Addr,
			Port:     GlobalConfig.CDN.Upstreams[0].Port,
			Weight:   GlobalConfig.CDN.Upstreams[0].Weight,
			Priority: 10,
			Name:     "primary",
		})
	}

	// 添加备用节点
	for i, upstream := range GlobalConfig.CDN.Upstreams[1:] {
		if upstream.Enabled {
			group.AddSecondary(&failover.Node{
				Addr:     upstream.Addr,
				Port:     upstream.Port,
				Weight:   upstream.Weight,
				Priority: 5,
				Name:     fmt.Sprintf("secondary-%d", i),
			})
		}
	}

	// 6. 初始化保护引擎
	protectionEng = protection.NewProtectionEngine(
		&protection.ProtectionConfig{
			GlobalMaxConnections:    GlobalConfig.CDN.Security.GlobalMaxConnections,
			GlobalMaxConnRate:       GlobalConfig.CDN.Security.GlobalMaxConnRate,
			PerClientMaxConnections: GlobalConfig.CDN.Security.PerClientMaxConnections,
			PerClientMaxRate:        GlobalConfig.CDN.Security.PerClientMaxRate,
			SlowConnectionThreshold: time.Duration(GlobalConfig.CDN.Security.SlowConnectionThreshold) * time.Second,
			SlowReadThreshold:       time.Duration(GlobalConfig.CDN.Security.SlowReadThreshold) * time.Second,
			SlowWriteThreshold:      time.Duration(GlobalConfig.CDN.Security.SlowWriteThreshold) * time.Second,
			MaxHeaderSize:           GlobalConfig.CDN.Security.MaxHeaderSize,
			MaxHeadersCount:         GlobalConfig.CDN.Security.MaxHeadersCount,
			MaxRequestBodySize:      GlobalConfig.CDN.Security.MaxRequestBodySize,
		},
		protection.NewConsoleLogger(),
	)
	protectionEng.Start(ctx)

	// 7. 初始化流量分发器
	distributor = distribute.NewDistributor(
		distribute.WithDistLoadBalancer(loadBalancer),
	)

	// 添加路由规则
	for _, routeCfg := range GlobalConfig.CDN.Routes {
		if routeCfg.Enabled {
			distributor.AddRoute(&distribute.Route{
				Name:       routeCfg.Name,
				Pattern:    routeCfg.Pattern,
				MatchType:  distribute.MatchType(routeCfg.MatchType),
				TargetPool: routeCfg.TargetPool,
				Action:     distribute.RouteAction(routeCfg.Action),
				Priority:   routeCfg.Priority,
				Enabled:    routeCfg.Enabled,
			})
			log.Printf("Route configured: %s -> %s", routeCfg.Name, routeCfg.TargetPool)
		}
	}

	// 8. 初始化转发器
	forwarder = forward.NewForwarder(
		forward.WithForwarderConnPool(connPool),
		forward.WithForwarderLoadBalancer(loadBalancer),
		forward.WithForwarderLogger(&consoleLogger{}),
	)

	// 配置上游集群
	upstreamAddrs := make([]string, 0)
	upstreamPorts := make([]int, 0)
	for _, upstream := range GlobalConfig.CDN.Upstreams {
		if upstream.Enabled {
			upstreamAddrs = append(upstreamAddrs, upstream.Addr)
			upstreamPorts = append(upstreamPorts, upstream.Port)
		}
	}

	fwdConfig := &forward.ForwardConfig{
		ClusterName:     "default",
		UpstreamAddrs:   upstreamAddrs,
		UpstreamPort:    GlobalConfig.CDN.Upstreams[0].Port,
		MaxIdleConns:    1000,
		MaxConnsPerAddr: 10000,
	}
	if err := forwarder.SetupCluster(fwdConfig); err != nil {
		log.Printf("Warning: failed to setup cluster: %v", err)
	}

	log.Println("All CDN components initialized successfully")
	return nil
}

func connectMaster() error {
	kaParams := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             30 * time.Second,
		PermitWithoutStream: true,
	}

	var creds credentials.TransportCredentials
	var err error

	if insecureMode {
		log.Println("WARNING: Using insecure connection")
		creds = insecure.NewCredentials()
	} else if GlobalConfig.Master.TLSEnabled {
		creds, err = loadTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %v", err)
		}
		log.Println("TLS encryption enabled")
	} else {
		log.Println("Using default TLS verification")
		creds = credentials.NewClientTLSFromCert(nil, "")
	}

	conn, err := grpc.Dial(
		GlobalConfig.Master.Addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(kaParams),
		grpc.WithUnaryInterceptor(authInterceptor()),
		grpc.WithStreamInterceptor(authStreamInterceptor()),
	)
	if err != nil {
		return err
	}

	masterConn = conn
	masterClient = pb.NewAgentServiceClient(conn)

	log.Printf("Connected to master: %s", GlobalConfig.Master.Addr)
	return nil
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	certFile := GlobalConfig.Master.TLSCertFile
	keyFile := GlobalConfig.Master.TLSKeyFile

	if certFile == "" || keyFile == "" {
		return credentials.NewClientTLSFromCert(nil, ""), nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	if GlobalConfig.Master.TLSCAFile != "" {
		caCert, err := os.ReadFile(GlobalConfig.Master.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %v", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		return credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      certPool,
			MinVersion:   tls.VersionTLS12,
		}), nil
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

func registerNode() error {
	ip, err := getLocalIP()
	if err != nil {
		ip = "127.0.0.1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := masterClient.Register(ctx, &pb.RegisterRequest{
		NodeId:   nodeID,
		NodeName: nodeName,
		NodeType: GlobalConfig.Node.Type,
		Region:   GlobalConfig.Node.Region,
		Ip:       ip,
		Metadata: map[string]string{
			"hostname":   getHostname(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
			"go_version": runtime.Version(),
			"version":    Version,
		},
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("registration failed: %s", resp.Message)
	}

	log.Printf("Registered successfully, master version: %s", resp.MasterVersion)
	return nil
}

func startHeartbeat(ctx context.Context) {
	sender := heartbeat.NewSender(masterClient, nodeID, heartbeat.Config{
		Interval: 10 * time.Second,
		Timeout:  30 * time.Second,
	})
	sender.Start()
}

func startStatusReporter(ctx context.Context) {
	reporter := status.NewReporter(masterClient, nodeID, status.Config{
		CollectInterval: 10 * time.Second,
	})
	reporter.Start()
}

func listenConfig(ctx context.Context) {
	if masterClient == nil {
		log.Println("Warning: Master client not initialized, config watching disabled")
		return
	}

	log.Printf("Starting config watcher for node %s", nodeID)

	reconnectDelay := 1 * time.Second
	maxReconnectDelay := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			log.Println("Config watcher stopped by context")
			return
		default:
			req := &pb.ConfigWatchRequest{
				NodeId:      nodeID,
				LastVersion: currentConfigVersion,
				NodeType:    GlobalConfig.Node.Type,
			}

			stream, err := masterClient.WatchConfig(ctx, req)
			if err != nil {
				log.Printf("Failed to start config watching: %v", err)

				// 退避重连
				select {
				case <-ctx.Done():
					return
				case <-time.After(reconnectDelay):
					reconnectDelay = reconnectDelay * 2
					if reconnectDelay > maxReconnectDelay {
						reconnectDelay = maxReconnectDelay
					}
					continue
				}
			}

			log.Printf("Config watcher started successfully")
			reconnectDelay = 1 * time.Second

			// 接收配置更新
			for {
				select {
				case <-ctx.Done():
					log.Println("Config watcher stopped by context")
					return
				default:
					resp, err := stream.Recv()
					if err != nil {
						log.Printf("Config watcher receive error: %v, reconnecting...", err)
						break
					}

					log.Printf("Received config update: version=%d, type=%s, checksum=%s, force=%v, message=%s",
						resp.Version, resp.ConfigType, resp.Checksum, resp.ForceReload, resp.Message)

					// 验证配置版本
					if resp.Version <= currentConfigVersion {
						log.Printf("Config version %d is not newer than current %d, skipping", resp.Version, currentConfigVersion)
						continue
					}

					// 验证校验和
					if resp.Checksum != "" {
						calculatedChecksum := calculateChecksum(resp.ConfigData)
						if calculatedChecksum != resp.Checksum {
							log.Printf("Config checksum mismatch: expected=%s, got=%s", resp.Checksum, calculatedChecksum)
							continue
						}
						log.Printf("Config checksum verified: %s", resp.Checksum)
					}

					// 应用配置更新
					if resp.ForceReload || resp.Version > currentConfigVersion {
						err := applyConfigUpdate(resp)
						if err != nil {
							log.Printf("Failed to apply config update: %v", err)

							// 记录失败
							configMutex.Lock()
							configApplyHistory = append(configApplyHistory, ConfigApplyRecord{
								Version:   resp.Version,
								ApplyTime: time.Now(),
								Success:   false,
								Error:     err.Error(),
								Reloaded:  false,
							})
							configMutex.Unlock()
						} else {
							log.Printf("Successfully applied config version %d", resp.Version)

							// 记录成功
							configMutex.Lock()
							configApplyHistory = append(configApplyHistory, ConfigApplyRecord{
								Version:   resp.Version,
								ApplyTime: time.Now(),
								Success:   true,
								Reloaded:  resp.ForceReload,
							})
							currentConfigVersion = resp.Version
							configMutex.Unlock()
						}
					}
				}
			}
		}
	}
}

// calculateChecksum 计算配置数据的校验和
func calculateChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:16]
}

func applyConfigUpdate(resp *pb.ConfigWatchResponse) error {
	// 1. 验证配置类型
	if resp.ConfigType == "" {
		return fmt.Errorf("config type is empty")
	}

	log.Printf("Applying config update: type=%s, version=%d", resp.ConfigType, resp.Version)

	// 2. 备份当前配置
	configMutex.Lock()
	oldConfigBackup, err := json.Marshal(GlobalConfig)
	if err != nil {
		log.Printf("Warning: failed to backup current config: %v", err)
	}
	configMutex.Unlock()

	// 3. 应用配置
	var applyErr error
	switch resp.ConfigType {
	case "cdn":
		applyErr = applyCDNConfig(resp)
	case "tls":
		applyErr = applyTLSConfig(resp)
	case "security":
		applyErr = applySecurityConfig(resp)
	case "routes":
		applyErr = applyRoutesConfig(resp)
	default:
		return fmt.Errorf("unsupported config type: %s", resp.ConfigType)
	}

	// 4. 如果应用失败，尝试回滚
	if applyErr != nil {
		log.Printf("Config apply failed, attempting rollback: %v", applyErr)
		rollbackErr := rollbackConfig(oldConfigBackup)
		if rollbackErr != nil {
			log.Printf("Rollback also failed: %v", rollbackErr)
			return fmt.Errorf("config apply failed: %v, rollback failed: %w", applyErr, rollbackErr)
		}
		log.Printf("Rollback successful")
		return applyErr
	}

	// 5. 验证新配置
	if err := validateAppliedConfig(); err != nil {
		log.Printf("Config validation failed, attempting rollback: %v", err)
		rollbackErr := rollbackConfig(oldConfigBackup)
		if rollbackErr != nil {
			log.Printf("Rollback also failed: %v", rollbackErr)
			return fmt.Errorf("config validation failed: %v, rollback failed: %w", err, rollbackErr)
		}
		log.Printf("Rollback successful")
		return err
	}

	// 6. 如果需要重载，重启相关服务
	if resp.ForceReload {
		if err := reloadServices(); err != nil {
			log.Printf("Warning: failed to reload services: %v", err)
		}
	}

	log.Printf("Config apply completed successfully: type=%s, version=%d", resp.ConfigType, resp.Version)
	return nil
}

// applyCDNConfig 应用CDN配置
func applyCDNConfig(resp *pb.ConfigWatchResponse) error {
	var cdnConfig pb.CDNConfig
	if err := json.Unmarshal(resp.ConfigData, &cdnConfig); err != nil {
		return fmt.Errorf("failed to unmarshal CDN config: %v", err)
	}

	// 验证配置
	if err := validateCDNConfig(&cdnConfig); err != nil {
		return fmt.Errorf("CDN config validation failed: %v", err)
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	// 应用服务器配置
	if cdnConfig.Server != nil {
		if cdnConfig.Server.HttpAddr != "" {
			GlobalConfig.CDN.Server.HTTPAddr = cdnConfig.Server.HttpAddr
		}
		if cdnConfig.Server.HttpsAddr != "" {
			GlobalConfig.CDN.Server.HTTPSAddr = cdnConfig.Server.HttpsAddr
		}
		if cdnConfig.Server.Mode != "" {
			GlobalConfig.CDN.Server.Mode = cdnConfig.Server.Mode
		}
		if cdnConfig.Server.TlsCertFile != "" {
			GlobalConfig.CDN.Server.TLSCertFile = cdnConfig.Server.TlsCertFile
		}
		if cdnConfig.Server.TlsKeyFile != "" {
			GlobalConfig.CDN.Server.TLSKeyFile = cdnConfig.Server.TlsKeyFile
		}
		if cdnConfig.Server.TlsDomain != "" {
			GlobalConfig.CDN.Server.TLSDomain = cdnConfig.Server.TlsDomain
		}
		GlobalConfig.CDN.Server.TLSAutoGen = cdnConfig.Server.TlsAutoGen
	}

	// 应用上游配置（替换而非追加）
	if len(cdnConfig.Upstreams) > 0 {
		GlobalConfig.CDN.Upstreams = make([]config.UpstreamConfig, 0, len(cdnConfig.Upstreams))
		for _, u := range cdnConfig.Upstreams {
			GlobalConfig.CDN.Upstreams = append(GlobalConfig.CDN.Upstreams, config.UpstreamConfig{
				Name:       u.Name,
				Addr:       u.Addr,
				Port:       int(u.Port),
				Weight:     int(u.Weight),
				Enabled:    u.Enabled,
				PathPrefix: u.PathPrefix,
			})
		}
	}

	// 应用负载均衡配置
	if cdnConfig.LoadBalance != nil {
		GlobalConfig.CDN.LoadBalance.Strategy = cdnConfig.LoadBalance.Strategy
		GlobalConfig.CDN.LoadBalance.Sticky = cdnConfig.LoadBalance.Sticky
		GlobalConfig.CDN.LoadBalance.StickyMode = cdnConfig.LoadBalance.StickyMode
		GlobalConfig.CDN.LoadBalance.StickyCookie = cdnConfig.LoadBalance.StickyCookie
		GlobalConfig.CDN.LoadBalance.StickyTimeout = cdnConfig.LoadBalance.StickyTimeout
	}

	// 应用健康检查配置
	if cdnConfig.HealthCheck != nil {
		GlobalConfig.CDN.HealthCheck.Enabled = cdnConfig.HealthCheck.Enabled
		GlobalConfig.CDN.HealthCheck.Interval = int(cdnConfig.HealthCheck.Interval)
		GlobalConfig.CDN.HealthCheck.Timeout = int(cdnConfig.HealthCheck.Timeout)
		GlobalConfig.CDN.HealthCheck.UnhealthyThreshold = int(cdnConfig.HealthCheck.UnhealthyThreshold)
		GlobalConfig.CDN.HealthCheck.HealthyThreshold = int(cdnConfig.HealthCheck.HealthyThreshold)
		GlobalConfig.CDN.HealthCheck.CheckPath = cdnConfig.HealthCheck.CheckPath
		GlobalConfig.CDN.HealthCheck.CheckMethod = cdnConfig.HealthCheck.CheckMethod
		GlobalConfig.CDN.HealthCheck.ExpectedCodes = cdnConfig.HealthCheck.ExpectedCodes
	}

	// 应用安全配置
	if cdnConfig.Security != nil {
		GlobalConfig.CDN.Security.GlobalMaxConnections = int(cdnConfig.Security.GlobalMaxConnections)
		GlobalConfig.CDN.Security.GlobalMaxConnRate = int(cdnConfig.Security.GlobalMaxConnRate)
		GlobalConfig.CDN.Security.PerClientMaxConnections = int(cdnConfig.Security.PerClientMaxConnections)
		GlobalConfig.CDN.Security.PerClientMaxRate = int(cdnConfig.Security.PerClientMaxRate)
		GlobalConfig.CDN.Security.SlowConnectionThreshold = int(cdnConfig.Security.SlowConnectionThreshold)
		GlobalConfig.CDN.Security.SlowReadThreshold = int(cdnConfig.Security.SlowReadThreshold)
		GlobalConfig.CDN.Security.SlowWriteThreshold = int(cdnConfig.Security.SlowWriteThreshold)
		GlobalConfig.CDN.Security.MaxHeaderSize = cdnConfig.Security.MaxHeaderSize
		GlobalConfig.CDN.Security.MaxHeadersCount = int(cdnConfig.Security.MaxHeadersCount)
		GlobalConfig.CDN.Security.MaxRequestBodySize = cdnConfig.Security.MaxRequestBodySize
	}

	// 应用路由配置（替换而非追加）
	if len(cdnConfig.Routes) > 0 {
		GlobalConfig.CDN.Routes = make([]config.RouteConfig, 0, len(cdnConfig.Routes))
		for _, r := range cdnConfig.Routes {
			GlobalConfig.CDN.Routes = append(GlobalConfig.CDN.Routes, config.RouteConfig{
				Name:        r.Name,
				Pattern:     r.Pattern,
				MatchType:   r.MatchType,
				TargetPool:  r.TargetPool,
				Action:      r.Action,
				RedirectURL: r.RedirectUrl,
				Priority:    int(r.Priority),
				Enabled:     r.Enabled,
			})
		}
	}

	return nil
}

// applyTLSConfig 应用TLS配置
func applyTLSConfig(resp *pb.ConfigWatchResponse) error {
	var tlsConfig pb.ServerConfig
	if err := json.Unmarshal(resp.ConfigData, &tlsConfig); err != nil {
		return fmt.Errorf("failed to unmarshal TLS config: %v", err)
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	if tlsConfig.TlsCertFile != "" {
		GlobalConfig.CDN.Server.TLSCertFile = tlsConfig.TlsCertFile
	}
	if tlsConfig.TlsKeyFile != "" {
		GlobalConfig.CDN.Server.TLSKeyFile = tlsConfig.TlsKeyFile
	}
	if tlsConfig.TlsDomain != "" {
		GlobalConfig.CDN.Server.TLSDomain = tlsConfig.TlsDomain
	}
	GlobalConfig.CDN.Server.TLSAutoGen = tlsConfig.TlsAutoGen

	return nil
}

// applySecurityConfig 应用安全配置
func applySecurityConfig(resp *pb.ConfigWatchResponse) error {
	var secConfig pb.SecurityConfig
	if err := json.Unmarshal(resp.ConfigData, &secConfig); err != nil {
		return fmt.Errorf("failed to unmarshal security config: %v", err)
	}

	// 验证配置
	if secConfig.GlobalMaxConnections <= 0 {
		return fmt.Errorf("invalid GlobalMaxConnections: %d", secConfig.GlobalMaxConnections)
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	GlobalConfig.CDN.Security.GlobalMaxConnections = int(secConfig.GlobalMaxConnections)
	GlobalConfig.CDN.Security.GlobalMaxConnRate = int(secConfig.GlobalMaxConnRate)
	GlobalConfig.CDN.Security.PerClientMaxConnections = int(secConfig.PerClientMaxConnections)
	GlobalConfig.CDN.Security.PerClientMaxRate = int(secConfig.PerClientMaxRate)
	GlobalConfig.CDN.Security.SlowConnectionThreshold = int(secConfig.SlowConnectionThreshold)
	GlobalConfig.CDN.Security.SlowReadThreshold = int(secConfig.SlowReadThreshold)
	GlobalConfig.CDN.Security.SlowWriteThreshold = int(secConfig.SlowWriteThreshold)
	GlobalConfig.CDN.Security.MaxHeaderSize = secConfig.MaxHeaderSize
	GlobalConfig.CDN.Security.MaxHeadersCount = int(secConfig.MaxHeadersCount)
	GlobalConfig.CDN.Security.MaxRequestBodySize = secConfig.MaxRequestBodySize

	return nil
}

// applyRoutesConfig 应用路由配置
func applyRoutesConfig(resp *pb.ConfigWatchResponse) error {
	var routes []*pb.RouteConfig
	if err := json.Unmarshal(resp.ConfigData, &routes); err != nil {
		return fmt.Errorf("failed to unmarshal routes config: %v", err)
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	GlobalConfig.CDN.Routes = make([]config.RouteConfig, 0, len(routes))
	for _, r := range routes {
		GlobalConfig.CDN.Routes = append(GlobalConfig.CDN.Routes, config.RouteConfig{
			Name:        r.Name,
			Pattern:     r.Pattern,
			MatchType:   r.MatchType,
			TargetPool:  r.TargetPool,
			Action:      r.Action,
			RedirectURL: r.RedirectUrl,
			Priority:    int(r.Priority),
			Enabled:     r.Enabled,
		})
	}

	return nil
}

// validateCDNConfig 验证CDN配置
func validateCDNConfig(cfg *pb.CDNConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if cfg.Server != nil {
		if cfg.Server.HttpAddr == "" && cfg.Server.HttpsAddr == "" {
			return fmt.Errorf("at least one server address must be specified")
		}
	}

	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream must be configured")
	}

	for _, u := range cfg.Upstreams {
		if u.Addr == "" {
			return fmt.Errorf("upstream address cannot be empty")
		}
		if u.Port <= 0 || u.Port > 65535 {
			return fmt.Errorf("invalid port: %d", u.Port)
		}
		if u.Weight < 0 {
			return fmt.Errorf("weight cannot be negative: %d", u.Weight)
		}
	}

	return nil
}

// validateAppliedConfig 验证已应用的配置
func validateAppliedConfig() error {
	configMutex.RLock()
	defer configMutex.RUnlock()

	if GlobalConfig.CDN.Server.HTTPAddr == "" && GlobalConfig.CDN.Server.HTTPSAddr == "" {
		return fmt.Errorf("no server address configured")
	}

	if len(GlobalConfig.CDN.Upstreams) == 0 {
		return fmt.Errorf("no upstreams configured")
	}

	return nil
}

// rollbackConfig 回滚配置
func rollbackConfig(backup []byte) error {
	if len(backup) == 0 {
		return fmt.Errorf("no backup available")
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	var oldConfig config.Config
	if err := json.Unmarshal(backup, &oldConfig); err != nil {
		return fmt.Errorf("failed to unmarshal backup config: %v", err)
	}

	GlobalConfig = &oldConfig
	return nil
}

// reloadServices 重启服务
func reloadServices() error {
	log.Println("Reloading services...")

	// 重启健康检查器
	if healthChecker != nil {
		healthChecker.Stop()
		time.Sleep(100 * time.Millisecond)
	}

	// 重新初始化健康检查器
	healthChecker = health.NewChecker(
		health.WithHCInterval(time.Duration(GlobalConfig.CDN.HealthCheck.Interval)*time.Second),
		health.WithHCTimeout(time.Duration(GlobalConfig.CDN.HealthCheck.Timeout)*time.Second),
		health.WithHCUnhealthyThreshold(GlobalConfig.CDN.HealthCheck.UnhealthyThreshold),
		health.WithHCHealthyThreshold(GlobalConfig.CDN.HealthCheck.HealthyThreshold),
	)
	ctx := context.Background()
	healthChecker.Start(ctx)

	log.Println("Services reloaded")
	return nil
}

func startHTTPServer(ctx context.Context) {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger())

	// 注册路由
	setupRoutes(router)

	httpServer = &http.Server{
		Addr:    GlobalConfig.CDN.Server.HTTPAddr,
		Handler: router,
	}

	go func() {
		log.Printf("HTTP server starting on %s", GlobalConfig.CDN.Server.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	if httpServer != nil {
		httpServer.Shutdown(context.Background())
	}
	log.Println("HTTP server stopped")
}

func startHTTPSServer(ctx context.Context) {
	if GlobalConfig.CDN.Server.TLSCertFile == "" && !GlobalConfig.CDN.Server.TLSAutoGen {
		log.Println("HTTPS server disabled (no certificate configured)")
		return
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger())

	// HTTPS 路由 - 转发到上游
	router.Any("/*path", handleHTTPSRequest)

	tlsConfig := tlsManager.GetConfig()

	httpsServer = &http.Server{
		Addr:      GlobalConfig.CDN.Server.HTTPSAddr,
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	go func() {
		log.Printf("HTTPS server starting on %s", GlobalConfig.CDN.Server.HTTPSAddr)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	<-ctx.Done()
	if httpsServer != nil {
		httpsServer.Shutdown(context.Background())
	}
	log.Println("HTTPS server stopped")
}

func handleHTTPSRequest(c *gin.Context) {
	clientIP := c.ClientIP()

	// 流量分发
	result, err := distributor.Distribute(c.Request.Context(), &distribute.TrafficContext{
		Request:   c.Request,
		Response:  c.Writer,
		ClientIP:  net.ParseIP(clientIP),
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
		Host:      c.Request.Host,
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		log.Printf("Distribution failed: %v", err)
		c.Status(http.StatusBadGateway)
		return
	}

	if result.Action == distribute.ActionBlock {
		c.Status(http.StatusForbidden)
		return
	}

	if result.Action == distribute.ActionDrop {
		c.Status(http.StatusTooManyRequests)
		return
	}

	// 获取默认集群
	cluster, err := loadBalancer.GetCluster("default")
	if err != nil {
		log.Printf("No backend cluster found: %v", err)
		c.Status(http.StatusBadGateway)
		return
	}

	// 选择后端
	lbReq := &forward.Request{
		IP:     net.ParseIP(clientIP),
		URL:    c.Request.URL.String(),
		Method: c.Request.Method,
	}

	backend, err := cluster.Select(c.Request.Context(), lbReq)
	if err != nil {
		log.Printf("No backend available: %v", err)
		c.Status(http.StatusServiceUnavailable)
		return
	}

	// 创建代理请求
	targetURL := *c.Request.URL
	targetURL.Scheme = "http"
	targetURL.Host = backend.Addr()

	proxyReq, err := http.NewRequest(c.Request.Method, targetURL.String(), c.Request.Body)
	if err != nil {
		log.Printf("Failed to create proxy request: %v", err)
		c.Status(http.StatusBadGateway)
		return
	}

	// 复制请求头
	for k, v := range c.Request.Header {
		proxyReq.Header[k] = v
	}

	// 添加 X-Forwarded-* 头
	proxyReq.Header.Set("X-Forwarded-For", clientIP)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	proxyReq.Header.Set("X-Forwarded-Host", c.Request.Host)

	// 移除 hop-by-hop 头
	for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade"} {
		proxyReq.Header.Del(h)
	}

	// 发送请求
	startTime := time.Now()
	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		log.Printf("Proxy request failed: %v", err)
		c.Status(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	latency := time.Since(startTime).Milliseconds()
	log.Printf("Request proxied to %s, latency: %dms", backend.Addr(), latency)

	// 复制响应头
	for k, v := range resp.Header {
		for _, vv := range v {
			c.Writer.Header().Add(k, vv)
		}
	}

	// 设置状态码
	c.Writer.WriteHeader(resp.StatusCode)

	// 复制响应体
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		log.Printf("Failed to copy response: %v", err)
	}
}

func startBackgroundServices(ctx context.Context) {
	// 启动健康检查
	if GlobalConfig.CDN.HealthCheck.Enabled {
		healthChecker.Start(ctx)
	}

	// 启动故障转移监控
	group, _ := failoverMgr.GetGroup("default")
	if group != nil && GlobalConfig.CDN.Failover.Enabled {
		group.StartMonitoring(ctx)
	}

	// 定期任务
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runPeriodicTasks()
		}
	}
}

func runPeriodicTasks() {
	// 更新健康状态到负载均衡器
	if GlobalConfig.CDN.HealthCheck.Enabled {
		statuses := healthChecker.GetAllStatus()
		for _, status := range statuses {
			log.Printf("Health status for %s: %s", status.Target, status.Status)
		}
	}
}

func stopComponents() {
	if healthChecker != nil {
		healthChecker.Stop()
	}
	if protectionEng != nil {
		protectionEng.Stop()
	}
	if connPool != nil {
		connPool.Close()
	}
	if tlsManager != nil {
		tlsManager.Stop()
	}
	if masterConn != nil {
		masterConn.Close()
	}
}

func setupRoutes(router *gin.Engine) {
	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": Version,
			"node_id": nodeID,
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ready": true})
	})

	// API路由组
	api := router.Group("/api/v1")
	{
		api.GET("/status", getStatus)
		api.GET("/metrics", getMetrics)
		api.GET("/health/status", getHealthStatus)
	}
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		log.Printf("%s %s %d %v", method, path, status, latency)
	}
}

func getStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"node_id":   nodeID,
		"node_name": nodeName,
		"status":    "online",
		"version":   Version,
	})
}

func getMetrics(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := gin.H{
		"node_id":   nodeID,
		"timestamp": time.Now().Unix(),
		"system": gin.H{
			"cpu_usage":    0.5,
			"memory_usage": float64(m.Alloc) / float64(m.Sys),
			"goroutines":   runtime.NumGoroutine(),
		},
		"network": gin.H{
			"bytes_in":     0,
			"bytes_out":    0,
			"active_conns": 0,
		},
		"cdn": gin.H{
			"total_requests": 0,
		},
	}

	c.JSON(http.StatusOK, metrics)
}

func getHealthStatus(c *gin.Context) {
	if healthChecker == nil {
		c.JSON(http.StatusOK, gin.H{"status": "unknown"})
		return
	}

	statuses := healthChecker.GetAllStatus()
	result := make([]map[string]interface{}, 0, len(statuses))
	for _, s := range statuses {
		result = append(result, map[string]interface{}{
			"target":    s.Target,
			"status":    s.Status,
			"latency":   s.Latency,
			"timestamp": s.Timestamp,
		})
	}
	c.JSON(http.StatusOK, gin.H{"targets": result})
}

// gRPC拦截器
func authInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+GlobalConfig.Node.Token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func authStreamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+GlobalConfig.Node.Token)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// 辅助函数
func generateNodeID() string {
	hostname := getHostname()
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%s-%d", hostname, timestamp)
}

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no local IP found")
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

// consoleLogger 日志实现
type consoleLogger struct{}

func (l *consoleLogger) Debug(args ...interface{}) {
	log.Println(args...)
}
func (l *consoleLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}
func (l *consoleLogger) Info(args ...interface{}) {
	log.Println(args...)
}
func (l *consoleLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}
func (l *consoleLogger) Warn(args ...interface{}) {
	log.Println(args...)
}
func (l *consoleLogger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}
func (l *consoleLogger) Error(args ...interface{}) {
	log.Println(args...)
}
func (l *consoleLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

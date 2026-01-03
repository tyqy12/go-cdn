package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
)

// CDN核心版本
const Version = "2.0.0"

// 全局配置
var GlobalConfig *Config

// Config CDN系统配置
type Config struct {
	// 服务配置
	Server struct {
		HTTPAddr  string `yaml:"http_addr"`
		HTTPSAddr string `yaml:"https_addr"`
		GRPCAddr  string `yaml:"grpc_addr"`
		Mode      string `yaml:"mode"` // debug, release
	}

	// 数据库配置
	Database struct {
		Type     string `yaml:"type"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
	}

	// Redis配置
	Redis struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
		PoolSize int    `yaml:"pool_size"`
	}

	// 日志配置
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"` // json, text
		Output string `yaml:"output"` // file, stdout
		Path   string `yaml:"path"`
	}

	// 功能开关
	Features struct {
		IPLibrary        bool `yaml:"ip_library"`
		HTTP3            bool `yaml:"http3"`
		Performance      bool `yaml:"performance"`
		StatsDashboard   bool `yaml:"stats_dashboard"`
		FiveSecondShield bool `yaml:"five_second_shield"`
		CCProtection     bool `yaml:"cc_protection"`
		L2Nodes          bool `yaml:"l2_nodes"`
		URLAuth          bool `yaml:"url_auth"`
		DNSScheduling    bool `yaml:"dns_scheduling"`
		LogExport        bool `yaml:"log_export"`
		BatchOperation   bool `yaml:"batch_operation"`
		ObjectStorage    bool `yaml:"object_storage"`
		Notification     bool `yaml:"notification"`
		EdgeComputing    bool `yaml:"edge_computing"`
		HLSEncryption    bool `yaml:"hls_encryption"`
		Billing          bool `yaml:"billing"`
		HighDefenseIP    bool `yaml:"high_defense_ip"`
		SmartDNS         bool `yaml:"smart_dns"`
		Monitor          bool `yaml:"monitor"`
	}
}

func main() {
	// 加载配置
	GlobalConfig = loadConfig()
	
	// 设置运行模式
	if GlobalConfig.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建主上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动服务
	go startHTTPServer(ctx)
	go startGRPCServer(ctx)
	
	// 启动后台服务
	go startBackgroundServices(ctx)

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭服务...")
	cancel()
	time.Sleep(2 * time.Second)
	log.Println("服务已关闭")
}

func loadConfig() *Config {
	// 加载YAML配置
	config := &Config{}
	
	// 默认配置
	config.Server.HTTPAddr = ":8080"
	config.Server.GRPCAddr = ":50051"
	config.Server.Mode = "debug"
	
	config.Database.Type = "mongodb"
	config.Database.Host = "localhost"
	config.Database.Port = 27017
	config.Database.Name = "ai-cdn"
	
	config.Redis.Host = "localhost"
	config.Redis.Port = 6379
	config.Redis.DB = 0
	config.Redis.PoolSize = 100
	
	config.Logging.Level = "info"
	config.Logging.Format = "json"
	config.Logging.Output = "stdout"
	
	// 功能开关默认值
	config.Features.IPLibrary = true
	config.Features.HTTP3 = true
	config.Features.Performance = true
	config.Features.StatsDashboard = true
	config.Features.CCProtection = true
	config.Features.L2Nodes = true
	config.Features.URLAuth = true
	config.Features.DNSScheduling = true
	config.Features.LogExport = true
	config.Features.ObjectStorage = true
	
	// 读取配置文件
	configPath := os.Getenv("CDN_CONFIG_PATH")
	if configPath == "" {
		configPath = "config/cdn.yml"
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("警告: 无法读取配置文件 %s，使用默认配置: %v", configPath, err)
		return config
	}
	
	// 解析YAML
	if err := yaml.Unmarshal(data, config); err != nil {
		log.Printf("警告: 配置文件解析失败，使用默认配置: %v", err)
		return config
	}
	
	log.Printf("配置加载成功: %s", configPath)
	return config
}

func startHTTPServer(ctx context.Context) {
	router := gin.New()
	router.Use(gin.Recovery())
	
	// 注册路由
	setupRoutes(router)
	
	srv := &http.Server{
		Addr:    GlobalConfig.Server.HTTPAddr,
		Handler: router,
	}

	go func() {
		log.Printf("HTTP服务器启动在 %s", GlobalConfig.Server.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP服务器错误: %v", err)
		}
	}()

	<-ctx.Done()
	srv.Shutdown(context.Background())
}

func startGRPCServer(ctx context.Context) {
	// gRPC服务器配置
	grpcAddr := GlobalConfig.Server.GRPCAddr
	if grpcAddr == "" {
		grpcAddr = ":50051"
	}
	
	// 创建监听器
	listener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Printf("gRPC监听器创建失败: %v", err)
		return
	}
	
	// 创建gRPC服务器
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor),
	)
	
	// 注册服务（需要导入相应的服务包）
	// master.RegisterMasterServiceServer(grpcServer, &masterServer{})
	// agent.RegisterAgentServiceServer(grpcServer, &agentServer{})
	
	log.Printf("gRPC服务器启动在 %s", grpcAddr)
	
	// 启动服务器
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Printf("gRPC服务器错误: %v", err)
		}
	}()
	
	// 等待上下文取消
	<-ctx.Done()
	grpcServer.GracefulStop()
	log.Println("gRPC服务器已停止")
}

// loggingInterceptor 日志拦截器
func loggingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	latency := time.Since(start)
	
	if err != nil {
		log.Printf("gRPC调用失败: %s, 耗时: %v, 错误: %v", info.FullMethod, latency, err)
	} else {
		log.Printf("gRPC调用成功: %s, 耗时: %v", info.FullMethod, latency)
	}
	
	return resp, err
}

func startBackgroundServices(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 定期执行后台任务
			runPeriodicTasks()
		}
	}
}

func setupRoutes(router *gin.Engine) {
	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": Version})
	})

	// API路由组
	api := router.Group("/api/v1")
	{
		// 节点管理
		api.GET("/nodes", listNodes)
		api.POST("/nodes", createNode)
		api.PUT("/nodes/:id", updateNode)
		api.DELETE("/nodes/:id", deleteNode)
		
		// 配置管理
		api.GET("/configs", listConfigs)
		api.POST("/configs", createConfig)
		
		// 监控数据
		api.GET("/metrics", getMetrics)
		
		// 统计看板
		api.GET("/stats/dashboard", getDashboardStats)
		
		// 防护设置
		api.POST("/security/cc-protection", configCCProtection)
		api.POST("/security/five-second-shield", configFiveSecondShield)
		
		// IP库查询
		api.GET("/ip/query", queryIPInfo)
		
		// 日志导出
		api.GET("/logs/export", exportLogs)
		
		// 批量操作
		api.POST("/batch/nodes", batchOperationNodes)
		
		// 计费管理
		api.GET("/billing/plans", getBillingPlans)
		api.GET("/billing/usage", getUsageStats)
		
		// DNS调度
		api.GET("/dns/records", getDNSRecords)
		api.POST("/dns/scheduling", configDNSScheduling)
		
		// 对象存储
		api.GET("/storage/buckets", listBuckets)
		
		// 消息通知
		api.GET("/notifications", listNotifications)
		
		// 边缘运算
		api.GET("/edge/functions", listEdgeFunctions)
		
		// HLS加密
		api.POST("/hls/encrypt", encryptHLS)
		api.POST("/hls/decrypt", decryptHLS)
		
		// 高防IP
		api.GET("/defense/ips", listDefenseIPs)
		
		// 可访问性监控
		api.GET("/monitor/sites", listMonitoredSites)
		api.POST("/monitor/check", triggerCheck)
	}
}

func runPeriodicTasks() {
	// 定期任务
	log.Println("执行定期任务...")
}

// 处理器函数
func listNodes(c *gin.Context)       { c.JSON(200, gin.H{"nodes": []string{}}) }
func createNode(c *gin.Context)      { c.JSON(201, gin.H{"status": "created"}) }
func updateNode(c *gin.Context)      { c.JSON(200, gin.H{"status": "updated"}) }
func deleteNode(c *gin.Context)      { c.JSON(200, gin.H{"status": "deleted"}) }
func listConfigs(c *gin.Context)     { c.JSON(200, gin.H{"configs": []string{}}) }
func createConfig(c *gin.Context)    { c.JSON(201, gin.H{"status": "created"}) }
func getMetrics(c *gin.Context)      { c.JSON(200, gin.H{"metrics": "data"}) }
func getDashboardStats(c *gin.Context) { c.JSON(200, gin.H{"stats": "dashboard"}) }
func configCCProtection(c *gin.Context) { c.JSON(200, gin.H{"status": "configured"}) }
func configFiveSecondShield(c *gin.Context) { c.JSON(200, gin.H{"status": "configured"}) }
func queryIPInfo(c *gin.Context)     { c.JSON(200, gin.H{"ip_info": "data"}) }
func exportLogs(c *gin.Context)      { c.JSON(200, gin.H{"download_url": "url"}) }
func batchOperationNodes(c *gin.Context) { c.JSON(200, gin.H{"status": "completed"}) }
func getBillingPlans(c *gin.Context) { c.JSON(200, gin.H{"plans": []string{}}) }
func getUsageStats(c *gin.Context)   { c.JSON(200, gin.H{"usage": "data"}) }
func getDNSRecords(c *gin.Context)   { c.JSON(200, gin.H{"records": []string{}}) }
func configDNSScheduling(c *gin.Context) { c.JSON(200, gin.H{"status": "configured"}) }
func listBuckets(c *gin.Context)     { c.JSON(200, gin.H{"buckets": []string{}}) }
func listNotifications(c *gin.Context) { c.JSON(200, gin.H{"notifications": []string{}}) }
func listEdgeFunctions(c *gin.Context) { c.JSON(200, gin.H{"functions": []string{}}) }
func encryptHLS(c *gin.Context)      { c.JSON(200, gin.H{"status": "encrypted"}) }
func decryptHLS(c *gin.Context)      { c.JSON(200, gin.H{"status": "decrypted"}) }
func listDefenseIPs(c *gin.Context)  { c.JSON(200, gin.H{"ips": []string{}}) }
func listMonitoredSites(c *gin.Context) { c.JSON(200, gin.H{"sites": []string{}}) }
func triggerCheck(c *gin.Context)    { c.JSON(200, gin.H{"status": "checking"}) }

func init() {
	fmt.Println("CDN系统启动初始化...")
}

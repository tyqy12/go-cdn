package main

import (
	"context"
	"flag"
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
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/ai-cdn-tunnel/master/config"
	"github.com/ai-cdn-tunnel/master/db"
	"github.com/ai-cdn-tunnel/master/handler"
	"github.com/ai-cdn-tunnel/master/ha"
	"github.com/ai-cdn-tunnel/master/monitor"
	"github.com/ai-cdn-tunnel/master/node"
	pb "github.com/ai-cdn-tunnel/proto/agent"
)

var (
	configPath  string
	httpAddr    string
	grpcAddr    string
	metricsAddr string
	nodeID      string
	enableHA    bool
)

func init() {
	flag.StringVar(&configPath, "config", "master.yml", "config file path")
	flag.StringVar(&httpAddr, "http", ":8080", "http server address")
	flag.StringVar(&grpcAddr, "grpc", ":50051", "grpc server address")
	flag.StringVar(&metricsAddr, "metrics", ":9090", "metrics server address")
	flag.StringVar(&nodeID, "node-id", generateNodeID(), "node ID for HA election")
	flag.BoolVar(&enableHA, "ha", true, "enable high availability leader election")
}

func main() {
	flag.Parse()

	// 生成节点ID
	if nodeID == "" {
		nodeID = generateNodeID()
	}

	log.Printf("Starting GoCDN Master, node ID: %s", nodeID)

	// 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		handleError("Failed to load config", err)
	}

	// 初始化数据库
	database, err := db.NewMongoDB(cfg.MongoURI)
	if err != nil {
		handleError("Failed to connect to MongoDB", err)
	}
	defer database.Close()

	// 初始化节点管理器
	nodeMgr := node.NewManager(database)

	// 初始化监控器
	monitorMgr := monitor.NewMonitor(database)

	// 初始化高可用选举
	var election *ha.LeaderElection
	if enableHA {
		electionConfig := ha.DefaultElectionConfig(nodeID)
		electionConfig.LeaseTTL = 30 * time.Second
		electionConfig.RetryInterval = 5 * time.Second
		electionConfig.Timeout = 10 * time.Second

		election = ha.NewLeaderElection(electionConfig, database)

		// 设置当选和撤销回调
		election.OnElected(func() {
			log.Printf("[HA] This node (%s) is now the leader", nodeID)
			// 当选为领导者后可以执行初始化操作
		})

		election.OnRevoked(func() {
			log.Printf("[HA] This node (%s) is no longer the leader", nodeID)
			// 失去领导者身份后可以执行清理操作
		})

		// 启动选举
		election.Start()
		log.Printf("[HA] Leader election started")
	}

	// 创建gRPC服务器
	grpcServer := createGRPCServer(nodeMgr, monitorMgr, database)

	// 创建HTTP服务器
	httpServer := createHTTPServer(nodeMgr, monitorMgr, database, cfg)

	// 启动gRPC服务
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		handleError("Failed to listen on gRPC port", err)
	}
	go func() {
		log.Printf("gRPC server listening on %s", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// 启动HTTP服务
	go func() {
		log.Printf("HTTP server listening on %s", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// 启动监控采集
	go monitorMgr.StartCollecting()

	// 等待关闭信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")

	// 停止高可用选举
	if election != nil {
		log.Println("Stopping leader election...")
		election.Stop()
	}

	grpcServer.GracefulStop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)

	log.Println("Servers stopped")
}

// handleError 处理致命错误
func handleError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", msg, err)
	os.Exit(1)
}

// generateNodeID 生成唯一节点ID
func generateNodeID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("master-%s-%d", hostname, os.Getpid())
}

func createGRPCServer(nodeMgr *node.Manager, monitorMgr *monitor.Monitor, database *db.MongoDB) *grpc.Server {
	// 配置keepalive
	kaParams := keepalive.ServerParameters{
		MaxConnectionIdle:     5 * time.Minute,
		MaxConnectionAge:      30 * time.Minute,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  1 * time.Minute,
		Timeout:               20 * time.Second,
	}

	// 创建gRPC服务器
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(kaParams),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	// 注册Agent服务
	agentServer := handler.NewAgentServer(nodeMgr, monitorMgr)
	agentServer.SetDatabase(database)
	pb.RegisterAgentServiceServer(grpcServer, agentServer)

	// 注册健康检查
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("agent", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// 启用反射
	reflection.Register(grpcServer)

	return grpcServer
}

func createHTTPServer(nodeMgr *node.Manager, monitorMgr *monitor.Monitor, database *db.MongoDB, cfg *config.Config) *http.Server {
	r := gin.Default()

	// 中间件
	r.Use(gin.Recovery())
	r.Use(handler.CORS())
	r.Use(handler.Logger())

	// 认证中间件
	if cfg.JWTSecret != "" {
		r.Use(handler.JWTAuth(cfg.JWTSecret))
	}

	// API路由
	api := r.Group("/api/v1")
	{
		// 节点管理
		nodes := api.Group("/nodes")
		nodes.GET("", handler.ListNodes(nodeMgr))
		nodes.GET("/:id", handler.GetNode(nodeMgr))
		nodes.PUT("/:id", handler.UpdateNode(nodeMgr))
		nodes.DELETE("/:id", handler.DeleteNode(nodeMgr))
		nodes.GET("/:id/status", handler.GetNodeStatus(nodeMgr))
		nodes.POST("/:id/restart", handler.RestartNode(nodeMgr))

		// 节点部署脚本
		deploy := nodes.Group("/deploy-script")
		deploy.POST("", handler.GenerateDeployScript)
		deploy.GET("/:scriptID", handler.GetDeployScript)
		deploy.GET("/:scriptID/download", handler.DownloadScript)

		// 快速安装
		nodes.POST("/quick-install", handler.QuickInstall)

		// 指令管理
		commands := api.Group("/commands")
		commands.POST("", handler.ExecuteCommand(nodeMgr, database))
		commands.GET("/:task_id", handler.GetCommandStatus(nodeMgr, database))
		commands.GET("", handler.ListCommandHistory(database))

		// 监控数据
		metrics := api.Group("/metrics")
		metrics.GET("/nodes/:id", handler.GetNodeMetrics(monitorMgr))
		metrics.GET("/aggregate", handler.GetAggregateMetrics(monitorMgr))

		// 告警
		alerts := api.Group("/alerts")
		alerts.GET("", handler.ListAlerts(database))
		alerts.GET("/:id", handler.GetAlert(database))
		alerts.POST("/:id/silence", handler.SilenceAlert(database))
	}

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return &http.Server{
		Addr:    httpAddr,
		Handler: r,
	}
}

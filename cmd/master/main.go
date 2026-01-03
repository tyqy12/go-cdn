package main

import (
    "context"
    "flag"
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

    pb "github.com/ai-cdn-tunnel/proto/agent"
    "github.com/ai-cdn-tunnel/master/config"
    "github.com/ai-cdn-tunnel/master/db"
    "github.com/ai-cdn-tunnel/master/handler"
    "github.com/ai-cdn-tunnel/master/node"
    "github.com/ai-cdn-tunnel/master/monitor"
)

var (
    configPath  string
    httpAddr    string
    grpcAddr    string
    metricsAddr string
)

func init() {
    flag.StringVar(&configPath, "config", "master.yml", "config file path")
    flag.StringVar(&httpAddr, "http", ":8080", "http server address")
    flag.StringVar(&grpcAddr, "grpc", ":50051", "grpc server address")
    flag.StringVar(&metricsAddr, "metrics", ":9090", "metrics server address")
}

func main() {
    flag.Parse()

    // 加载配置
    cfg, err := config.Load(configPath)
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 初始化数据库
    database, err := db.NewMongoDB(cfg.MongoURI)
    if err != nil {
        log.Fatalf("Failed to connect to MongoDB: %v", err)
    }
    defer database.Close()

    // 初始化节点管理器
    nodeMgr := node.NewManager(database)

    // 初始化监控器
    monitorMgr := monitor.NewMonitor(database)

    // 创建gRPC服务器
    grpcServer := createGRPCServer(nodeMgr, monitorMgr)

    // 创建HTTP服务器
    httpServer := createHTTPServer(nodeMgr, monitorMgr, cfg)

    // 启动gRPC服务
    lis, err := net.Listen("tcp", grpcAddr)
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }
    go func() {
        log.Printf("gRPC server listening on %s", grpcAddr)
        if err := grpcServer.Serve(lis); err != nil {
            log.Fatalf("Failed to serve gRPC: %v", err)
        }
    }()

    // 启动HTTP服务
    go func() {
        log.Printf("HTTP server listening on %s", httpAddr)
        if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Failed to serve HTTP: %v", err)
        }
    }()

    // 启动监控采集
    go monitorMgr.StartCollecting()

    // 优雅关闭
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down servers...")

    grpcServer.GracefulStop()
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    httpServer.Shutdown(ctx)

    log.Println("Servers stopped")
}

func createGRPCServer(nodeMgr *node.Manager, monitorMgr *monitor.Monitor) *grpc.Server {
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

func createHTTPServer(nodeMgr *node.Manager, monitorMgr *monitor.Monitor, cfg *config.Config) *http.Server {
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
        nodes.POST("/:id/tags", handler.UpdateNodeTags(nodeMgr))
        nodes.POST("/:id/online", handler.OnlineNode(nodeMgr))
        nodes.POST("/:id/offline", handler.OfflineNode(nodeMgr))

        // 节点部署脚本
        deploy := nodes.Group("/deploy-script")
        deploy.POST("", handler.GenerateDeployScript)
        deploy.GET("/:scriptID", handler.GetDeployScript)
        deploy.GET("/:scriptID/download", handler.DownloadScript)

        // 快速安装
        nodes.POST("/quick-install", handler.QuickInstall)

        // 配置管理
        configs := api.Group("/configs")
        configs.GET("", handler.ListConfigs(nodeMgr))
        configs.GET("/:version", handler.GetConfig(nodeMgr))
        configs.POST("", handler.CreateConfig(nodeMgr))
        configs.POST("/:version/publish", handler.PublishConfig(nodeMgr))
        configs.POST("/:version/rollback", handler.RollbackConfig(nodeMgr))

        // 指令管理
        commands := api.Group("/commands")
        commands.POST("", handler.ExecuteCommand(nodeMgr))
        commands.GET("/:task_id", handler.GetCommandStatus(nodeMgr))

        // 监控数据
        metrics := api.Group("/metrics")
        metrics.GET("/nodes/:id", handler.GetNodeMetrics(monitorMgr))
        metrics.GET("/aggregate", handler.GetAggregateMetrics(monitorMgr))

        // 告警
        alerts := api.Group("/alerts")
        alerts.GET("", handler.ListAlerts(monitorMgr))
        alerts.GET("/:id", handler.GetAlert(monitorMgr))
        alerts.POST("/:id/silence", handler.SilenceAlert(monitorMgr))
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

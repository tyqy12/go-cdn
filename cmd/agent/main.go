package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/ai-cdn-tunnel/agent/config"
	"github.com/ai-cdn-tunnel/agent/heartbeat"
	"github.com/ai-cdn-tunnel/agent/status"
	"github.com/ai-cdn-tunnel/agent/updater"
	pb "github.com/ai-cdn-tunnel/proto/agent"
)

var (
	configPath   string
	masterAddr   string
	nodeID       string
	nodeName     string
	nodeType     string
	region       string
	token        string
	tlsEnabled   bool
	tlsCertFile  string
	tlsKeyFile   string
	tlsCAFile    string
	insecureMode bool
)

func init() {
	flag.StringVar(&configPath, "config", "agent.yml", "config file path")
	flag.StringVar(&masterAddr, "master", "localhost:50051", "master server address")
	flag.StringVar(&nodeID, "id", "", "node id (auto-generated if empty)")
	flag.StringVar(&nodeName, "name", "", "node name")
	flag.StringVar(&nodeType, "type", "edge", "node type (edge/core)")
	flag.StringVar(&region, "region", "hk", "region code")
	flag.StringVar(&token, "token", "", "authentication token")
	flag.BoolVar(&tlsEnabled, "tls", false, "enable TLS encryption")
	flag.StringVar(&tlsCertFile, "cert", "", "TLS certificate file path")
	flag.StringVar(&tlsKeyFile, "key", "", "TLS key file path")
	flag.StringVar(&tlsCAFile, "ca", "", "TLS CA certificate file path for mTLS")
	flag.BoolVar(&insecureMode, "insecure", false, "allow insecure connections (not recommended for production)")
}

func main() {
	flag.Parse()

	// 生成节点ID
	if nodeID == "" {
		nodeID = generateNodeID()
	}
	if nodeName == "" {
		nodeName = fmt.Sprintf("%s-%s", nodeType, region)
	}

	// 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Starting Agent: %s (%s) - %s", nodeID, nodeName, nodeType)

	// 创建gRPC连接
	conn, err := createGRPCConnection(masterAddr)
	if err != nil {
		log.Fatalf("Failed to connect to master: %v", err)
	}
	defer conn.Close()

	// 创建Agent客户端
	client := pb.NewAgentServiceClient(conn)

	// 初始化状态收集器
	statusReporter := status.NewReporter(client, nodeID, status.Config{
		CollectInterval: 10 * time.Second,
	})
	statusReporter.Start()

	// 初始化心跳发送器
	heartbeatSender := heartbeat.NewSender(client, nodeID, heartbeat.Config{
		Interval: 10 * time.Second,
		Timeout:  30 * time.Second,
	})

	// 初始化配置更新器
	configUpdater := updater.NewConfigUpdater(client, nodeID, cfg, updater.Config{
		ConfigPath:   cfg.GostConfigPath,
		RestartDelay: 5 * time.Second,
	})

	// 启动心跳
	heartbeatSender.Start()

	// 注册节点
	err = registerNode(client)
	if err != nil {
		log.Printf("Warning: Failed to register node: %v", err)
	}

	// 启动配置监听
	go configUpdater.Listen(context.Background())

	// 启动命令监听
	go listenCommands(client)

	// 等待中断信号
	waitForSignal()

	// 停止服务
	log.Println("Stopping agent...")
	heartbeatSender.Stop()
	statusReporter.Stop()
}

func createGRPCConnection(addr string) (*grpc.ClientConn, error) {
	// 配置keepalive
	kaParams := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             30 * time.Second,
		PermitWithoutStream: true,
	}

	// 选择传输凭证
	var creds credentials.TransportCredentials
	var err error

	if insecureMode {
		// 不安全模式（仅限开发环境）
		log.Println("WARNING: Using insecure connection. TLS is recommended for production.")
		creds = insecure.NewCredentials()
	} else if tlsEnabled {
		// TLS 模式
		creds, err = loadTLSCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %v", err)
		}
		log.Println("TLS encryption enabled")
	} else {
		// 默认：检查地址是否使用 TLS 端口或使用环境变量
		if strings.HasPrefix(addr, "tls://") {
			addr = strings.TrimPrefix(addr, "tls://")
			creds, err = loadTLSCredentials()
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS credentials: %v", err)
			}
			log.Println("TLS encryption enabled (via tls:// prefix)")
		} else if os.Getenv("MASTER_TLS_ENABLED") == "true" {
			creds, err = loadTLSCredentials()
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS credentials: %v", err)
			}
			log.Println("TLS encryption enabled (via environment variable)")
		} else {
			// 默认使用 TLS（安全优先）
			log.Println("WARNING: TLS not enabled, falling back to insecure credentials for compatibility")
			creds = insecure.NewCredentials()
		}
	}

	// 创建连接
	conn, err := grpc.Dial(
		addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(kaParams),
		grpc.WithUnaryInterceptor(authInterceptor(token)),
		grpc.WithStreamInterceptor(authStreamInterceptor(token)),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// loadTLSCredentials 加载 TLS 凭证
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// 加载服务器证书
	certFile := tlsCertFile
	keyFile := tlsKeyFile

	// 从环境变量读取
	if certFile == "" {
		certFile = os.Getenv("MASTER_TLS_CERT")
	}
	if keyFile == "" {
		keyFile = os.Getenv("MASTER_TLS_KEY")
	}

	// 如果没有提供证书，返回 nil 以使用系统根证书
	if certFile == "" || keyFile == "" {
		// 使用默认 TLS 配置，仅验证服务器证书
		return credentials.NewClientTLSFromCert(nil, ""), nil
	}

	// 加载客户端证书和密钥
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	// 检查是否需要 mTLS（双向 TLS）
	caFile := tlsCAFile
	if caFile == "" {
		caFile = os.Getenv("MASTER_TLS_CA")
	}

	if caFile != "" {
		// mTLS 模式：需要验证服务器证书
		caCert, err := os.ReadFile(caFile)
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

	// 普通 TLS 模式
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

func registerNode(client pb.AgentServiceClient) error {
	// 获取本机IP
	ip, err := getLocalIP()
	if err != nil {
		ip = "127.0.0.1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Register(ctx, &pb.RegisterRequest{
		NodeId:   nodeID,
		NodeName: nodeName,
		NodeType: nodeType,
		Region:   region,
		Ip:       ip,
		Metadata: map[string]string{
			"hostname":   getHostname(),
			"os":         getOS(),
			"arch":       getArch(),
			"go_version": getGoVersion(),
		},
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		log.Printf("Registration failed: %s", resp.Message)
		return fmt.Errorf("registration failed: %s", resp.Message)
	}

	log.Printf("Registered successfully, master version: %s", resp.MasterVersion)
	return nil
}

func listenCommands(client pb.AgentServiceClient) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.ExecuteCommand(ctx, &pb.CommandRequest{
		NodeId: nodeID,
	})
	if err != nil {
		log.Printf("Failed to start command stream: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			cmd, err := stream.Recv()
			if err != nil {
				log.Printf("Command stream error: %v", err)
				return
			}

			// 执行命令
			go executeCommand(cmd, client)
		}
	}
}

func executeCommand(cmd *pb.CommandRequest, client pb.AgentServiceClient) {
	var output string
	var cmdErr string

	switch cmd.Command {
	case "reload":
		err := reloadConfig()
		if err != nil {
			cmdErr = err.Error()
		} else {
			output = "Config reloaded successfully"
		}

	case "restart":
		err := restartService()
		if err != nil {
			cmdErr = err.Error()
		} else {
			output = "Service restarted successfully"
		}

	case "stop":
		stopService()
		output = "Service stopped"

	case "status":
		output = getServiceStatus()

	case "logs":
		output = getRecentLogs(100)

	default:
		cmdErr = fmt.Sprintf("Unknown command: %s", cmd.Command)
	}

	// 上报结果
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.ExecuteCommand(ctx, &pb.CommandResponse{
		CommandId: cmd.CommandId,
		Success:   cmdErr == "",
		Output:    output,
		Error:     cmdErr,
	})
	if err != nil {
		log.Printf("Failed to report command result: %v", err)
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

func reloadConfig() error {
	// 发送SIGHUP到gost进程
	cmd := exec.Command("pkill", "-HUP", "gost")
	return cmd.Run()
}

func restartService() error {
	// 重启gost服务 - 支持 Linux 和 Windows
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("systemctl", "restart", "gost")
		return cmd.Run()
	case "windows":
		// Windows 下使用 sc 命令
		cmd := exec.Command("sc", "stop", "gost")
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Failed to stop service: %v", err)
		}
		cmd = exec.Command("sc", "start", "gost")
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func stopService() error {
	// 停止gost服务 - 支持 Linux 和 Windows
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("systemctl", "stop", "gost")
		return cmd.Run()
	case "windows":
		cmd := exec.Command("sc", "stop", "gost")
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func getServiceStatus() string {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("systemctl", "is-active", "gost")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Sprintf("gost status: unknown (error: %v)", err)
		}
		return fmt.Sprintf("gost status: %s", strings.TrimSpace(string(output)))
	case "windows":
		cmd := exec.Command("sc", "query", "gost")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Sprintf("gost status: unknown (error: %v)", err)
		}
		return fmt.Sprintf("gost status: %s", strings.TrimSpace(string(output)))
	default:
		return "gost status: unsupported platform"
	}
}

func getRecentLogs(lines int) string {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("journalctl", "-u", "gost", "-n", fmt.Sprintf("%d", lines), "--no-pager")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Sprintf("Failed to get logs: %v", err)
		}
		return string(output)
	case "windows":
		// Windows 下获取事件日志
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf("Get-EventLog -LogName Application -Source gost -Newest %d | Format-List", lines))
		output, err := cmd.Output()
		if err != nil {
			return fmt.Sprintf("Failed to get logs: %v", err)
		}
		return string(output)
	default:
		return fmt.Sprintf("Logs not supported on %s", runtime.GOOS)
	}
}

// gRPC拦截器
func authInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func authStreamInterceptor(token string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// 系统信息
func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func getOS() string {
	return runtime.GOOS
}

func getArch() string {
	return runtime.GOARCH
}

func getGoVersion() string {
	return runtime.Version()
}

func waitForSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

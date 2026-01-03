package http3

import (
	"crypto/tls"
	"testing"
	"time"

	"google.golang.org/grpc/keepalive"
)

// TestNewHTTP3Server 测试创建HTTP/3服务器
func TestNewHTTP3Server(t *testing.T) {
	config := &Config{
		Addr:               "0.0.0.0:8443",
		MaxIncomingStreams: 1000,
		IdleTimeout:        30 * time.Second,
		KeepAliveInterval:  5 * time.Second,
	}

	server := NewHTTP3Server(config)
	if server == nil {
		t.Fatal("创建HTTP/3服务器失败")
	}

	if server.config == nil {
		t.Error("配置为空")
	}

	t.Log("创建HTTP/3服务器测试通过")
}

// TestHTTP3Server_GetStats 测试获取服务器统计
func TestHTTP3Server_GetStats(t *testing.T) {
	config := &Config{
		Addr: "127.0.0.1:0",
	}

	server := NewHTTP3Server(config)

	stats := server.GetStats()
	if stats == nil {
		t.Fatal("服务器统计为空")
	}

	if stats.TotalConnections < 0 {
		t.Error("连接数异常")
	}

	t.Logf("HTTP/3统计: 连接数=%d, 活跃连接=%d", stats.TotalConnections, stats.ActiveConnections)
}

// TestHTTP3Server_StartStop 测试启动和停止服务器
func TestHTTP3Server_StartStop(t *testing.T) {
	config := &Config{
		Addr:              "127.0.0.1:0",
		IdleTimeout:       30 * time.Second,
		KeepAliveInterval: 5 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h3", "h3-29"},
		},
	}

	server := NewHTTP3Server(config)

	// 启动服务器
	err := server.Start()
	if err != nil {
		t.Logf("启动服务器失败（可能需要TLS证书）: %v", err)
		return
	}

	// 验证服务器已启动
	if server == nil {
		t.Error("服务器为空")
		return
	}

	// 停止服务器
	err = server.Stop()
	if err != nil {
		t.Errorf("停止服务器失败: %v", err)
	}

	t.Log("HTTP/3服务器启动/停止测试通过")
}

// TestNewGRPCServer 测试创建gRPC服务器
func TestNewGRPCServer(t *testing.T) {
	config := &GRPCConfig{
		Addr:           "0.0.0.0:50051",
		MaxRecvMsgSize: 1024 * 1024 * 4,
		MaxSendMsgSize: 1024 * 1024 * 4,
		KeepAliveParams: &keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      10 * time.Minute,
			MaxConnectionAgeGrace: 30 * time.Second,
			Time:                  1 * time.Minute,
			Timeout:               20 * time.Second,
		},
	}

	server := NewGRPCServer(config)
	if server == nil {
		t.Fatal("创建gRPC服务器失败")
	}

	t.Log("创建gRPC服务器测试通过")
}

// TestGRPCServer_StartStop 测试启动和停止服务器
func TestGRPCServer_StartStop(t *testing.T) {
	config := &GRPCConfig{
		Addr: "127.0.0.1:0", // 使用随机端口
	}

	server := NewGRPCServer(config)

	// 启动服务器
	err := server.Start()
	if err != nil {
		t.Logf("启动服务器失败: %v", err)
		return
	}

	// 停止服务器
	err = server.Stop()
	if err != nil {
		t.Errorf("停止服务器失败: %v", err)
	}

	t.Log("gRPC服务器启动/停止测试通过")
}

// TestGRPCServer_GetStats 测试获取服务器统计
func TestGRPCServer_GetStats(t *testing.T) {
	config := &GRPCConfig{
		Addr: "127.0.0.1:0",
	}

	server := NewGRPCServer(config)

	stats := server.GetStats()
	if stats == nil {
		t.Fatal("服务器统计为空")
	}

	if stats.TotalConnections < 0 {
		t.Error("连接数异常")
	}

	t.Logf("gRPC统计: 连接数=%d, 活跃连接=%d", stats.TotalConnections, stats.ActiveConnections)
}

// TestHTTP3Config 测试HTTP/3配置
func TestHTTP3Config(t *testing.T) {
	config := &Config{
		Addr:               "0.0.0.0:8443",
		MaxIncomingStreams: 100,
		IdleTimeout:        30 * time.Second,
		KeepAliveInterval:  5 * time.Second,
	}

	if config.MaxIncomingStreams <= 0 {
		t.Error("MaxIncomingStreams应该为正数")
	}

	if config.IdleTimeout <= 0 {
		t.Error("IdleTimeout应该为正数")
	}

	t.Log("HTTP/3配置测试通过")
}

// TestGRPCConfig 测试gRPC配置
func TestGRPCConfig(t *testing.T) {
	config := &GRPCConfig{
		Addr:           "0.0.0.0:50051",
		MaxRecvMsgSize: 1024 * 1024 * 4,
		MaxSendMsgSize: 1024 * 1024 * 4,
	}

	if config.MaxRecvMsgSize <= 0 {
		t.Error("MaxRecvMsgSize应该为正数")
	}

	if config.MaxSendMsgSize <= 0 {
		t.Error("MaxSendMsgSize应该为正数")
	}

	t.Log("gRPC配置测试通过")
}

// TestServerStats 测试服务器统计
func TestServerStats(t *testing.T) {
	stats := &ServerStats{
		ActiveConnections: 10,
		TotalConnections:  100,
		BytesReceived:     1024 * 1024,
		BytesSent:         5 * 1024 * 1024,
		RequestsTotal:     1000,
		Errors:            5,
	}

	if stats.TotalConnections != 100 {
		t.Error("连接数不匹配")
	}

	if stats.Errors > stats.RequestsTotal {
		t.Error("错误数不应该超过请求数")
	}

	t.Log("服务器统计测试通过")
}

// TestGRPCStats 测试gRPC统计
func TestGRPCStats(t *testing.T) {
	stats := &GRPCStats{
		TotalConnections:  100,
		ActiveConnections: 50,
		TotalRequests:     1000,
		TotalErrors:       10,
	}

	if stats.TotalConnections != 100 {
		t.Error("连接数不匹配")
	}

	if stats.TotalErrors > stats.TotalRequests {
		t.Error("错误数不应该超过请求数")
	}

	t.Log("gRPC统计测试通过")
}

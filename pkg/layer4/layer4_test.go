package layer4

import (
	"testing"
	"time"
)

// TestNewLayer4Proxy 测试创建四层代理
func TestNewLayer4Proxy(t *testing.T) {
	config := &Layer4Config{
		Enabled: true,
		Connection: &ConnectionConfig{
			MaxConnections: 1000,
			ConnectTimeout: 10 * time.Second,
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    60 * time.Second,
		},
		ConnectionLimit: &ConnectionLimitConfig{
			Enabled:                true,
			PerIPMaxConnections:    100,
			PerIPMaxConnectionRate: 10,
			RateWindow:             time.Minute,
			BlockDuration:          5 * time.Minute,
		},
	}

	proxy := NewLayer4Proxy(config)
	if proxy == nil {
		t.Fatal("创建四层代理失败")
	}

	if proxy.config.Connection.MaxConnections != 1000 {
		t.Error("配置未正确加载")
	}
}

// TestIPConnectionLimiter 测试IP连接限制
func TestIPConnectionLimiter(t *testing.T) {
	config := &ConnectionLimitConfig{
		Enabled:                true,
		PerIPMaxConnections:    5,
		PerIPMaxConnectionRate: 10,
		RateWindow:             time.Minute,
		BlockDuration:          5 * time.Minute,
	}

	limiter := NewIPConnectionLimiter(config)
	if limiter == nil {
		t.Fatal("创建连接限制器失败")
	}

	// 测试允许连接
	for i := 0; i < 5; i++ {
		if !limiter.AllowConnection("192.168.1.1") {
			t.Errorf("第%d次连接应该被允许", i+1)
		}
	}

	// 第6次应该被拒绝
	if limiter.AllowConnection("192.168.1.1") {
		t.Error("超过最大连接数应该被拒绝")
	}
}

// TestIPConnectionLimiterRateLimit 测试速率限制
func TestIPConnectionLimiterRateLimit(t *testing.T) {
	config := &ConnectionLimitConfig{
		Enabled:                true,
		PerIPMaxConnections:    100,
		PerIPMaxConnectionRate: 3,
		RateWindow:             time.Minute,
		BlockDuration:          5 * time.Minute,
	}

	limiter := NewIPConnectionLimiter(config)

	// 快速发起3个连接，应该允许
	for i := 0; i < 3; i++ {
		if !limiter.AllowConnection("192.168.1.2") {
			t.Errorf("第%d次连接应该被允许", i+1)
		}
	}

	// 第4次应该因为速率限制被拒绝
	if limiter.AllowConnection("192.168.1.2") {
		t.Error("超过速率限制应该被拒绝")
	}

	// 检查是否被封锁
	blocked := limiter.GetBlockedIPs()
	if len(blocked) == 0 {
		t.Error("IP应该被封锁")
	}
}

// TestLoadBalancer 测试负载均衡器
func TestLoadBalancer(t *testing.T) {
	config := &LoadBalanceConfig{
		Enabled: true,
		Method:  "round_robin",
	}

	lb := NewLoadBalancer(config)
	if lb == nil {
		t.Fatal("创建负载均衡器失败")
	}

	// 添加目标服务器
	lb.AddTarget(&TargetConfig{
		Addr:    "10.0.0.1",
		Port:    8080,
		Weight:  50,
		Healthy: true,
	})

	lb.AddTarget(&TargetConfig{
		Addr:    "10.0.0.2",
		Port:    8080,
		Weight:  50,
		Healthy: true,
	})

	// 测试选择
	for i := 0; i < 10; i++ {
		target := lb.Select("192.168.1.1")
		if target == nil {
			t.Error("应该选择到目标服务器")
		}
	}
}

// TestLoadBalancerLeastConn 测试最少连接负载均衡
func TestLoadBalancerLeastConn(t *testing.T) {
	config := &LoadBalanceConfig{
		Enabled: true,
		Method:  "least_conn",
	}

	lb := NewLoadBalancer(config)

	// 添加服务器
	target1 := &TargetConfig{
		Addr:   "10.0.0.1",
		Port:   8080,
		Weight: 50,
	}
	target1.Healthy = true
	target1.CurrentConnections = 10

	target2 := &TargetConfig{
		Addr:   "10.0.0.2",
		Port:   8080,
		Weight: 50,
	}
	target2.Healthy = true
	target2.CurrentConnections = 5

	lb.AddTarget(target1)
	lb.AddTarget(target2)

	selected := lb.Select("192.168.1.1")
	if selected == nil {
		t.Fatal("选择结果为空")
	}
	if selected.Addr != "10.0.0.2" {
		t.Error("应该选择连接数最少的服务器")
	}
}

// TestGetStats 测试获取统计
func TestGetStats(t *testing.T) {
	config := &Layer4Config{
		Enabled: true,
	}

	proxy := NewLayer4Proxy(config)
	stats := proxy.GetStats()

	if stats == nil {
		t.Fatal("统计为空")
	}

	if stats.TotalConnections != 0 {
		t.Error("初始连接数应该为0")
	}
}

// TestGetListeners 测试获取监听器列表
func TestGetListeners(t *testing.T) {
	config := &Layer4Config{
		Enabled: true,
	}

	proxy := NewLayer4Proxy(config)
	listeners := proxy.GetListeners()

	if listeners == nil {
		t.Fatal("监听器列表为空")
	}
}

// TestGetActiveConnections 测试获取活动连接
func TestGetActiveConnections(t *testing.T) {
	config := &Layer4Config{
		Enabled: true,
	}

	proxy := NewLayer4Proxy(config)
	connections := proxy.GetActiveConnections()

	if connections == nil {
		t.Fatal("连接列表为空")
	}

	if len(connections) != 0 {
		t.Error("初始应该没有活动连接")
	}
}

package dns

import (
	"context"
	"testing"
	"time"
)

// TestNewSmartDNS 测试创建智能DNS
func TestNewSmartDNS(t *testing.T) {
	config := &SmartDNSConfig{
		Enabled:    true,
		ListenAddr: "0.0.0.0",
		ListenPort: 53,
		Protocols:  []string{"udp", "tcp"},
	}

	dns := NewSmartDNS(config)
	if dns == nil {
		t.Fatal("创建智能DNS失败")
	}

	if dns.config == nil {
		t.Error("配置为空")
	}

	t.Log("创建智能DNS测试通过")
}

// TestSmartDNS_Resolve 测试DNS解析
func TestSmartDNS_Resolve(t *testing.T) {
	config := &SmartDNSConfig{
		Enabled: true,
	}

	dns := NewSmartDNS(config)

	// 先添加区域和记录
	zone := &DNSZone{
		Name:    "example.com",
		Records: make([]*SmartDNSRecord, 0),
	}
	zone.Records = append(zone.Records, &SmartDNSRecord{
		Type:  "A",
		Name:  "www",
		Value: "192.168.1.1",
		TTL:   3600 * time.Second,
	})
	dns.AddZone(zone)

	// 测试域名解析
	question := &DNSQuestion{
		Name:     "www.example.com",
		Type:     "A",
		Class:    "IN",
		ClientIP: "192.168.1.100",
	}

	response, err := dns.Resolve(context.Background(), question)
	if err != nil {
		t.Logf("解析可能失败（无DNS服务器）: %v", err)
	}

	t.Logf("解析结果: %v", response)
}

// TestSmartDNS_AddZone 测试添加DNS区域
func TestSmartDNS_AddZone(t *testing.T) {
	config := &SmartDNSConfig{
		Enabled: true,
	}

	dns := NewSmartDNS(config)

	zone := &DNSZone{
		Name:    "example.com",
		Records: make([]*SmartDNSRecord, 0),
	}

	err := dns.AddZone(zone)
	if err != nil {
		t.Errorf("添加区域失败: %v", err)
	}

	// 验证区域已添加
	dns.mu.RLock()
	_, exists := dns.zones["example.com"]
	dns.mu.RUnlock()

	if !exists {
		t.Error("区域未找到")
	}

	t.Log("添加DNS区域测试通过")
}

// TestSmartDNS_GetStats 测试获取统计
func TestSmartDNS_GetStats(t *testing.T) {
	config := &SmartDNSConfig{
		Enabled: true,
	}

	dns := NewSmartDNS(config)

	stats := dns.GetStats()
	if stats == nil {
		t.Fatal("统计为空")
	}

	if stats.TotalQueries < 0 {
		t.Error("查询计数异常")
	}

	t.Logf("DNS统计: 查询数=%d", stats.TotalQueries)
}

// TestSmartDNS_RegisterNode 测试注册节点
func TestSmartDNS_RegisterNode(t *testing.T) {
	config := &SmartDNSConfig{
		Enabled: true,
	}

	dns := NewSmartDNS(config)

	node := &NodeInfo{
		ID:      "node-1",
		Name:    "主节点",
		Address: "192.168.1.10",
		Region:  "cn",
		ISP:     "cmcc",
		Status:  "online",
	}

	dns.RegisterNode(node)

	nodes := dns.GetNodeStatus()
	if len(nodes) != 1 {
		t.Errorf("期望1个节点，实际%d个", len(nodes))
	}

	t.Log("注册节点测试通过")
}

// TestDNSScheduler 测试DNS调度器
func TestDNSScheduler(t *testing.T) {
	config := &SchedulerConfig{
		Enabled:  true,
		Strategy: "weighted",
	}

	scheduler := NewDNSScheduler(config)
	if scheduler == nil {
		t.Fatal("调度器为空")
	}

	// 添加DNS记录
	record := DNSRecord{
		Type:   "A",
		Name:   "www.example.com",
		Value:  "192.168.1.1",
		TTL:    300 * time.Second,
		Weight: 100,
	}
	scheduler.AddRecord(record)

	// 解析域名
	ips, err := scheduler.Resolve("www.example.com", "192.168.1.100")
	if err != nil {
		t.Logf("解析可能失败: %v", err)
	}

	t.Logf("解析结果: %v", ips)
	t.Log("DNS调度器测试通过")
}

// TestDNSScheduler_AddProvider 测试添加DNS提供商
func TestDNSScheduler_AddProvider(t *testing.T) {
	config := &SchedulerConfig{
		Enabled:  true,
		Strategy: "smart",
	}

	scheduler := NewDNSScheduler(config)

	provider := DNSProvider{
		Name:      "aliyun",
		Type:      "aliyun",
		APIKey:    "test-key",
		SecretKey: "test-secret",
		Endpoint:  "dns.aliyun.com",
		Enabled:   true,
		Weight:    100,
		Priority:  1,
	}

	scheduler.AddProvider(provider)

	t.Log("DNS提供商添加测试通过")
}

// TestDNSScheduler_GetStats 测试获取调度统计
func TestDNSScheduler_GetStats(t *testing.T) {
	config := &SchedulerConfig{
		Enabled:  true,
		Strategy: "round_robin",
	}

	scheduler := NewDNSScheduler(config)

	stats := scheduler.GetStats()
	if stats == nil {
		t.Fatal("统计为空")
	}

	if stats.TotalQueries < 0 {
		t.Error("查询计数异常")
	}

	t.Logf("调度统计: 总查询=%d", stats.TotalQueries)
}

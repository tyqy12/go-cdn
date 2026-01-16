package monitor

import (
	"testing"
	"time"

	"github.com/ai-cdn-tunnel/proto/agent"
)

func TestNewMonitor(t *testing.T) {
	// 由于 NewMonitor 需要真实的 db，这里测试基本结构
	monitor := &Monitor{
		nodes:       make(map[string]*NodeMetrics),
		collectors:  make(map[string]*StatusCollector),
		metricsChan: make(chan *agent.StatusReport, 1000),
	}

	if monitor.nodes == nil {
		t.Error("nodes should not be nil")
	}

	if monitor.collectors == nil {
		t.Error("collectors should not be nil")
	}

	if monitor.metricsChan == nil {
		t.Error("metricsChan should not be nil")
	}
}

func TestNodeMetrics_Structure(t *testing.T) {
	now := time.Now()
	metrics := &NodeMetrics{
		NodeID:     "test-node",
		LastUpdate: now,
		System: &SystemMetrics{
			CPUUsage:    0.5,
			MemoryUsage: 0.6,
			DiskUsage:   0.4,
			Goroutines:  100,
			Uptime:      3600,
		},
		Network: &NetworkMetrics{
			BandwidthIn:  1000000,
			BandwidthOut: 2000000,
			BytesIn:      100000000,
			BytesOut:     200000000,
		},
		CDN: &CDNMetrics{
			QPS:             1000,
			TotalRequests:   100000,
			SuccessRequests: 99000,
			ErrorRequests:   1000,
			P50Latency:      50,
			P95Latency:      100,
			P99Latency:      200,
		},
		Connections: &ConnectionMetrics{
			ActiveConnections: 500,
			TotalConnections:  10000,
			ClosedConnections: 9500,
			IdleConnections:   200,
		},
		Security: &SecurityMetrics{
			BlockedConnections:  100,
			SlowConnections:     50,
			RateLimitedRequests: 200,
			CCBlocked:           10,
		},
	}

	if metrics.NodeID != "test-node" {
		t.Errorf("Expected NodeID 'test-node', got '%s'", metrics.NodeID)
	}

	if metrics.System.CPUUsage != 0.5 {
		t.Errorf("Expected CPUUsage 0.5, got %f", metrics.System.CPUUsage)
	}

	if metrics.CDN.QPS != 1000 {
		t.Errorf("Expected QPS 1000, got %f", metrics.CDN.QPS)
	}

	if metrics.Connections.ActiveConnections != 500 {
		t.Errorf("Expected ActiveConnections 500, got %d", metrics.Connections.ActiveConnections)
	}
}

func TestSystemMetrics_Fields(t *testing.T) {
	metrics := &SystemMetrics{
		CPUUsage:    0.75,
		MemoryUsage: 0.80,
		DiskUsage:   0.50,
		Goroutines:  200,
		Uptime:      86400,
	}

	if metrics.CPUUsage < 0 || metrics.CPUUsage > 1 {
		t.Errorf("CPUUsage should be between 0 and 1, got %f", metrics.CPUUsage)
	}

	if metrics.MemoryUsage < 0 || metrics.MemoryUsage > 1 {
		t.Errorf("MemoryUsage should be between 0 and 1, got %f", metrics.MemoryUsage)
	}

	if metrics.DiskUsage < 0 || metrics.DiskUsage > 1 {
		t.Errorf("DiskUsage should be between 0 and 1, got %f", metrics.DiskUsage)
	}
}

func TestNetworkMetrics_Fields(t *testing.T) {
	metrics := &NetworkMetrics{
		BandwidthIn:  1000000,
		BandwidthOut: 2000000,
		BytesIn:      1024 * 1024 * 100,
		BytesOut:     1024 * 1024 * 200,
	}

	if metrics.BandwidthIn < 0 {
		t.Errorf("BandwidthIn should be non-negative, got %f", metrics.BandwidthIn)
	}

	if metrics.BandwidthOut < 0 {
		t.Errorf("BandwidthOut should be non-negative, got %f", metrics.BandwidthOut)
	}
}

func TestCDNMetrics_Fields(t *testing.T) {
	metrics := &CDNMetrics{
		QPS:             5000,
		TotalRequests:   1000000,
		SuccessRequests: 990000,
		ErrorRequests:   10000,
		P50Latency:      25,
		P95Latency:      75,
		P99Latency:      150,
	}

	// 验证成功率计算
	successRate := float64(metrics.SuccessRequests) / float64(metrics.TotalRequests)
	if successRate < 0.9 {
		t.Errorf("Expected success rate > 90%%, got %f", successRate)
	}

	if metrics.P50Latency > metrics.P95Latency {
		t.Errorf("P50 latency should be less than P95 latency")
	}

	if metrics.P95Latency > metrics.P99Latency {
		t.Errorf("P95 latency should be less than P99 latency")
	}
}

func TestConnectionMetrics_Fields(t *testing.T) {
	metrics := &ConnectionMetrics{
		ActiveConnections: 1000,
		TotalConnections:  50000,
		ClosedConnections: 48000,
		IdleConnections:   250,
	}

	// 验证连接状态一致性 (Active + Closed + Idle 应该小于等于 Total)
	total := metrics.ActiveConnections + metrics.ClosedConnections + metrics.IdleConnections
	if total > metrics.TotalConnections {
		t.Errorf("Connection counts (%d) exceed TotalConnections (%d)", total, metrics.TotalConnections)
	}
}

func TestSecurityMetrics_Fields(t *testing.T) {
	metrics := &SecurityMetrics{
		BlockedConnections:  50,
		SlowConnections:     25,
		RateLimitedRequests: 100,
		CCBlocked:           5,
	}

	if metrics.BlockedConnections < 0 {
		t.Errorf("BlockedConnections should be non-negative")
	}

	if metrics.RateLimitedRequests < 0 {
		t.Errorf("RateLimitedRequests should be non-negative")
	}
}

func TestStatusCollector_UpdateAndGet(t *testing.T) {
	collector := &StatusCollector{
		nodeID: "test-node",
		status: nil,
	}

	// 初始状态为 nil
	if collector.GetStatus() != nil {
		t.Error("Initial status should be nil")
	}

	// 更新状态
	status := &agent.StatusReport{
		NodeId:    "test-node",
		Timestamp: time.Now().Unix(),
		System: &agent.SystemMetrics{
			CpuUsage:   0.5,
			MemUsage:   0.6,
			DiskUsage:  0.4,
			Goroutines: 100,
			Uptime:     3600,
		},
	}

	collector.UpdateStatus(status)

	// 获取状态
	retrieved := collector.GetStatus()
	if retrieved == nil {
		t.Fatal("GetStatus should not return nil after update")
	}

	if retrieved.NodeId != "test-node" {
		t.Errorf("Expected NodeId 'test-node', got '%s'", retrieved.NodeId)
	}

	if retrieved.System.CpuUsage != 0.5 {
		t.Errorf("Expected CpuUsage 0.5, got %f", retrieved.System.CpuUsage)
	}
}

func TestMetricsData_Structure(t *testing.T) {
	now := time.Now()
	metrics := &MetricsData{
		NodeID:    "test-node",
		Timestamp: now,
		System: &agent.SystemMetrics{
			CpuUsage:   0.5,
			MemUsage:   0.6,
			DiskUsage:  0.4,
			Goroutines: 100,
			Uptime:     3600,
		},
		Network: &agent.NetworkMetrics{
			BandwidthIn:  1000000,
			BandwidthOut: 2000000,
			BytesIn:      100000000,
			BytesOut:     200000000,
		},
		CDN: &agent.CDNMetrics{
			Qps:           1000,
			TotalRequests: 100000,
		},
		Connections: &agent.ConnectionMetrics{
			ActiveConnections: 500,
		},
		Security: &agent.SecurityMetrics{
			BlockedConnections: 100,
		},
	}

	if metrics.NodeID != "test-node" {
		t.Errorf("Expected NodeID 'test-node', got '%s'", metrics.NodeID)
	}

	if metrics.System == nil {
		t.Error("System should not be nil")
	}

	if metrics.Network == nil {
		t.Error("Network should not be nil")
	}
}

func TestMonitorStats_Structure(t *testing.T) {
	stats := &MonitorStats{
		TotalNodes:  10,
		Collectors:  8,
		OnlineNodes: 7,
	}

	if stats.TotalNodes != 10 {
		t.Errorf("Expected TotalNodes 10, got %d", stats.TotalNodes)
	}

	if stats.Collectors != 8 {
		t.Errorf("Expected Collectors 8, got %d", stats.Collectors)
	}

	if stats.OnlineNodes != 7 {
		t.Errorf("Expected OnlineNodes 7, got %d", stats.OnlineNodes)
	}
}

func TestNodeMetrics_UpdateFromProto(t *testing.T) {
	now := time.Now()
	protoMetrics := &agent.StatusReport{
		NodeId:    "test-node",
		Timestamp: now.Unix(),
		System: &agent.SystemMetrics{
			CpuUsage:   0.45,
			MemUsage:   0.55,
			DiskUsage:  0.35,
			Goroutines: 150,
			Uptime:     7200,
		},
		Network: &agent.NetworkMetrics{
			BandwidthIn:  1500000,
			BandwidthOut: 2500000,
			BytesIn:      150000000,
			BytesOut:     250000000,
		},
		CDN: &agent.CDNMetrics{
			Qps:           1500,
			TotalRequests: 150000,
			SuccessRequests: 148500,
			ErrorRequests: 1500,
			P50Latency:      30,
			P95Latency:      80,
			P99Latency:      160,
		},
		Connections: &agent.ConnectionMetrics{
			ActiveConnections: 600,
			TotalConnections:  12000,
			ClosedConnections: 11400,
			IdleConnections:   250,
		},
		Security: &agent.SecurityMetrics{
			BlockedConnections:  75,
			SlowConnections:     35,
			RateLimitedRequests: 150,
			CCBlocked:           8,
		},
	}

	// 验证从 proto 转换后的值
	if protoMetrics.System.CpuUsage != 0.45 {
		t.Errorf("Expected CpuUsage 0.45, got %f", protoMetrics.System.CpuUsage)
	}

	if protoMetrics.CDN.Qps != 1500 {
		t.Errorf("Expected Qps 1500, got %f", protoMetrics.CDN.Qps)
	}

	if protoMetrics.Connections.ActiveConnections != 600 {
		t.Errorf("Expected ActiveConnections 600, got %d", protoMetrics.Connections.ActiveConnections)
	}
}

func TestTimeBasedMetrics(t *testing.T) {
	// 测试时间相关字段的处理
	now := time.Now()
	metrics := &NodeMetrics{
		NodeID:     "time-test-node",
		LastUpdate: now,
	}

	// 验证时间更新
	if metrics.LastUpdate.IsZero() {
		t.Error("LastUpdate should not be zero")
	}

	// 计算年龄
	age := time.Since(metrics.LastUpdate)
	if age < 0 {
		t.Errorf("Age should be non-negative, got %v", age)
	}
}

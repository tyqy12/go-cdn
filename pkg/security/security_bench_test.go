package security

import (
	"testing"
	"time"
)

// BenchmarkCCProtection_ProcessRequest CC防护处理请求基准测试
func BenchmarkCCProtection_ProcessRequest(b *testing.B) {
	config := &CCConfig{
		Enabled:         true,
		DetectionMode:   "standalone",
		ResponseStrategy: "block",
	}

	cc := NewCCProtection(config)

	req := &RequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Headers:   make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.ProcessRequest(req)
	}
}

// BenchmarkCCProtection_ConcurrentProcess 并发CC防护基准测试
func BenchmarkCCProtection_ConcurrentProcess(b *testing.B) {
	config := &CCConfig{
		Enabled:         true,
		DetectionMode:   "standalone",
		ResponseStrategy: "block",
	}

	cc := NewCCProtection(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := &RequestInfo{
				IP:        "192.168.1." + string(rune(time.Now().Unix()%255)),
				UserAgent: "Mozilla/5.0",
				URL:       "/api/test",
				Method:    "GET",
				Headers:   make(map[string]string),
			}
			cc.ProcessRequest(req)
		}
	})
}

// BenchmarkTrafficAnalyzer_Analyze 流量分析基准测试
func BenchmarkTrafficAnalyzer_Analyze(b *testing.B) {
	config := &CCConfig{
		Enabled:       true,
		DetectionMode: "standalone",
		Thresholds: CCThresholds{
			RequestsPerSecond: 100,
		},
	}

	analyzer := NewTrafficAnalyzer(config)

	req := &RequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Headers:   make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(req)
	}
}

// BenchmarkIPFirewall_AddRule 防火墙规则基准测试
func BenchmarkIPFirewall_AddRule(b *testing.B) {
	config := &CCConfig{
		Enabled: true,
	}

	mitigator := NewAttackMitigator(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mitigator.firewall.rules["192.168.1."+string(rune(i%255))] = &FirewallRule{
			IP:       "192.168.1." + string(rune(i%255)),
			Action:   "block",
			Priority: 100,
		}
	}
}

// BenchmarkMLModel_Predict ML模型预测基准测试
func BenchmarkMLModel_Predict(b *testing.B) {
	ml := &MLModel{
		config: &MLConfig{
			Enabled:              true,
			ModelType:            "isolation_forest",
			AnomalyScoreThreshold: 0.7,
		},
		isTrained: true,
	}

	req := &RequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Headers:   make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ml.Predict(req)
	}
}

// BenchmarkCCStats_Update CC统计更新基准测试
func BenchmarkCCStats_Update(b *testing.B) {
	stats := &CCStats{
		AttackTypes: make(map[string]int64),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.mu.Lock()
		stats.TotalRequests++
		stats.AllowedRequests++
		stats.AttackTypes["flood"]++
		stats.mu.Unlock()
	}
}

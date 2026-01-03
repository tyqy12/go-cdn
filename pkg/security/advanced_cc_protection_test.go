package security

import (
	"testing"
	"time"
)

// TestNewAdvancedCCProtection 测试创建高级CC防护
func TestNewAdvancedCCProtection(t *testing.T) {
	config := &AdvancedCCConfig{
		Enabled:        true,
		DetectionMode:  "standalone",
		ProtectionMode: "standard",
		GlobalThresholds: &GlobalThresholds{
			RequestsPerSecond: 100,
			PerIPRequests:     50,
			PerIPConnections:  20,
		},
		Detection: &CCDetectionConfig{
			RateDetection:    true,
			SensitivityLevel: "medium",
		},
		Challenge: &AdvancedChallengeConfig{
			Enabled:                true,
			ChallengeValidDuration: 5 * time.Minute,
			MaxRetries:             3,
		},
	}

	protection := NewAdvancedCCProtection(config)
	if protection == nil {
		t.Fatal("创建CC防护失败")
	}

	if !protection.config.Enabled {
		t.Error("配置未正确加载")
	}
}

// TestCheckRequest 测试请求检查
func TestCheckRequest(t *testing.T) {
	protection := NewAdvancedCCProtection(&AdvancedCCConfig{
		Enabled:        true,
		DetectionMode:  "standalone",
		ProtectionMode: "standard",
	})

	req := &CCRequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}

	result := protection.CheckRequest(req)
	if result == nil {
		t.Fatal("检查结果为空")
	}

	// 正常请求应该被允许
	if !result.Allowed {
		t.Error("正常请求应该被允许")
	}
}

// TestWhiteList 测试白名单
func TestWhiteList(t *testing.T) {
	protection := NewAdvancedCCProtection(&AdvancedCCConfig{
		Enabled:        true,
		DetectionMode:  "standalone",
		ProtectionMode: "standard",
		WhiteList:      []string{"192.168.1.100"},
	})

	req := &CCRequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}

	result := protection.CheckRequest(req)
	if !result.Allowed {
		t.Error("白名单IP应该被允许")
	}

	if result.Reason != "白名单" {
		t.Error("应该返回白名单原因")
	}
}

// TestBlackList 测试黑名单
func TestBlackList(t *testing.T) {
	protection := NewAdvancedCCProtection(&AdvancedCCConfig{
		Enabled:        true,
		DetectionMode:  "standalone",
		ProtectionMode: "standard",
		BlackList:      []string{"192.168.1.100"},
	})

	req := &CCRequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Headers:   make(map[string]string),
		Timestamp: time.Now(),
	}

	result := protection.CheckRequest(req)
	if result.Allowed {
		t.Error("黑名单IP应该被阻止")
	}

	if result.Reason != "黑名单" {
		t.Error("应该返回黑名单原因")
	}
}

// TestBlockAndAllowIP 测试封锁和允许IP
func TestBlockAndAllowIP(t *testing.T) {
	protection := NewAdvancedCCProtection(&AdvancedCCConfig{
		Enabled:        true,
		DetectionMode:  "standalone",
		ProtectionMode: "standard",
	})

	// 封锁IP
	protection.BlockIP("10.0.0.1", 1*time.Hour)

	threatIPs := protection.GetThreatIPs()
	if len(threatIPs) == 0 {
		t.Error("应该返回被封锁的IP")
	}
}

// TestGetStats 测试获取统计
func TestGetStats(t *testing.T) {
	protection := NewAdvancedCCProtection(&AdvancedCCConfig{
		Enabled:        true,
		DetectionMode:  "standalone",
		ProtectionMode: "standard",
	})

	stats := protection.GetStats()
	if stats == nil {
		t.Fatal("统计为空")
	}

	if stats.TotalRequests != 0 {
		t.Error("初始请求数应该为0")
	}
}

// TestChallengeManager 测试挑战管理器
func TestChallengeManager(t *testing.T) {
	config := &AdvancedChallengeConfig{
		Enabled:                true,
		ChallengeValidDuration: 5 * time.Minute,
		MaxRetries:             3,
		JSChallenge:            true,
	}

	mgr := NewChallengeManager(config)
	if mgr == nil {
		t.Fatal("创建挑战管理器失败")
	}

	// 创建挑战
	challenge := mgr.CreateChallenge("192.168.1.100", "Mozilla/5.0")
	if challenge == nil {
		t.Fatal("创建挑战失败")
	}

	if challenge.Type == "" {
		t.Error("挑战类型不应为空")
	}

	if challenge.Token == "" {
		t.Error("挑战令牌不应为空")
	}

	if challenge.Status != "pending" {
		t.Error("挑战状态应为pending")
	}
}

// TestBehaviorAnalyzer 测试行为分析器
func TestBehaviorAnalyzer(t *testing.T) {
	analyzer := &BehaviorAnalyzer{}

	req := &CCRequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
	}

	score := analyzer.Analyze(req)
	if score < 0 || score > 1 {
		t.Error("分数应该在0-1之间")
	}
}

// TestMLModel 测试机器学习模型
func TestMLModel(t *testing.T) {
	model := &CCMLModel{}

	req := &CCRequestInfo{
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
	}

	score := model.Predict(req)
	if score < 0 || score > 1 {
		t.Error("分数应该在0-1之间")
	}
}

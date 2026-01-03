package accesscontrol

import (
	"testing"
	"time"
)

// TestNewAccessControl 测试创建访问控制
func TestNewAccessControl(t *testing.T) {
	config := &AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
		MatchMode:     "all",
	}

	ac := NewAccessControl(config)
	if ac == nil {
		t.Fatal("创建访问控制失败")
	}

	if !ac.config.Enabled {
		t.Error("配置未正确加载")
	}
}

// TestCheckRequest 测试请求检查
func TestCheckRequest(t *testing.T) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	req := &AccessRequest{
		SourceIP:  "192.168.1.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Timestamp: time.Now(),
	}

	result := ac.CheckRequest(req)
	if result == nil {
		t.Fatal("检查结果为空")
	}

	if !result.Allowed {
		t.Error("默认允许策略未生效")
	}
}

// TestCheckRequestWithBlock 测试黑名单阻止
func TestCheckRequestWithBlock(t *testing.T) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	// 添加黑名单IP
	ac.AddToBlackList("192.168.1.100")

	req := &AccessRequest{
		SourceIP:  "192.168.1.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Timestamp: time.Now(),
	}

	result := ac.CheckRequest(req)
	if result.Allowed {
		t.Error("黑名单IP应该被阻止")
	}
}

// TestCheckRequestWithAllow 测试白名单允许
func TestCheckRequestWithAllow(t *testing.T) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "block",
	})

	// 添加白名单IP
	ac.AddToWhiteList("192.168.1.100")

	req := &AccessRequest{
		SourceIP:  "192.168.1.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
		Timestamp: time.Now(),
	}

	result := ac.CheckRequest(req)
	if !result.Allowed {
		t.Error("白名单IP应该被允许")
	}
}

// TestAddAndRemoveRule 测试添加和移除规则
func TestAddAndRemoveRule(t *testing.T) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	rule := &AccessRule{
		ID:        "test-rule-1",
		Name:      "测试规则",
		Type:      "ip",
		Condition: "eq",
		Value:     "10.0.0.1",
		Action:    "block",
		Priority:  100,
		Enabled:   true,
	}

	err := ac.AddRule(rule)
	if err != nil {
		t.Errorf("添加规则失败: %v", err)
	}

	rules := ac.GetRules()
	if len(rules) != 1 {
		t.Errorf("规则数量错误: 期望1, 实际%d", len(rules))
	}

	err = ac.RemoveRule("test-rule-1")
	if err != nil {
		t.Errorf("移除规则失败: %v", err)
	}

	rules = ac.GetRules()
	if len(rules) != 0 {
		t.Errorf("规则未正确移除: 数量%d", len(rules))
	}
}

// TestBlockAndAllowIP 测试封锁和允许IP
func TestBlockAndAllowIP(t *testing.T) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	// 封锁IP
	ac.BlockIP("10.0.0.1", "测试封锁")

	if !ac.IsBlocked("10.0.0.1") {
		t.Error("IP应该被封锁")
	}

	// 允许IP
	ac.AllowIP("10.0.0.1")

	if ac.IsBlocked("10.0.0.1") {
		t.Error("IP应该被允许")
	}
}

// TestGetStats 测试获取统计
func TestGetStats(t *testing.T) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	stats := ac.GetStats()
	if stats == nil {
		t.Fatal("统计为空")
	}

	// 执行一些请求
	for i := 0; i < 10; i++ {
		req := &AccessRequest{
			SourceIP:  "192.168.1.1",
			Host:      "example.com",
			UserAgent: "Mozilla/5.0",
			URL:       "/api/test",
			Method:    "GET",
			Timestamp: time.Now(),
		}
		ac.CheckRequest(req)
	}

	stats = ac.GetStats()
	if stats.TotalRequests < 10 {
		t.Error("统计未正确更新")
	}
}

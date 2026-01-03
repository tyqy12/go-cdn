package accesscontrol

import (
	"regexp"
	"testing"
)

// BenchmarkAccessControl_CheckRequest 访问控制检查基准测试
func BenchmarkAccessControl_CheckRequest(b *testing.B) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	// 添加一些规则
	ac.AddRule(&AccessRule{
		ID:        "test-rule-1",
		Name:      "测试规则1",
		Type:      "ip",
		Condition: "range",
		Value:     "192.168.1.0/24",
		Action:    "allow",
		Priority:  100,
		Enabled:   true,
	})

	req := &AccessRequest{
		SourceIP:  "192.168.1.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.CheckRequest(req)
	}
}

// BenchmarkAccessControl_AddRule 添加规则基准测试
func BenchmarkAccessControl_AddRule(b *testing.B) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule := &AccessRule{
			ID:        "bench-rule",
			Name:      "基准测试规则",
			Type:      "url",
			Condition: "prefix",
			Value:     "/api/test",
			Action:    "allow",
			Priority:  100,
			Enabled:   true,
		}
		ac.AddRule(rule)
	}
}

// BenchmarkAccessControl_ConcurrentCheck 并发访问检查基准测试
func BenchmarkAccessControl_ConcurrentCheck(b *testing.B) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	// 添加规则
	for i := 0; i < 100; i++ {
		ac.AddRule(&AccessRule{
			ID:        "test-rule",
			Name:      "测试规则",
			Type:      "url",
			Condition: "prefix",
			Value:     "/api/test",
			Action:    "allow",
			Priority:  100,
			Enabled:   true,
		})
	}

	req := &AccessRequest{
		SourceIP:  "192.168.1.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ac.CheckRequest(req)
		}
	})
}

// BenchmarkAccessControl_IPMatching IP匹配基准测试
func BenchmarkAccessControl_IPMatching(b *testing.B) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	// 添加IP规则
	for i := 0; i < 50; i++ {
		ac.AddRule(&AccessRule{
			ID:        "ip-rule-" + string(rune(i)),
			Name:      "IP规则",
			Type:      "ip",
			Condition: "range",
			Value:     "192.168." + string(rune(i)) + ".0/24",
			Action:    "allow",
			Priority:  100,
			Enabled:   true,
		})
	}

	req := &AccessRequest{
		SourceIP:  "192.168.25.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/test",
		Method:    "GET",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.CheckRequest(req)
	}
}

// BenchmarkAccessControl_RegexMatching 正则匹配基准测试
func BenchmarkAccessControl_RegexMatching(b *testing.B) {
	ac := NewAccessControl(&AccessConfig{
		Enabled:       true,
		DefaultAction: "allow",
	})

	// 添加正则规则
	ac.AddRule(&AccessRule{
		ID:        "regex-rule",
		Name:      "正则规则",
		Type:      "url",
		Condition: "regex",
		Value:     `^/api/v[0-9]+/test.*$`,
		ValueRegex: regexp.MustCompile(`^/api/v[0-9]+/test.*$`),
		Action:    "allow",
		Priority:  100,
		Enabled:   true,
	})

	req := &AccessRequest{
		SourceIP:  "192.168.1.100",
		Host:      "example.com",
		UserAgent: "Mozilla/5.0",
		URL:       "/api/v1/test123",
		Method:    "GET",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.CheckRequest(req)
	}
}

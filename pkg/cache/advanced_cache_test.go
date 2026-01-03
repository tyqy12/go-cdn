package cache

import (
	"testing"
	"time"
)

// TestNewAdvancedCache 测试创建高级缓存
func TestNewAdvancedCache(t *testing.T) {
	config := &CacheConfig{
		Enabled: true,
		Global: &GlobalCacheConfig{
			DefaultTTL:      3600 * time.Second,
			MaxTTL:          86400 * time.Second,
			MaxSize:         10 * 1024 * 1024 * 1024,
			MaxEntries:      1000000,
			CleanupInterval: 300 * time.Second,
		},
		Rules: []CacheRuleConfig{
			{
				Name:     "HTML缓存",
				RuleType: "extension",
				Pattern:  "html",
				Cache:    true,
				TTL:      3600 * time.Second,
				Priority: 100,
				Enabled:  true,
			},
		},
	}

	cache := NewAdvancedCache(config)
	if cache == nil {
		t.Fatal("创建缓存失败")
	}

	if !cache.config.Enabled {
		t.Error("配置未正确加载")
	}

	if len(cache.rules) != 1 {
		t.Errorf("规则数量错误: 期望1, 实际%d", len(cache.rules))
	}
}

// TestCacheRule 测试缓存规则
func TestCacheRule(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	rule := &CacheRule{
		ID:       "test-rule-1",
		Name:     "API缓存",
		RuleType: "path",
		Pattern:  "/api",
		Cache:    true,
		TTL:      300 * time.Second,
		Priority: 100,
		Enabled:  true,
	}

	err := cache.AddRule(rule)
	if err != nil {
		t.Errorf("添加规则失败: %v", err)
	}

	rules := cache.GetRules()
	if len(rules) != 1 {
		t.Errorf("规则数量错误: 期望1, 实际%d", len(rules))
	}
}

// TestMatchExtension 测试扩展名匹配
func TestMatchExtension(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 测试匹配
	if !cache.matchExtension("html", "/test.html") {
		t.Error("应该匹配html扩展名")
	}

	if !cache.matchExtension("js", "/test.js") {
		t.Error("应该匹配js扩展名")
	}

	if cache.matchExtension("html", "/test.js") {
		t.Error("不应该匹配")
	}
}

// TestMatchPath 测试路径匹配
func TestMatchPath(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 测试匹配
	if !cache.matchPath("/api", "/api/test") {
		t.Error("应该匹配/api路径")
	}

	if !cache.matchPath("/api", "/api/v1/users") {
		t.Error("应该匹配/api/v1/users路径")
	}

	if cache.matchPath("/api", "/admin/test") {
		t.Error("不应该匹配/admin路径")
	}
}

// TestGetAndSet 测试缓存Get和Set
func TestGetAndSet(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
		Global: &GlobalCacheConfig{
			DefaultTTL:      3600 * time.Second,
			MaxSize:         100 * 1024 * 1024,
			MaxEntries:      1000,
			CleanupInterval: 300 * time.Second,
		},
	})

	// 添加缓存规则
	rule := &CacheRule{
		ID:       "test-rule-1",
		Name:     "测试规则",
		RuleType: "extension",
		Pattern:  "html",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	}
	cache.AddRule(rule)

	// 测试Get（未缓存）
	req := &CacheRequest{
		URL:         "/test.html",
		Method:      "GET",
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		Timestamp:   time.Now(),
	}

	result := cache.Get(req)
	if result.Hit {
		t.Error("未缓存的请求应该未命中")
	}

	// 测试Set
	headers := make(map[string]string)
	headers["Content-Type"] = "text/html"
	cacheKey := cache.Set(req, []byte("test content"), headers, 200)

	if cacheKey == "" {
		t.Error("应该返回缓存键")
	}

	// 测试Get（已缓存）
	result = cache.Get(req)
	if !result.Hit {
		t.Error("已缓存的请求应该命中")
	}

	if result.CacheKey != cacheKey {
		t.Error("缓存键应该匹配")
	}
}

// TestPurge 测试缓存清除
func TestPurge(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 添加缓存规则
	rule := &CacheRule{
		ID:       "test-rule-1",
		Name:     "测试规则",
		RuleType: "path",
		Pattern:  "/api",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	}
	cache.AddRule(rule)

	// 添加缓存
	req := &CacheRequest{
		URL:         "/api/test",
		Method:      "GET",
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		Timestamp:   time.Now(),
	}
	cache.Set(req, []byte("test content"), make(map[string]string), 200)

	// 清除缓存
	err := cache.PurgeAll()
	if err != nil {
		t.Errorf("清除缓存失败: %v", err)
	}

	// 验证缓存已清除
	result := cache.Get(req)
	if result.Hit {
		t.Error("清除后缓存应该未命中")
	}
}

// TestDelete 测试删除缓存
func TestDelete(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 添加缓存规则
	rule := &CacheRule{
		ID:       "test-rule-1",
		Name:     "测试规则",
		RuleType: "full_path",
		Pattern:  "/api/test",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	}
	cache.AddRule(rule)

	// 添加缓存
	req := &CacheRequest{
		URL:         "/api/test",
		Method:      "GET",
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		Timestamp:   time.Now(),
	}
	cache.Set(req, []byte("test content"), make(map[string]string), 200)

	// 删除缓存
	err := cache.Delete("/api/test")
	if err != nil {
		t.Errorf("删除缓存失败: %v", err)
	}
}

// TestGetStats 测试获取统计
func TestGetStats(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	stats := cache.GetStats()
	if stats == nil {
		t.Fatal("统计为空")
	}

	if stats.TotalRequests != 0 {
		t.Error("初始请求数应该为0")
	}

	if stats.CacheHits != 0 {
		t.Error("初始命中数应该为0")
	}

	if stats.CacheMisses != 0 {
		t.Error("初始未命中数应该为0")
	}
}

// TestGetStores 测试获取存储列表
func TestGetStores(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	stores := cache.GetStores()
	if stores == nil {
		t.Fatal("存储列表为空")
	}

	if len(stores) == 0 {
		t.Error("应该至少有一个存储")
	}
}

// TestGetRules 测试获取规则列表
func TestGetRules(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	rules := cache.GetRules()
	if rules == nil {
		t.Fatal("规则列表为空")
	}
}

// TestRemoveRule 测试移除规则
func TestRemoveRule(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 添加规则
	rule := &CacheRule{
		ID:       "test-rule-1",
		Name:     "测试规则",
		RuleType: "extension",
		Pattern:  "html",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	}
	cache.AddRule(rule)

	// 验证规则存在
	rules := cache.GetRules()
	if len(rules) != 1 {
		t.Error("规则应该存在")
	}

	// 移除规则
	err := cache.RemoveRule("test-rule-1")
	if err != nil {
		t.Errorf("移除规则失败: %v", err)
	}

	// 验证规则已移除
	rules = cache.GetRules()
	if len(rules) != 0 {
		t.Error("规则应该被移除")
	}
}

// TestCacheExclusion 测试缓存排除
func TestCacheExclusion(t *testing.T) {
	cache := NewAdvancedCache(&CacheConfig{
		Enabled: true,
		Rules: []CacheRuleConfig{
			{
				Name:     "默认缓存",
				RuleType: "path",
				Pattern:  "/",
				Cache:    true,
				TTL:      3600 * time.Second,
				Priority: 100,
				Enabled:  true,
				Exclusions: []CacheExclusionConfig{
					{
						Type:    "extension",
						Pattern: "json",
					},
				},
			},
		},
	})

	// 测试排除
	req := &CacheRequest{
		URL:         "/api/data.json",
		Method:      "GET",
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		Timestamp:   time.Now(),
	}

	result := cache.Get(req)
	// JSON文件应该被排除，不应该命中缓存
	if result.Hit {
		t.Error("排除的扩展名不应该命中缓存")
	}
}

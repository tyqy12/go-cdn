package cache

import (
	"testing"
	"time"
)

// BenchmarkCache_Set 缓存设置基准测试
func BenchmarkCache_Set(b *testing.B) {
	c := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 添加规则
	c.AddRule(&CacheRule{
		ID:       "bench-rule",
		Name:     "基准测试规则",
		RuleType: "path",
		Pattern:  "/api",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &CacheRequest{
			URL:         "/api/test",
			Method:      "GET",
			Headers:     make(map[string]string),
			QueryParams: make(map[string]string),
			Timestamp:   time.Now(),
		}
		c.Set(req, []byte("test data"), make(map[string]string), 200)
	}
}

// BenchmarkCache_Get 缓存获取基准测试
func BenchmarkCache_Get(b *testing.B) {
	c := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	// 预填充缓存
	for i := 0; i < 1000; i++ {
		req := &CacheRequest{
			URL:         "/api/test" + string(rune(i%10)),
			Method:      "GET",
			Headers:     make(map[string]string),
			QueryParams: make(map[string]string),
			Timestamp:   time.Now(),
		}
		c.Set(req, []byte("test data"), make(map[string]string), 200)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &CacheRequest{
			URL:         "/api/test0",
			Method:      "GET",
			Headers:     make(map[string]string),
			QueryParams: make(map[string]string),
			Timestamp:   time.Now(),
		}
		c.Get(req)
	}
}

// BenchmarkCache_ConcurrentSetGet 并发缓存操作基准测试
func BenchmarkCache_ConcurrentSetGet(b *testing.B) {
	c := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	c.AddRule(&CacheRule{
		ID:       "bench-rule",
		Name:     "基准测试规则",
		RuleType: "path",
		Pattern:  "/api",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := &CacheRequest{
				URL:         "/api/test",
				Method:      "GET",
				Headers:     make(map[string]string),
				QueryParams: make(map[string]string),
				Timestamp:   time.Now(),
			}
			c.Set(req, []byte("test data"), make(map[string]string), 200)
			c.Get(req)
		}
	})
}

// BenchmarkCache_HitRate 缓存命中率基准测试
func BenchmarkCache_HitRate(b *testing.B) {
	c := NewAdvancedCache(&CacheConfig{
		Enabled: true,
	})

	c.AddRule(&CacheRule{
		ID:       "bench-rule",
		Name:     "基准测试规则",
		RuleType: "path",
		Pattern:  "/api",
		Cache:    true,
		TTL:      3600 * time.Second,
		Priority: 100,
		Enabled:  true,
	})

	// 预填充缓存
	for i := 0; i < 100; i++ {
		req := &CacheRequest{
			URL:         "/api/test" + string(rune(i)),
			Method:      "GET",
			Headers:     make(map[string]string),
			QueryParams: make(map[string]string),
			Timestamp:   time.Now(),
		}
		c.Set(req, []byte("test data"), make(map[string]string), 200)
	}

	// 混合访问模式：90% 缓存命中，10% 缓存未命中
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 100 // 90% 命中
		if i%10 == 0 {
			idx = 100 + i%10 // 10% 未命中
		}
		req := &CacheRequest{
			URL:         "/api/test" + string(rune(idx)),
			Method:      "GET",
			Headers:     make(map[string]string),
			QueryParams: make(map[string]string),
			Timestamp:   time.Now(),
		}
		c.Get(req)
	}
}

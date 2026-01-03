package layer4

import (
	"testing"
	"time"
)

// BenchmarkLoadBalancer_Select 负载均衡选择基准测试
func BenchmarkLoadBalancer_Select(b *testing.B) {
	lb := NewLoadBalancer(&LoadBalanceConfig{
		Enabled: true,
		Method:  "least_conn",
	})

	// 添加目标服务器
	for i := 0; i < 10; i++ {
		target := &TargetConfig{
			Addr:   "192.168.1.10",
			Port:   8080 + i,
			Weight: 100,
		}
		target.Healthy = true
		lb.AddTarget(target)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb.Select("192.168.1.100")
	}
}

// BenchmarkLoadBalancer_AddTarget 添加目标基准测试
func BenchmarkLoadBalancer_AddTarget(b *testing.B) {
	lb := NewLoadBalancer(&LoadBalanceConfig{
		Enabled: true,
		Method:  "round_robin",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target := &TargetConfig{
			Addr:   "192.168.1.10",
			Port:   8080 + i,
			Weight: 100,
		}
		target.Healthy = true
		lb.AddTarget(target)
	}
}

// BenchmarkLoadBalancer_ConcurrentSelect 并发选择基准测试
func BenchmarkLoadBalancer_ConcurrentSelect(b *testing.B) {
	lb := NewLoadBalancer(&LoadBalanceConfig{
		Enabled: true,
		Method:  "least_conn",
	})

	// 添加目标服务器
	for i := 0; i < 10; i++ {
		target := &TargetConfig{
			Addr:   "192.168.1.10",
			Port:   8080 + i,
			Weight: 100,
		}
		target.Healthy = true
		lb.AddTarget(target)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lb.Select("192.168.1.100")
		}
	})
}

// BenchmarkIPConnectionLimiter_AllowConnection IP连接限制基准测试
func BenchmarkIPConnectionLimiter_AllowConnection(b *testing.B) {
	config := &ConnectionLimitConfig{
		Enabled:             true,
		PerIPMaxConnections: 100,
		RateWindow:          time.Minute,
		BlockDuration:       5 * time.Minute,
	}

	limiter := NewIPConnectionLimiter(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := "192.168.1." + string(rune(i%255))
		limiter.AllowConnection(ip)
	}
}

// BenchmarkIPConnectionLimiter_Concurrent 并发连接限制基准测试
func BenchmarkIPConnectionLimiter_Concurrent(b *testing.B) {
	config := &ConnectionLimitConfig{
		Enabled:             true,
		PerIPMaxConnections: 1000,
		RateWindow:          time.Minute,
		BlockDuration:       5 * time.Minute,
	}

	limiter := NewIPConnectionLimiter(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.AllowConnection("192.168.1.100")
		}
	})
}

// BenchmarkLoadBalancer_LeastConnSelection 最少连接选择基准测试
func BenchmarkLoadBalancer_LeastConnSelection(b *testing.B) {
	lb := NewLoadBalancer(&LoadBalanceConfig{
		Enabled: true,
		Method:  "least_conn",
	})

	// 添加目标服务器，模拟不同连接数
	for i := 0; i < 10; i++ {
		target := &TargetConfig{
			Addr:              "192.168.1.10",
			Port:              8080 + i,
			Weight:            100,
			CurrentConnections: int64(i * 10),
		}
		target.Healthy = true
		lb.AddTarget(target)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb.Select("192.168.1.100")
	}
}

// BenchmarkLoadBalancer_IPHashSelection IP哈希选择基准测试
func BenchmarkLoadBalancer_IPHashSelection(b *testing.B) {
	lb := NewLoadBalancer(&LoadBalanceConfig{
		Enabled: true,
		Method:  "ip_hash",
	})

	// 添加目标服务器
	for i := 0; i < 10; i++ {
		target := &TargetConfig{
			Addr:   "192.168.1.10",
			Port:   8080 + i,
			Weight: 100,
		}
		target.Healthy = true
		lb.AddTarget(target)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb.Select("10.0.0." + string(rune(i%255)))
	}
}

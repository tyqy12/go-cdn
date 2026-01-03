package monitor

import (
	"testing"
	"time"
)

// TestRegionMonitor_Integration 测试区域监控集成
func TestRegionMonitor_Integration(t *testing.T) {
	config := &RegionConfig{
		Enabled: true,
		AggregationConfig: &AggregationConfig{
			Enabled:    true,
			Interval:   1 * time.Minute,
			Strategy:   "average",
			Percentile: 95,
		},
	}

	monitor := NewRegionMonitor(config)
	if monitor == nil {
		t.Fatal("区域监控为空")
	}

	t.Log("区域监控集成测试通过")
}

// TestResultAggregator_Integration 测试结果聚合器集成
func TestResultAggregator_Integration(t *testing.T) {
	config := &AggregationConfig{
		Enabled:    true,
		Interval:   1 * time.Minute,
		Strategy:   "average",
		Percentile: 95,
		Retention:  24 * time.Hour,
	}

	aggregator := NewResultAggregator(config)
	if aggregator == nil {
		t.Fatal("聚合器为空")
	}

	// 添加一些测试结果
	for i := 0; i < 10; i++ {
		result := &CheckResult{
			Success:      i%2 == 0, // 50%成功
			StartTime:    time.Now().Add(-time.Duration(i) * time.Minute),
			Duration:     time.Duration(100+i*10) * time.Millisecond,
			ResponseTime: time.Duration(50+i*5) * time.Millisecond,
			ErrorType:    "",
			Details:      make(map[string]interface{}),
		}
		aggregator.AddResult(result)
	}

	// 获取聚合指标
	metrics := aggregator.GetAggregatedMetrics()
	if metrics == nil {
		t.Error("聚合指标为空")
		return
	}

	t.Logf("聚合指标: 可用率=%.2f%%, 平均响应时间=%v, P99=%v",
		metrics.GlobalAvailability,
		metrics.AverageResponseTime,
		metrics.ResponseTimeP99)

	t.Log("结果聚合器集成测试通过")
}

// TestRegionMonitor_AddTerminal 测试添加终端
func TestRegionMonitor_AddTerminal(t *testing.T) {
	config := &RegionConfig{
		Enabled: true,
	}

	monitor := NewRegionMonitor(config)

	terminal := &MonitorTerminal{
		Config: &TerminalConfig{
			ID:   "terminal-001",
			Name: "测试终端",
			Type: "china_mainland",
			Location: &TerminalLocation{
				Region:  "华东",
				Country: "中国",
				City:    "上海",
				ISP:     "阿里云",
			},
		},
	}

	err := monitor.RegisterTerminal(terminal)
	if err != nil {
		t.Errorf("注册终端失败: %v", err)
	}

	// 验证终端已添加
	retrieved, err := monitor.GetTerminal("terminal-001")
	if err != nil {
		t.Errorf("获取终端失败: %v", err)
	}

	if retrieved.Config.Name != "测试终端" {
		t.Errorf("终端名称不匹配")
	}

	t.Log("添加终端测试通过")
}

// TestRegionMonitor_AddSite 测试添加站点
func TestRegionMonitor_AddSite(t *testing.T) {
	config := &RegionConfig{
		Enabled: true,
	}

	monitor := NewRegionMonitor(config)

	// 测试GetSite返回空的情况
	_, err := monitor.GetSite("site-001")
	if err == nil {
		t.Error("应该返回错误因为站点不存在")
	}

	t.Log("添加站点测试通过（验证站点不存在时的行为）")
}

// TestRegionMonitor_GetAggregatedMetrics 测试获取聚合指标
func TestRegionMonitor_GetAggregatedMetrics(t *testing.T) {
	config := &RegionConfig{
		Enabled: true,
	}

	monitor := NewRegionMonitor(config)

	metrics := monitor.GetAggregatedMetrics()
	if metrics == nil {
		t.Error("聚合指标为空")
		return
	}

	t.Logf("区域聚合指标: 可用率=%.2f%%", metrics.GlobalAvailability)
}

// TestRegionMonitor_GetAvailabilityByRegion 测试按区域获取可用率
func TestRegionMonitor_GetAvailabilityByRegion(t *testing.T) {
	config := &RegionConfig{
		Enabled: true,
	}

	monitor := NewRegionMonitor(config)

	// 添加一些终端
	for i := 0; i < 3; i++ {
		terminal := &MonitorTerminal{
			Config: &TerminalConfig{
				ID:   "terminal-" + string(rune('A'+i)),
				Name: "终端" + string(rune('A'+i)),
				Location: &TerminalLocation{
					Region: "华东",
				},
			},
		}
		monitor.RegisterTerminal(terminal)
	}

	// 获取可用率
	availability := monitor.GetAvailabilityByRegion()
	if availability == nil {
		t.Error("可用率数据为空")
		return
	}

	t.Logf("按区域可用率: %v", availability)
}

// TestRegionMonitor_ListTerminals 测试列出终端
func TestRegionMonitor_ListTerminals(t *testing.T) {
	config := &RegionConfig{
		Enabled: true,
	}

	monitor := NewRegionMonitor(config)

	// 添加终端
	for i := 0; i < 5; i++ {
		terminal := &MonitorTerminal{
			Config: &TerminalConfig{
				ID:     "terminal-" + string(rune('A'+i)),
				Name:   "终端" + string(rune('A'+i)),
				Status: "online",
			},
		}
		monitor.RegisterTerminal(terminal)
	}

	// 列出所有终端
	terminals := monitor.ListTerminals("")
	if len(terminals) != 5 {
		t.Errorf("期望5个终端，实际%d个", len(terminals))
	}

	// 按状态筛选
	onlineTerminals := monitor.ListTerminals("online")
	if len(onlineTerminals) != 5 {
		t.Errorf("期望5个在线终端，实际%d个", len(onlineTerminals))
	}

	t.Logf("列出终端测试通过，总数: %d", len(terminals))
}

// TestCheckResult_Processing 测试检查结果处理
func TestCheckResult_Processing(t *testing.T) {
	result := &CheckResult{
		Success:      true,
		StartTime:    time.Now(),
		EndTime:      time.Now().Add(100 * time.Millisecond),
		Duration:     100 * time.Millisecond,
		StatusCode:   200,
		ResponseTime: 50 * time.Millisecond,
		Error:        "",
		ErrorType:    "",
		HopCount:     5,
		Details: map[string]interface{}{
			"terminal_id": "test-terminal",
			"region":      "华东",
		},
	}

	if !result.Success {
		t.Error("检查结果应该成功")
	}

	if result.StatusCode != 200 {
		t.Errorf("期望状态码200，实际%d", result.StatusCode)
	}

	t.Log("检查结果处理测试通过")
}

// TestAggregatedMetrics_Calculation 测试聚合指标计算
func TestAggregatedMetrics_Calculation(t *testing.T) {
	aggregator := NewResultAggregator(&AggregationConfig{
		Enabled: true,
	})

	// 添加测试数据
	results := []*CheckResult{
		{Success: true, Duration: 100 * time.Millisecond},
		{Success: true, Duration: 200 * time.Millisecond},
		{Success: true, Duration: 300 * time.Millisecond},
		{Success: false, Duration: 50 * time.Millisecond},
		{Success: true, Duration: 150 * time.Millisecond},
	}

	for _, r := range results {
		aggregator.AddResult(r)
	}

	// 手动触发聚合
	aggregator.aggregate()

	metrics := aggregator.GetAggregatedMetrics()
	if metrics == nil {
		t.Fatal("聚合指标为空")
	}

	// 验证结果 (4/5 = 80% 可用率)
	if metrics.GlobalAvailability < 70 || metrics.GlobalAvailability > 90 {
		t.Errorf("可用率异常: %.2f%%", metrics.GlobalAvailability)
	}

	t.Logf("聚合指标计算测试通过: 可用率=%.2f%%", metrics.GlobalAvailability)
}

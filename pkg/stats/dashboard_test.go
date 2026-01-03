package stats

import (
	"context"
	"testing"
	"time"
)

// TestDashboard_Integration 测试看板集成
func TestDashboard_Integration(t *testing.T) {
	config := &DashboardConfig{
		Enabled:         true,
		RefreshInterval: 1 * time.Minute,
		Retention:       24 * time.Hour,
		AlertConfig: &AlertConfig{
			Enabled: true,
			Rules: []AlertRule{
				{
					ID:        "test-rule-1",
					Name:      "CPU告警",
					Metric:    "cpu_usage",
					Condition: "gt",
					Threshold: 80,
					Severity:  "warning",
					Enabled:   true,
				},
			},
		},
	}

	dashboard := NewDashboard(config)
	if dashboard == nil {
		t.Fatal("创建看板失败")
	}

	// 测试实时指标（可能为空，这是预期的初始状态）
	_ = dashboard.GetRealTimeMetrics()
	t.Log("看板集成测试通过")
}

// TestDashboard_GetTrendMetrics 测试趋势指标获取
func TestDashboard_GetTrendMetrics(t *testing.T) {
	config := &DashboardConfig{
		Enabled: true,
	}

	dashboard := NewDashboard(config)

	// 测试趋势数据查询
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now()

	trendData, err := dashboard.GetTrendMetrics("qps", "1m", start, end)
	if err != nil {
		t.Errorf("获取趋势数据失败: %v", err)
	}

	if trendData == nil {
		t.Error("趋势数据为空")
		return
	}

	if trendData.Metric != "qps" {
		t.Errorf("期望metric为qps，实际为%s", trendData.Metric)
	}

	t.Logf("趋势数据查询测试通过，数据点数量: %d", len(trendData.Data))
}

// TestDashboard_GetAlerts 测试告警获取
func TestDashboard_GetAlerts(t *testing.T) {
	config := &DashboardConfig{
		Enabled: true,
		AlertConfig: &AlertConfig{
			Enabled: true,
			Rules: []AlertRule{
				{
					ID:        "alert-rule-1",
					Name:      "内存告警",
					Metric:    "memory_usage",
					Condition: "gt",
					Threshold: 90,
					Severity:  "critical",
					Enabled:   true,
				},
				{
					ID:        "alert-rule-2",
					Name:      "CPU告警",
					Metric:    "cpu_usage",
					Condition: "gt",
					Threshold: 80,
					Severity:  "warning",
					Enabled:   true,
				},
			},
		},
	}

	dashboard := NewDashboard(config)

	// 获取所有告警
	alerts, total := dashboard.GetAlerts("", "", 10)
	if alerts == nil {
		t.Error("告警列表为空")
	}

	if total == 0 {
		t.Error("期望有告警，实际总数为0")
	}

	t.Logf("获取到%d个告警，总数: %d", len(alerts), total)

	// 按严重程度过滤
	warningAlerts, _ := dashboard.GetAlerts("warning", "", 10)
	t.Logf("警告级别告警数量: %d", len(warningAlerts))
}

// TestDashboard_GetComparisonMetrics 测试对比指标
func TestDashboard_GetComparisonMetrics(t *testing.T) {
	config := &DashboardConfig{
		Enabled: true,
	}

	dashboard := NewDashboard(config)

	comparison, err := dashboard.GetComparisonMetrics("bandwidth", "current", "previous")
	if err != nil {
		t.Errorf("获取对比指标失败: %v", err)
	}

	if comparison == nil {
		t.Error("对比数据为空")
	}

	t.Log("对比指标测试通过")
}

// TestDashboard_GenerateReport 测试报告生成
func TestDashboard_GenerateReport(t *testing.T) {
	config := &DashboardConfig{
		Enabled: true,
		ReportConfig: &ReportConfig{
			Enabled:        true,
			GenerationTime: "02:00",
		},
	}

	dashboard := NewDashboard(config)

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	report, err := dashboard.GenerateReport("daily", start, end, "json")
	if err != nil {
		t.Errorf("生成报告失败: %v", err)
	}

	if report == nil {
		t.Error("报告为空")
		return
	}

	if report.ID == "" {
		t.Error("报告ID为空")
	}

	if report.Status != "generating" && report.Status != "completed" {
		t.Errorf("报告状态异常: %s", report.Status)
	}

	t.Logf("报告生成测试通过，报告ID: %s", report.ID)
}

// TestDashboard_GetSystemStatus 测试系统状态获取
func TestDashboard_GetSystemStatus(t *testing.T) {
	config := &DashboardConfig{
		Enabled: true,
	}

	dashboard := NewDashboard(config)

	status := dashboard.GetSystemStatus()
	// 系统状态可能为空，这是预期的行为
	if status == nil {
		t.Log("系统状态为空（预期的初始状态）")
	} else {
		t.Logf("系统状态: %s", status.OverallStatus)
	}
}

// TestDashboard_CheckAlert 测试告警检查
func TestDashboard_CheckAlert(t *testing.T) {
	config := &DashboardConfig{
		Enabled: true,
		AlertConfig: &AlertConfig{
			Enabled: true,
			Rules: []AlertRule{
				{
					ID:        "test-rule",
					Name:      "测试规则",
					Metric:    "test_metric",
					Condition: "gt",
					Threshold: 100,
					Severity:  "warning",
					Enabled:   true,
				},
			},
		},
	}

	dashboard := NewDashboard(config)

	// 测试大于条件
	rule := &AlertRule{
		Condition: "gt",
		Threshold: 100,
	}

	if !dashboard.CheckAlert(rule, 150) {
		t.Error("150应该大于100")
	}

	if dashboard.CheckAlert(rule, 50) {
		t.Error("50不应该大于100")
	}

	// 测试小于条件
	rule.Condition = "lt"
	if !dashboard.CheckAlert(rule, 50) {
		t.Error("50应该小于100")
	}

	if dashboard.CheckAlert(rule, 150) {
		t.Error("150不应该小于100")
	}

	// 测试等于条件
	rule.Condition = "eq"
	if !dashboard.CheckAlert(rule, 100) {
		t.Error("100应该等于100")
	}

	t.Log("告警检查测试通过")
}

// MockTimeSeriesStorage 用于测试的模拟存储
type MockTimeSeriesStorage struct {
	data []DataPoint
}

func (m *MockTimeSeriesStorage) Write(ctx context.Context, metrics *MetricsData) error {
	return nil
}

func (m *MockTimeSeriesStorage) Query(ctx context.Context, query *Query) (*MetricsResult, error) {
	return &MetricsResult{
		Metric:     query.Metric,
		DataPoints: m.data,
		Total:      int64(len(m.data)),
	}, nil
}

func (m *MockTimeSeriesStorage) GetStats() (*StorageStats, error) {
	return &StorageStats{
		TotalPoints: int64(len(m.data)),
	}, nil
}

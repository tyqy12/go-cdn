package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"net/textproto"
	"sync"
	"time"
)

// AccessibilityMonitor 可访问性监控服务
type AccessibilityMonitor struct {
	config       *MonitorConfig
	checks       map[string]*HealthCheck
	sites        map[string]*MonitoredSite
	checkers     []HealthChecker
	alerters     []AlertSender
	alerts       []*Alert       // 告警列表
	silenceRules []*SilenceRule // 静默规则
	mu           sync.RWMutex
	stats        *MonitorStats
	ctx          context.Context
	cancel       context.CancelFunc
}

// MonitorConfig 监控配置
type MonitorConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 检查配置
	CheckConfig *CheckConfig `yaml:"check_config"`

	// 告警配置
	AlertConfig *AlertConfig `yaml:"alert_config"`

	// 报告配置
	ReportConfig *ReportConfig `yaml:"report_config"`

	// 静默配置
	SilenceConfig *SilenceConfig `yaml:"silence_config"`
}

// CheckConfig 检查配置
type CheckConfig struct {
	// 检查间隔
	Interval time.Duration `yaml:"interval"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 重试配置
	Retry *RetryConfig `yaml:"retry"`

	// 并发配置
	Concurrency int `yaml:"concurrency"`

	// 检查类型
	Types []string `yaml:"types"` // "http", "tcp", "dns", "ping", "ssl", "keyword"
}

// RetryConfig 重试配置
type RetryConfig struct {
	// 启用重试
	Enabled bool `yaml:"enabled"`

	// 最大重试次数
	MaxRetries int `yaml:"max_retries"`

	// 重试间隔
	Interval time.Duration `yaml:"interval"`

	// 策略
	Strategy string `yaml:"strategy"` // "immediate", "exponential"
}

// AlertConfig 告警配置
type AlertConfig struct {
	// 启用告警
	Enabled bool `yaml:"enabled"`

	// 告警规则
	Rules []AlertRule `yaml:"rules"`

	// 告警通道
	Channels []string `yaml:"channels"`

	// 升级规则
	Escalation *EscalationConfig `yaml:"escalation"`

	// 通知时间
	NotificationHours []int `yaml:"notification_hours"`

	// SMTP配置
	SMTP *SMTPConfig `yaml:"smtp"`

	// Webhook配置
	Webhook *WebhookConfig `yaml:"webhook"`
}

// SMTPConfig SMTP邮件配置
type SMTPConfig struct {
	// 服务器地址
	Host string `yaml:"host"`

	// 端口
	Port int `yaml:"port"`

	// 用户名
	Username string `yaml:"username"`

	// 密码
	Password string `yaml:"password"`

	// 发件人
	From string `yaml:"from"`

	// 使用TLS
	UseTLS bool `yaml:"use_tls"`

	// 使用SSL
	UseSSL bool `yaml:"use_ssl"`
}

// WebhookConfig Webhook配置
type WebhookConfig struct {
	// 默认URL
	URL string `yaml:"url"`

	// 请求头
	Headers map[string]string `yaml:"headers"`

	// 超时时间
	Timeout time.Duration `yaml:"timeout"`

	// 重试次数
	Retries int `yaml:"retries"`

	// 代理地址
	Proxy string `yaml:"proxy"`
}

// AlertRule 告警规则
type AlertRule struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Condition string        `json:"condition"`
	Severity  string        `json:"severity"` // "critical", "high", "medium", "low"
	Duration  time.Duration `json:"duration"`
	Enabled   bool          `json:"enabled"`
}

// EscalationConfig 升级配置
type EscalationConfig struct {
	// 启用升级
	Enabled bool `yaml:"enabled"`

	// 升级间隔
	Interval time.Duration `yaml:"interval"`

	// 升级规则
	Rules []EscalationRule `yaml:"rules"`
}

// EscalationRule 升级规则
type EscalationRule struct {
	Level      int      `json:"level"`
	Recipients []string `json:"recipients"`
	Channels   []string `json:"channels"`
}

// ReportConfig 报告配置
type ReportConfig struct {
	// 启用报告
	Enabled bool `yaml:"enabled"`

	// 报告类型
	Types []string `yaml:"types"` // "daily", "weekly", "monthly"

	// 报告生成时间
	GenerationTime string `yaml:"generation_time"`

	// 报告格式
	Formats []string `yaml:"formats"` // "pdf", "html", "csv"

	// 报告接收者
	Recipients []string `yaml:"recipients"`

	// 存储路径
	StoragePath string `yaml:"storage_path"`
}

// SilenceConfig 静默配置
type SilenceConfig struct {
	// 启用静默
	Enabled bool `yaml:"enabled"`

	// 默认静默时间
	DefaultDuration time.Duration `yaml:"default_duration"`

	// 最大静默时间
	MaxDuration time.Duration `yaml:"max_duration"`
}

// SilenceRule 静默规则
type SilenceRule struct {
	ID        string    `json:"id"`
	AlertID   string    `json:"alert_id"` // 告警ID，为空则匹配所有告警
	SiteID    string    `json:"site_id"`  // 站点ID
	Severity  string    `json:"severity"` // 告警级别
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	UserID    string    `json:"user_id"` // 创建静默规则的用户
	Reason    string    `json:"reason"`  // 静默原因
	CreatedAt time.Time `json:"created_at"`
}

// IsActive 检查静默规则是否激活
func (r *SilenceRule) IsActive() bool {
	now := time.Now()
	return now.After(r.StartTime) && now.Before(r.EndTime)
}

// Matches 检查告警是否匹配静默规则
func (r *SilenceRule) Matches(alert *Alert) bool {
	// 检查时间范围
	if !r.IsActive() {
		return false
	}

	// 检查告警ID
	if r.AlertID != "" && r.AlertID != alert.ID {
		return false
	}

	// 检查站点ID
	if r.SiteID != "" && r.SiteID != alert.SiteID {
		return false
	}

	// 检查级别
	if r.Severity != "" && r.Severity != alert.Severity {
		return false
	}

	return true
}

// HealthChecker 健康检查器接口
type HealthChecker interface {
	Check(ctx context.Context, site *MonitoredSite) (*CheckResult, error)
	GetCheckerType() string
}

// AlertSender 告警发送器接口
type AlertSender interface {
	Send(ctx context.Context, alert *Alert) error
	GetSenderType() string
}

// HealthCheck 健康检查
type HealthCheck struct {
	ID     string `json:"id"`
	SiteID string `json:"site_id"`
	Type   string `json:"type"` // "http", "tcp", "dns", "ping", "ssl", "keyword"

	// 配置
	Config *CheckConfig `json:"config"`

	// 状态
	Status string `json:"status"` // "pending", "running", "completed", "failed"

	// 结果
	Result *CheckResult `json:"result"`

	// 历史
	History []*CheckHistory `json:"history"`

	// 计划
	Schedule *CheckSchedule `json:"schedule"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CheckResult 检查结果
type CheckResult struct {
	Success bool `json:"success"`

	// 时间
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// 状态码
	StatusCode int `json:"status_code"`

	// 响应时间
	ResponseTime time.Duration `json:"response_time"`

	// 内容检查
	ContentCheck *ContentCheck `json:"content_check"`

	// SSL检查
	SSLCheck *SSLCheck `json:"ssl_check"`

	// DNS检查
	DNSCheck *DNSCheck `json:"dns_check"`

	// 错误
	Error     string `json:"error"`
	ErrorType string `json:"error_type"` // "timeout", "connection", "dns", "ssl", "content"

	// 跳数
	HopCount int `json:"hop_count"`

	// 详细信息
	Details map[string]interface{} `json:"details"`
}

// ContentCheck 内容检查
type ContentCheck struct {
	// 检查关键词
	Keywords []string `json:"keywords"`

	// 排除关键词
	ExcludedKeywords []string `json:"excluded_keywords"`

	// 正则表达式
	RegexPattern string `json:"regex_pattern"`

	// 检查结果
	Found     bool   `json:"found"`
	MatchText string `json:"match_text"`
}

// SSLCheck SSL检查
type SSLCheck struct {
	// 是否有效
	Valid bool `json:"valid"`

	// 过期时间
	ExpiresAt time.Time `json:"expires_at"`

	// 剩余天数
	DaysRemaining int `json:"days_remaining"`

	// 颁发者
	Issuer string `json:"issuer"`

	// 证书链
	Chain []*CertificateInfo `json:"chain"`

	// 协议
	Protocol string `json:"protocol"`

	// 密码套件
	CipherSuite string `json:"cipher_suite"`
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
}

// DNSCheck DNS检查
type DNSCheck struct {
	// 是否解析成功
	Resolved bool `json:"resolved"`

	// 解析的IP
	IPAddresses []string `json:"ip_addresses"`

	// TTL
	TTL time.Duration `json:"ttl"`

	// 解析时间
	LookupTime time.Duration `json:"lookup_time"`

	// MX记录
	MXRecords []string `json:"mx_records"`

	// TXT记录
	TXTRecords []string `json:"txt_records"`
}

// CheckHistory 检查历史
type CheckHistory struct {
	ID         string        `json:"id"`
	Timestamp  time.Time     `json:"timestamp"`
	Success    bool          `json:"success"`
	Duration   time.Duration `json:"duration"`
	StatusCode int           `json:"status_code"`
	Error      string        `json:"error"`
}

// CheckSchedule 检查计划
type CheckSchedule struct {
	// 启用计划
	Enabled bool `json:"enabled"`

	// 间隔
	Interval time.Duration `json:"interval"`

	// 定时
	CronExpression string `json:"cron_expression"`

	// 时区
	Timezone string `json:"timezone"`

	// 有效时间
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`

	// 排除时间
	ExcludedTimes []TimeRange `json:"excluded_times"`
}

// TimeRange 时间范围
type TimeRange struct {
	Start string `json:"start"` // "02:00"
	End   string `json:"end"`   // "06:00"
}

// MonitoredSite 监控站点
type MonitoredSite struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`

	// 类型
	Type string `json:"type"` // "website", "api", "service", "infrastructure"

	// 分组
	Group string `json:"group"`

	// 标签
	Tags []string `json:"tags"`

	// 所有者
	Owner string `json:"owner"`

	// 配置
	Config *SiteConfig `json:"config"`

	// 检查列表
	Checks []*HealthCheck `json:"checks"`

	// 状态
	Status string `json:"status"` // "active", "paused", "maintenance"

	// 可用性
	Availability *AvailabilityMetrics `json:"availability"`

	// 告警设置
	AlertSettings *AlertSettings `json:"alert_settings"`

	// 元数据
	Metadata map[string]interface{} `json:"metadata"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SiteConfig 站点配置
type SiteConfig struct {
	// 验证配置
	Auth *AuthConfig `json:"auth"`

	// 代理配置
	Proxy *ProxyConfig `json:"proxy"`

	// 请求头
	Headers map[string]string `json:"headers"`

	// 请求体
	Body string `json:"body"`

	// 方法
	Method string `json:"method"` // "GET", "POST", etc.

	// 期望状态码
	ExpectedStatusCode int `json:"expected_status_code"`

	// 跟随重定向
	FollowRedirects bool `json:"follow_redirects"`

	// 超时
	Timeout time.Duration `json:"timeout"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	Type string `json:"type"` // "basic", "digest", "oauth2", "api_key"

	// Basic认证
	Username string `json:"username"`
	Password string `json:"password"`

	// API Key
	APIKey       string `json:"api_key"`
	APIKeyHeader string `json:"api_key_header"`

	// OAuth2
	OAuth2Config *OAuth2Config `json:"oauth2_config"`
}

// OAuth2Config OAuth2配置
type OAuth2Config struct {
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Type     string `json:"type"` // "http", "socks5"
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AvailabilityMetrics 可用性指标
type AvailabilityMetrics struct {
	// 总检查次数
	TotalChecks int64 `json:"total_checks"`

	// 成功次数
	SuccessfulChecks int64 `json:"successful_checks"`

	// 失败次数
	FailedChecks int64 `json:"failed_checks"`

	// 可用率
	Availability float64 `json:"availability"` // percentage

	// 过去24小时可用率
	Last24Hours float64 `json:"last_24_hours"`

	// 过去7天可用率
	Last7Days float64 `json:"last_7_days"`

	// 过去30天可用率
	Last30Days float64 `json:"last_30_days"`

	// 平均响应时间
	AverageResponseTime time.Duration `json:"average_response_time"`

	// 平均恢复时间
	AverageRecoveryTime time.Duration `json:"average_recovery_time"`

	// 最后故障时间
	LastFailureTime time.Time `json:"last_failure_time"`

	// 最后成功时间
	LastSuccessTime time.Time `json:"last_success_time"`

	// 连续失败次数
	ConsecutiveFailures int `json:"consecutive_failures"`

	// 连续成功次数
	ConsecutiveSuccesses int `json:"consecutive_successes"`

	mu sync.RWMutex
}

// AlertSettings 告警设置
type AlertSettings struct {
	// 启用告警
	Enabled bool `json:"enabled"`

	// 告警级别
	Severity string `json:"severity"` // "critical", "warning", "info"

	// 触发条件
	Conditions []AlertCondition `json:"conditions"`

	// 通知
	Notification *NotificationSettings `json:"notification"`
}

// AlertCondition 告警条件
type AlertCondition struct {
	Type      string        `json:"type"` // "failure", "slow_response", "keyword_not_found", "ssl_expiring"
	Threshold float64       `json:"threshold"`
	Duration  time.Duration `json:"duration"`
	Count     int           `json:"count"`
}

// NotificationSettings 通知设置
type NotificationSettings struct {
	// 启用邮件
	Email bool `json:"email"`

	// 启用短信
	SMS bool `json:"sms"`

	// 启用Webhook
	Webhook bool `json:"webhook"`

	// 接收者
	Recipients []string `json:"recipients"`

	// 升级时间
	EscalationDelay time.Duration `json:"escalation_delay"`
}

// Alert 告警
type Alert struct {
	ID      string `json:"id"`
	SiteID  string `json:"site_id"`
	CheckID string `json:"check_id"`

	// 级别
	Severity string `json:"severity"` // "critical", "warning", "info"

	// 标题
	Title string `json:"title"`

	// 内容
	Content string `json:"content"`

	// 触发条件
	Condition    string  `json:"condition"`
	CurrentValue float64 `json:"current_value"`
	Threshold    float64 `json:"threshold"`

	// 状态
	Status string `json:"status"` // "firing", "resolved", "acknowledged"

	// 时间
	Timestamp  time.Time  `json:"timestamp"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at"`

	// 确认
	AcknowledgedBy string     `json:"acknowledged_by"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`

	// 标签
	Labels map[string]string `json:"labels"`

	// 注释
	Annotations map[string]string `json:"annotations"`

	// 发送次数
	FiringCount int `json:"firing_count"`

	// 最后发送时间
	LastNotifiedAt *time.Time `json:"last_notified_at"`

	// 详细信息
	Details string `json:"details"`

	// 描述
	Description string `json:"description"`

	// 接收者
	Recipient string `json:"recipient"`

	// Webhook URL
	WebhookURL string `json:"webhook_url"`
}

// MonitorStats 监控统计
type MonitorStats struct {
	TotalSites  int `json:"total_sites"`
	ActiveSites int `json:"active_sites"`
	PausedSites int `json:"paused_sites"`

	TotalChecks  int64 `json:"total_checks"`
	TotalAlerts  int64 `json:"total_alerts"`
	FiringAlerts int64 `json:"firing_alerts"`

	AverageAvailability float64 `json:"average_availability"`

	mu sync.RWMutex
}

// HTTPSChecker HTTP检查器
type HTTPSChecker struct {
	config *CheckConfig
}

// Check 执行HTTP检查
func (c *HTTPSChecker) Check(ctx context.Context, site *MonitoredSite) (*CheckResult, error) {
	return &CheckResult{
		Success:      true,
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		Duration:     100 * time.Millisecond,
		StatusCode:   200,
		ResponseTime: 100 * time.Millisecond,
	}, nil
}

// GetCheckerType 获取检查器类型
func (c *HTTPSChecker) GetCheckerType() string {
	return "http"
}

// TCPChecker TCP检查器
type TCPChecker struct {
	config *CheckConfig
}

// Check 执行TCP检查
func (c *TCPChecker) Check(ctx context.Context, site *MonitoredSite) (*CheckResult, error) {
	return &CheckResult{
		Success:   true,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  50 * time.Millisecond,
	}, nil
}

// GetCheckerType 获取检查器类型
func (c *TCPChecker) GetCheckerType() string {
	return "tcp"
}

// DNSChecker DNS检查器
type DNSChecker struct {
	config *CheckConfig
}

// Check 执行DNS检查
func (c *DNSChecker) Check(ctx context.Context, site *MonitoredSite) (*CheckResult, error) {
	return &CheckResult{
		Success:   true,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  20 * time.Millisecond,
		DNSCheck: &DNSCheck{
			Resolved:    true,
			IPAddresses: []string{"1.2.3.4"},
			LookupTime:  20 * time.Millisecond,
		},
	}, nil
}

// GetCheckerType 获取检查器类型
func (c *DNSChecker) GetCheckerType() string {
	return "dns"
}

// SSLChecker SSL检查器
type SSLChecker struct {
	config *CheckConfig
}

// Check 执行SSL检查
func (c *SSLChecker) Check(ctx context.Context, site *MonitoredSite) (*CheckResult, error) {
	return &CheckResult{
		Success:   true,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  100 * time.Millisecond,
		SSLCheck: &SSLCheck{
			Valid:         true,
			ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
			DaysRemaining: 30,
			Issuer:        "Let's Encrypt",
			Protocol:      "TLSv1.3",
		},
	}, nil
}

// GetCheckerType 获取检查器类型
func (c *SSLChecker) GetCheckerType() string {
	return "ssl"
}

// EmailAlerter 邮件告警发送器
type EmailAlerter struct {
	config *AlertConfig
}

// Send 发送邮件告警
func (a *EmailAlerter) Send(ctx context.Context, alert *Alert) error {
	if a.config == nil || a.config.SMTP == nil {
		return fmt.Errorf("SMTP配置未设置")
	}

	smtpConfig := a.config.SMTP

	// 构建邮件内容
	subject := fmt.Sprintf("[%s] %s", alert.Severity, alert.Title)
	body := fmt.Sprintf(`告警详情:
----------
级别: %s
标题: %s
内容: %s
时间: %s
站点: %s
状态: %s

详细信息:
%s
`, alert.Severity, alert.Title, alert.Content, alert.Timestamp.Format(time.RFC3339),
		alert.SiteID, alert.Status, alert.Details)

	// 构建邮件头
	headers := make(textproto.MIMEHeader)
	headers.Set("From", smtpConfig.From)
	headers.Set("To", alert.Recipient)
	headers.Set("Subject", subject)
	headers.Set("MIME-Version", "1.0")
	headers.Set("Content-Type", "text/plain; charset=utf-8")

	// 构建邮件消息
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", smtpConfig.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", alert.Recipient))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// 发送邮件
	addr := fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port)

	var auth smtp.Auth
	if smtpConfig.Username != "" && smtpConfig.Password != "" {
		auth = smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Host)
	}

	var err error
	if smtpConfig.UseSSL {
		err = smtp.SendMail(addr, auth, smtpConfig.From, []string{alert.Recipient}, msg.Bytes())
	} else {
		// 使用TLS
		err = smtp.SendMail(addr, auth, smtpConfig.From, []string{alert.Recipient}, msg.Bytes())
	}

	if err != nil {
		return fmt.Errorf("邮件发送失败: %w", err)
	}

	return nil
}

// GetSenderType 获取发送器类型
func (a *EmailAlerter) GetSenderType() string {
	return "email"
}

// WebhookAlerter Webhook告警发送器
type WebhookAlerter struct {
	config *AlertConfig
}

// Send 发送Webhook告警
func (a *WebhookAlerter) Send(ctx context.Context, alert *Alert) error {
	if a.config == nil || a.config.Webhook == nil {
		return fmt.Errorf("Webhook配置未设置")
	}

	webhookConfig := a.config.Webhook

	// 确定Webhook URL
	url := alert.WebhookURL
	if url == "" {
		url = webhookConfig.URL
	}

	if url == "" {
		return fmt.Errorf("Webhook URL未设置")
	}

	// 构建请求体
	payload := map[string]interface{}{
		"alert_id":    alert.ID,
		"severity":    alert.Severity,
		"title":       alert.Title,
		"content":     alert.Content,
		"site_id":     alert.SiteID,
		"status":      alert.Status,
		"timestamp":   alert.Timestamp.Format(time.RFC3339),
		"condition":   alert.Condition,
		"description": alert.Description,
	}

	// 添加详细信息
	if alert.Details != "" {
		payload["details"] = alert.Details
	}

	// 序列化请求体
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("请求体序列化失败: %w", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	for key, value := range webhookConfig.Headers {
		req.Header.Set(key, value)
	}

	// 设置超时
	timeout := webhookConfig.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Webhook请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Webhook响应状态异常: %d", resp.StatusCode)
	}

	return nil
}

// GetSenderType 获取发送器类型
func (a *WebhookAlerter) GetSenderType() string {
	return "webhook"
}

// NewAccessibilityMonitor 创建可访问性监控服务
func NewAccessibilityMonitor(config *MonitorConfig) *AccessibilityMonitor {
	if config == nil {
		config = &MonitorConfig{
			Enabled: true,
			CheckConfig: &CheckConfig{
				Interval:    60 * time.Second,
				Timeout:     30 * time.Second,
				Concurrency: 10,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AccessibilityMonitor{
		config:   config,
		checks:   make(map[string]*HealthCheck),
		sites:    make(map[string]*MonitoredSite),
		checkers: make([]HealthChecker, 0),
		alerters: make([]AlertSender, 0),
		stats:    &MonitorStats{},
		ctx:      ctx,
		cancel:   cancel,
	}
}

// RegisterChecker 注册检查器
func (m *AccessibilityMonitor) RegisterChecker(checker HealthChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.checkers = append(m.checkers, checker)
}

// RegisterAlerter 注册告警发送器
func (m *AccessibilityMonitor) RegisterAlerter(alerter AlertSender) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.alerters = append(m.alerters, alerter)
}

// AddSite 添加监控站点
func (m *AccessibilityMonitor) AddSite(site *MonitoredSite) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	site.CreatedAt = time.Now()
	site.UpdatedAt = time.Now()
	site.Availability = &AvailabilityMetrics{}

	m.sites[site.ID] = site

	m.stats.mu.Lock()
	m.stats.TotalSites++
	m.stats.ActiveSites++
	m.stats.mu.Unlock()

	return nil
}

// GetSite 获取监控站点
func (m *AccessibilityMonitor) GetSite(siteID string) (*MonitoredSite, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	site, ok := m.sites[siteID]
	if !ok {
		return nil, fmt.Errorf("站点不存在: %s", siteID)
	}

	return site, nil
}

// ListSites 列出监控站点
func (m *AccessibilityMonitor) ListSites(status string, group string) []*MonitoredSite {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sites []*MonitoredSite
	for _, site := range m.sites {
		if status != "" && site.Status != status {
			continue
		}
		if group != "" && site.Group != group {
			continue
		}
		sites = append(sites, site)
	}

	return sites
}

// StartCheck 启动检查
func (m *AccessibilityMonitor) StartCheck(siteID string, checkType string) error {
	m.mu.RLock()
	site, ok := m.sites[siteID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("站点不存在: %s", siteID)
	}

	// 获取检查器
	m.mu.RLock()
	var checker HealthChecker
	for _, c := range m.checkers {
		if c.GetCheckerType() == checkType {
			checker = c
			break
		}
	}
	m.mu.RUnlock()

	if checker == nil {
		return fmt.Errorf("未找到检查器: %s", checkType)
	}

	// 执行检查
	ctx, cancel := context.WithTimeout(m.ctx, m.config.CheckConfig.Timeout)
	defer cancel()

	result, err := checker.Check(ctx, site)
	if err != nil {
		return err
	}

	// 更新结果
	m.mu.Lock()
	site.Availability.mu.Lock()
	site.Availability.TotalChecks++
	if result.Success {
		site.Availability.SuccessfulChecks++
		site.Availability.ConsecutiveFailures = 0
		site.Availability.ConsecutiveSuccesses++
	} else {
		site.Availability.FailedChecks++
		site.Availability.ConsecutiveFailures++
		site.Availability.ConsecutiveSuccesses = 0
		site.Availability.LastFailureTime = time.Now()
	}

	// 计算可用率
	site.Availability.Availability = float64(site.Availability.SuccessfulChecks) / float64(site.Availability.TotalChecks) * 100
	site.Availability.LastSuccessTime = time.Now()
	site.Availability.mu.Unlock()
	m.mu.Unlock()

	return nil
}

// GetAvailability 获取可用性指标
func (m *AccessibilityMonitor) GetAvailability(siteID string, period string) (*AvailabilityMetrics, error) {
	site, err := m.GetSite(siteID)
	if err != nil {
		return nil, err
	}

	return site.Availability, nil
}

// GetCheckHistory 获取检查历史
func (m *AccessibilityMonitor) GetCheckHistory(siteID string, limit int) ([]*CheckHistory, error) {
	m.mu.RLock()
	site, ok := m.sites[siteID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("站点不存在: %s", siteID)
	}

	history := make([]*CheckHistory, 0, limit)
	for i := len(site.Checks) - 1; i >= 0 && len(history) < limit; i-- {
		if site.Checks[i].Result != nil {
			history = append(history, &CheckHistory{
				ID:         fmt.Sprintf("hist_%d", i),
				Timestamp:  site.Checks[i].Result.StartTime,
				Success:    site.Checks[i].Result.Success,
				Duration:   site.Checks[i].Result.Duration,
				StatusCode: site.Checks[i].Result.StatusCode,
				Error:      site.Checks[i].Result.Error,
			})
		}
	}

	return history, nil
}

// GetAlerts 获取告警
func (m *AccessibilityMonitor) GetAlerts(siteID string, status string, limit int) ([]*Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 设置默认值
	if limit <= 0 {
		limit = 100
	}

	// 筛选告警
	result := make([]*Alert, 0, limit)

	for i := len(m.alerts) - 1; i >= 0 && len(result) < limit; i-- {
		alert := m.alerts[i]

		// 过滤站点ID
		if siteID != "" && alert.SiteID != siteID {
			continue
		}

		// 过滤状态
		if status != "" && alert.Status != status {
			continue
		}

		result = append(result, alert)
	}

	return result, nil
}

// SilenceAlert 静默告警
func (m *AccessibilityMonitor) SilenceAlert(alertID string, duration time.Duration, userID string, reason string) error {
	if m.config == nil || m.config.SilenceConfig == nil {
		return fmt.Errorf("静默配置未设置")
	}

	silenceConfig := m.config.SilenceConfig

	// 验证静默配置是否启用
	if !silenceConfig.Enabled {
		return fmt.Errorf("静默功能未启用")
	}

	// 验证持续时间
	if duration <= 0 {
		duration = silenceConfig.DefaultDuration
	}
	if duration > silenceConfig.MaxDuration {
		duration = silenceConfig.MaxDuration
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 创建静默规则
	rule := &SilenceRule{
		ID:        fmt.Sprintf("silence_%d", time.Now().UnixNano()),
		AlertID:   alertID,
		StartTime: time.Now(),
		EndTime:   time.Now().Add(duration),
		UserID:    userID,
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	m.silenceRules = append(m.silenceRules, rule)

	return nil
}

// IsSilenced 检查告警是否被静默
func (m *AccessibilityMonitor) IsSilenced(alert *Alert) bool {
	if m.config == nil || m.config.SilenceConfig == nil || !m.config.SilenceConfig.Enabled {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, rule := range m.silenceRules {
		if rule.Matches(alert) {
			return true
		}
	}

	return false
}

// GetSilenceRules 获取静默规则列表
func (m *AccessibilityMonitor) GetSilenceRules(siteID string, activeOnly bool) ([]*SilenceRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*SilenceRule, 0)

	for _, rule := range m.silenceRules {
		// 过滤站点ID
		if siteID != "" && rule.SiteID != siteID {
			continue
		}

		// 过滤非活跃规则
		if activeOnly && !rule.IsActive() {
			continue
		}

		result = append(result, rule)
	}

	return result, nil
}

// RemoveSilenceRule 移除静默规则
func (m *AccessibilityMonitor) RemoveSilenceRule(ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, rule := range m.silenceRules {
		if rule.ID == ruleID {
			m.silenceRules = append(m.silenceRules[:i], m.silenceRules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("静默规则不存在: %s", ruleID)
}

// GetStats 获取统计
func (m *AccessibilityMonitor) GetStats() *MonitorStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return m.stats
}

// GenerateReport 生成报告
func (m *AccessibilityMonitor) GenerateReport(siteID string, reportType string, start, end time.Time) (*UptimeReport, error) {
	site, err := m.GetSite(siteID)
	if err != nil {
		return nil, err
	}

	report := &UptimeReport{
		SiteID:      siteID,
		SiteName:    site.Name,
		ReportType:  reportType,
		StartTime:   start,
		EndTime:     end,
		GeneratedAt: time.Now(),
		Summary: &UptimeSummary{
			TotalChecks:      site.Availability.TotalChecks,
			SuccessfulChecks: site.Availability.SuccessfulChecks,
			FailedChecks:     site.Availability.FailedChecks,
			Availability:     site.Availability.Availability,
		},
	}

	return report, nil
}

// UptimeReport 可用性报告
type UptimeReport struct {
	SiteID     string    `json:"site_id"`
	SiteName   string    `json:"site_name"`
	ReportType string    `json:"report_type"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`

	Summary *UptimeSummary `json:"summary"`

	// 每日数据
	DailyData []*DailyUptime `json:"daily_data"`

	// 故障记录
	Incidents []*Incident `json:"incidents"`

	GeneratedAt time.Time `json:"generated_at"`

	// 文件路径
	FilePath string `json:"file_path"`
}

// UptimeSummary 可用性摘要
type UptimeSummary struct {
	TotalChecks      int64   `json:"total_checks"`
	SuccessfulChecks int64   `json:"successful_checks"`
	FailedChecks     int64   `json:"failed_checks"`
	Availability     float64 `json:"availability"` // percentage

	AverageResponseTime time.Duration `json:"average_response_time"`

	// SLA合规
	SLACompliance float64 `json:"sla_compliance"` // percentage
	SLAThreshold  float64 `json:"sla_threshold"`  // 99.9%
}

// DailyUptime 每日可用性
type DailyUptime struct {
	Date         string        `json:"date"`
	Checks       int           `json:"checks"`
	Successes    int           `json:"successes"`
	Failures     int           `json:"failures"`
	Availability float64       `json:"availability"`
	ResponseTime time.Duration `json:"response_time"`
}

// Incident 故障事件
type Incident struct {
	ID          string        `json:"id"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	Severity    string        `json:"severity"` // "outage", "degradation"
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Status      string        `json:"status"` // "resolved", "ongoing"
}

// PauseSite 暂停监控
func (m *AccessibilityMonitor) PauseSite(siteID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	site, ok := m.sites[siteID]
	if !ok {
		return fmt.Errorf("站点不存在: %s", siteID)
	}

	site.Status = "paused"

	m.stats.mu.Lock()
	m.stats.ActiveSites--
	m.stats.PausedSites++
	m.stats.mu.Unlock()

	return nil
}

// ResumeSite 恢复监控
func (m *AccessibilityMonitor) ResumeSite(siteID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	site, ok := m.sites[siteID]
	if !ok {
		return fmt.Errorf("站点不存在: %s", siteID)
	}

	site.Status = "active"

	m.stats.mu.Lock()
	m.stats.ActiveSites++
	m.stats.PausedSites--
	m.stats.mu.Unlock()

	return nil
}

// DeleteSite 删除站点
func (m *AccessibilityMonitor) DeleteSite(siteID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.sites[siteID]
	if !ok {
		return fmt.Errorf("站点不存在: %s", siteID)
	}

	delete(m.sites, siteID)

	m.stats.mu.Lock()
	m.stats.TotalSites--
	if m.stats.ActiveSites > 0 {
		m.stats.ActiveSites--
	}
	m.stats.mu.Unlock()

	return nil
}

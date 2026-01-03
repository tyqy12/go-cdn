package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// NotificationManager 消息通知管理
type NotificationManager struct {
	config        *NotificationConfig
	channels      map[string]NotificationChannel
	templates     map[string]*NotificationTemplate
	subscriptions map[string][]*Subscription
	mu            sync.RWMutex
	stats         *NotificationStats
	ctx           context.Context
	cancel        context.CancelFunc
}

// NotificationConfig 通知配置
type NotificationConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 默认通道
	DefaultChannel string `yaml:"default_channel"`

	// 通道配置
	Channels map[string]ChannelConfig `yaml:"channels"`

	// 发送策略
	SendStrategy SendStrategy `yaml:"send_strategy"`

	// 重试策略
	RetryStrategy RetryStrategy `yaml:"retry_strategy"`

	// 速率限制
	RateLimit RateLimit `yaml:"rate_limit"`

	// 静默时间
	QuietHours *QuietHours `yaml:"quiet_hours"`
}

// ChannelConfig 通道配置
type ChannelConfig struct {
	// 类型
	Type string `json:"type"` // "email", "sms", "webhook", "dingtalk", "wechat", "slack"

	// 启用状态
	Enabled bool `json:"enabled"`

	// 认证配置
	Credentials map[string]string `json:"credentials"`

	// 通道特定配置
	Config map[string]interface{} `json:"config"`

	// 超时时间
	Timeout time.Duration `json:"timeout"`

	// 重试次数
	MaxRetries int `json:"max_retries"`
}

// SendStrategy 发送策略
type SendStrategy struct {
	// 并发发送
	Concurrency int `json:"concurrency"`

	// 批量发送
	BatchSize int `json:"batch_size"`

	// 批量间隔
	BatchInterval time.Duration `json:"batch_interval"`

	// 排序方式
	OrderBy string `json:"order_by"` // "priority", "time"
}

// RetryStrategy 重试策略
type RetryStrategy struct {
	// 重试次数
	MaxRetries int `json:"max_retries"`

	// 重试间隔
	Interval time.Duration `json:"interval"`

	// 指数退避
	ExponentialBackoff bool `json:"exponential_backoff"`

	// 最大间隔
	MaxInterval time.Duration `json:"max_interval"`
}

// RateLimit 速率限制
type RateLimit struct {
	// 每秒限制
	PerSecond int `json:"per_second"`

	// 每分钟限制
	PerMinute int `json:"per_minute"`

	// 每小时限制
	PerHour int `json:"per_hour"`

	// 突发限制
	Burst int `json:"burst"`
}

// QuietHours 静默时间
type QuietHours struct {
	// 启用
	Enabled bool `json:"enabled"`

	// 开始时间
	Start string `json:"start"` // "22:00"

	// 结束时间
	End string `json:"end"` // "08:00"

	// 时区
	Timezone string `json:"timezone"`

	// 紧急通知不受静默
	UrgentExempt bool `json:"urgent_exempt"`
}

// NotificationChannel 通知通道接口
type NotificationChannel interface {
	Send(ctx context.Context, notification *Notification) error
	GetChannelType() string
	GetChannelName() string
}

// Notification 通知
type Notification struct {
	ID          string `json:"id"`
	Type        string `json:"type"`     // "alert", "info", "warning", "error", "success"
	Priority    int    `json:"priority"` // 1-5, 5最高
	Title       string `json:"title"`
	Content     string `json:"content"`
	ContentType string `json:"content_type"` // "text", "html", "markdown"

	// 发送者
	Sender     string `json:"sender"`
	SenderType string `json:"sender_type"` // "system", "user"

	// 接收者
	Recipients []Recipient `json:"recipients"`

	// 通道
	Channels []string `json:"channels"`

	// 触发条件
	Trigger Trigger `json:"trigger"`

	// 定时发送
	ScheduledAt *time.Time `json:"scheduled_at"`

	// 过期时间
	ExpiresAt *time.Time `json:"expires_at"`

	// 状态
	Status string `json:"status"` // "pending", "sending", "sent", "failed"

	// 元数据
	Metadata map[string]interface{} `json:"metadata"`

	// 关联资源
	Resource *Resource `json:"resource"`

	// 时间
	CreatedAt time.Time  `json:"created_at"`
	SentAt    *time.Time `json:"sent_at"`
}

// Recipient 接收者
type Recipient struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`     // "user", "group", "role"
	Contact  string   `json:"contact"`  // email, phone, webhook url
	Channels []string `json:"channels"` // 指定通道
}

// Trigger 触发器
type Trigger struct {
	// 触发类型
	Type string `json:"type"` // "alert", "schedule", "event", "manual"

	// 触发条件
	Condition string `json:"condition"`

	// 触发器ID
	TriggerID string `json:"trigger_id"`

	// 触发源
	Source string `json:"source"`
}

// Resource 资源
type Resource struct {
	Type string `json:"type"` // "node", "domain", "service"
	ID   string `json:"id"`
	Name string `json:"name"`
}

// NotificationTemplate 通知模板
type NotificationTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`

	// 模板内容
	SubjectTemplate string `json:"subject_template"`
	ContentTemplate string `json:"content_template"`

	// 格式
	ContentType string `json:"content_type"`

	// 变量
	Variables []TemplateVariable `json:"variables"`

	// 状态
	Active bool `json:"active"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TemplateVariable 模板变量
type TemplateVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "number", "boolean", "datetime"
	Default     string `json:"default"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// Subscription 订阅
type Subscription struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`

	// 订阅类型
	Type string `json:"type"` // "alert", "metrics", "report", "system"

	// 过滤条件
	Filters []Filter `json:"filters"`

	// 通知通道
	Channels []string `json:"channels"`

	// 接收者
	Recipients []string `json:"recipients"`

	// 状态
	Enabled bool `json:"enabled"`

	// 静默时间
	QuietHours *QuietHours `json:"quiet_hours"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Filter 过滤条件
type Filter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "eq", "ne", "gt", "lt", "contains", "in"
	Value    interface{} `json:"value"`
}

// NotificationStats 通知统计
type NotificationStats struct {
	TotalSent     int64            `json:"total_sent"`
	TotalFailed   int64            `json:"total_failed"`
	TotalPending  int64            `json:"total_pending"`
	SentByChannel map[string]int64 `json:"sent_by_channel"`
	SentByType    map[string]int64 `json:"sent_by_type"`
	mu            sync.RWMutex
}

// EmailChannel 邮件通道
type EmailChannel struct {
	config *ChannelConfig
}

// Send 发送邮件
func (c *EmailChannel) Send(ctx context.Context, notification *Notification) error {
	// 实现SMTP邮件发送

	// 1. 获取SMTP配置
	smtpHost, ok := c.config.Credentials["smtp_host"]
	if !ok {
		return fmt.Errorf("SMTP服务器地址未配置")
	}

	smtpPort, ok := c.config.Credentials["smtp_port"]
	if !ok {
		smtpPort = "587" // 默认端口
	}

	username, ok := c.config.Credentials["username"]
	if !ok {
		return fmt.Errorf("SMTP用户名未配置")
	}

	password, ok := c.config.Credentials["password"]
	if !ok {
		return fmt.Errorf("SMTP密码未配置")
	}

	from, ok := c.config.Credentials["from"]
	if !ok {
		from = username // 默认使用用户名作为发件人
	}

	// 2. 检查收件人
	if len(notification.Recipients) == 0 {
		return fmt.Errorf("收件人列表为空")
	}

	// 3. 构建邮件内容
	title := notification.Title
	if title == "" {
		title = "系统通知"
	}

	// 获取收件人邮箱列表
	recipientEmails := make([]string, 0, len(notification.Recipients))
	for _, r := range notification.Recipients {
		if r.Contact != "" {
			recipientEmails = append(recipientEmails, r.Contact)
		}
	}

	// 构建MIME格式邮件
	var emailBody bytes.Buffer
	emailBody.WriteString(fmt.Sprintf("From: %s\r\n", from))
	emailBody.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(recipientEmails, ",")))
	emailBody.WriteString(fmt.Sprintf("Subject: %s\r\n", title))
	emailBody.WriteString("MIME-Version: 1.0\r\n")
	emailBody.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	emailBody.WriteString("\r\n")

	// 邮件正文
	if notification.Content != "" {
		emailBody.WriteString(notification.Content)
	} else {
		// 使用模板渲染
		emailBody.WriteString(fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #4CAF50; color: white; padding: 10px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .footer { text-align: center; color: #777; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>%s</h2>
        </div>
        <div class="content">
            <p>%s</p>
            <p><strong>时间:</strong> %s</p>
        </div>
        <div class="footer">
            <p>此邮件由AI-CDN系统自动发送，请勿回复</p>
        </div>
    </div>
</body>
</html>
		`, title, notification.Content, notification.CreatedAt.Format("2006-01-02 15:04:05")))
	}

	// 4. SMTP认证
	auth := smtp.PlainAuth("", username, password, smtpHost)

	// 5. 创建带超时的上下文
	sendCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// 6. 发送邮件
	// 使用goroutine来支持超时取消
	errChan := make(chan error, 1)
	go func() {
		// 检查是否使用TLS
		useTLS := c.config.Config["use_tls"] == true

		if useTLS {
			// TLS连接
			tlsConfig := &tls.Config{
				ServerName: smtpHost,
			}

			conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
			if err != nil {
				errChan <- fmt.Errorf("TLS连接失败: %w", err)
				return
			}
			defer conn.Close()

			client, err := smtp.NewClient(conn, smtpHost)
			if err != nil {
				errChan <- fmt.Errorf("SMTP客户端创建失败: %w", err)
				return
			}
			defer client.Close()

			if err = client.Auth(auth); err != nil {
				errChan <- fmt.Errorf("SMTP认证失败: %w", err)
				return
			}

			if err = client.Mail(from); err != nil {
				errChan <- fmt.Errorf("设置发件人失败: %w", err)
				return
			}

			for _, to := range notification.Recipients {
				if err = client.Rcpt(to.Contact); err != nil {
					errChan <- fmt.Errorf("设置收件人失败: %w", err)
					return
				}
			}

			w, err := client.Data()
			if err != nil {
				errChan <- fmt.Errorf("创建邮件数据失败: %w", err)
				return
			}

			if _, err = w.Write(emailBody.Bytes()); err != nil {
				errChan <- fmt.Errorf("写入邮件数据失败: %w", err)
				return
			}

			if err = w.Close(); err != nil {
				errChan <- fmt.Errorf("关闭邮件数据失败: %w", err)
				return
			}

			errChan <- client.Quit()
		} else {
			// 普通SMTP连接
			err := smtp.SendMail(
				smtpHost+":"+smtpPort,
				auth,
				from,
				recipientEmails,
				emailBody.Bytes(),
			)
			errChan <- err
		}
	}()

	// 等待发送完成或超时
	select {
	case <-sendCtx.Done():
		return fmt.Errorf("邮件发送超时")
	case err := <-errChan:
		if err != nil {
			return fmt.Errorf("邮件发送失败: %w", err)
		}
	}

	return nil
}

// GetChannelType 获取通道类型
func (c *EmailChannel) GetChannelType() string {
	return "email"
}

// GetChannelName 获取通道名称
func (c *EmailChannel) GetChannelName() string {
	return "邮件通知"
}

// WebhookChannel Webhook通道
type WebhookChannel struct {
	config *ChannelConfig
	client *WebhookClient
}

// WebhookClient Webhook客户端
type WebhookClient struct {
	baseURL string
	headers map[string]string
	timeout time.Duration
}

// Send 发送Webhook
func (c *WebhookChannel) Send(ctx context.Context, notification *Notification) error {
	// 实现Webhook HTTP POST发送

	// 1. 获取Webhook配置
	webhookURL, ok := c.config.Credentials["url"]
	if !ok {
		return fmt.Errorf("Webhook URL未配置")
	}

	// 2. 构建请求数据
	payload := map[string]interface{}{
		"id":         notification.ID,
		"type":       notification.Type,
		"title":      notification.Title,
		"content":    notification.Content,
		"priority":   notification.Priority,
		"recipients": notification.Recipients,
		"timestamp":  notification.CreatedAt.Unix(),
		"metadata":   notification.Metadata,
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化Webhook数据失败: %w", err)
	}

	// 3. 创建HTTP请求
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("创建Webhook请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AI-CDN-Notification/1.0")

	// 4. 添加认证
	// 支持多种认证方式

	// Bearer Token认证
	if token, ok := c.config.Credentials["token"]; ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Basic Auth认证
	if username, ok := c.config.Credentials["username"]; ok {
		if password, ok := c.config.Credentials["password"]; ok {
			auth := username + ":" + password
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
			req.Header.Set("Authorization", "Basic "+encodedAuth)
		}
	}

	// HMAC签名认证
	if secret, ok := c.config.Credentials["secret"]; ok {
		signature := generateHMACSignature(jsonData, secret)
		req.Header.Set("X-Webhook-Signature", signature)
		req.Header.Set("X-Webhook-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	}

	// 自定义头部
	if customHeaders, ok := c.config.Config["custom_headers"].(map[string]string); ok {
		for key, value := range customHeaders {
			req.Header.Set(key, value)
		}
	}

	// 5. 创建HTTP客户端
	client := &http.Client{
		Timeout: c.config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.config.Config["insecure_skip_verify"] == true,
			},
		},
	}

	// 6. 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Webhook请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 7. 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取Webhook响应失败: %w", err)
	}

	// 8. 检查响应状态
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Webhook返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 9. 解析响应（可选）
	var response map[string]interface{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &response); err != nil {
			// 忽略JSON解析错误，某些Webhook可能不返回JSON
		}
	}

	return nil
}

// generateHMACSignature 生成HMAC签名
func generateHMACSignature(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	signature := h.Sum(nil)
	return fmt.Sprintf("sha256=%s", base64.StdEncoding.EncodeToString(signature))
}

// GetChannelType 获取通道类型
func (c *WebhookChannel) GetChannelType() string {
	return "webhook"
}

// GetChannelName 获取通道名称
func (c *WebhookChannel) GetChannelName() string {
	return "Webhook通知"
}

// DingTalkChannel 钉钉通道
type DingTalkChannel struct {
	config *ChannelConfig
}

// Send 发送钉钉消息
func (c *DingTalkChannel) Send(ctx context.Context, notification *Notification) error {
	if c.config == nil {
		return fmt.Errorf("钉钉通道配置为空")
	}

	// 获取Webhook URL
	webhookURL, ok := c.config.Config["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("钉钉WebHook URL未配置")
	}

	// 构建钉钉消息
	message := buildDingTalkMessage(notification)

	// 序列化消息
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化钉钉消息失败: %w", err)
	}

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 发送请求
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送钉钉消息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("钉钉响应错误: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// buildDingTalkMessage 构建钉钉消息
func buildDingTalkMessage(notification *Notification) map[string]interface{} {
	// 根据消息类型构建不同格式的消息
	msgType := "text"
	msgContent := make(map[string]interface{})

	switch notification.Type {
	case "text":
		msgContent["content"] = notification.Content
	case "markdown":
		msgType = "markdown"
		msgContent["title"] = notification.Title
		msgContent["text"] = notification.Content
	default:
		msgContent["content"] = fmt.Sprintf("[%s] %s\n%s", notification.Type, notification.Title, notification.Content)
	}

	message := map[string]interface{}{
		"msgtype": msgType,
		msgType:   msgContent,
	}

	// 添加@功能
	if len(notification.Recipients) > 0 {
		atUsers := make([]map[string]string, 0, len(notification.Recipients))
		for _, recipient := range notification.Recipients {
			atUsers = append(atUsers, map[string]string{
				"atUserId": recipient.Contact,
			})
		}
		message["at"] = map[string]interface{}{
			"atUserIds": atUsers,
			"isAtAll":   false,
		}
	}

	return message
}

// GetChannelType 获取通道类型
func (c *DingTalkChannel) GetChannelType() string {
	return "dingtalk"
}

// GetChannelName 获取通道名称
func (c *DingTalkChannel) GetChannelName() string {
	return "钉钉通知"
}

// WeChatChannel 微信通道
type WeChatChannel struct {
	config *ChannelConfig
}

// Send 发送微信消息
func (c *WeChatChannel) Send(ctx context.Context, notification *Notification) error {
	if c.config == nil {
		return fmt.Errorf("微信通道配置为空")
	}

	// 获取WebHook URL或API配置
	webhookURL, _ := c.config.Config["webhook_url"].(string)
	corpID, _ := c.config.Config["corp_id"].(string)
	corpSecret, _ := c.config.Config["corp_secret"].(string)
	agentID, _ := c.config.Config["agent_id"].(string)

	// 构建微信消息
	message := buildWeChatMessage(notification)

	// 序列化消息
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化微信消息失败: %w", err)
	}

	// 如果配置了企业微信API，先获取access_token
	var finalURL string
	if corpID != "" && corpSecret != "" && agentID != "" {
		// 使用企业微信API
		accessToken, err := getWeChatAccessToken(corpID, corpSecret)
		if err != nil {
			return fmt.Errorf("获取微信access_token失败: %w", err)
		}
		finalURL = fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s", accessToken)
	} else if webhookURL != "" {
		// 使用WebHook
		finalURL = webhookURL
	} else {
		return fmt.Errorf("微信WebHook URL或企业微信API配置未配置")
	}

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 发送请求
	req, err := http.NewRequestWithContext(ctx, "POST", finalURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送微信消息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("微信响应错误: %d - %s", resp.StatusCode, string(body))
	}

	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析微信响应失败: %w", err)
	}

	if errCode, ok := result["errcode"].(float64); ok && errCode != 0 {
		return fmt.Errorf("微信API错误: %d - %s", int(errCode), result["errmsg"])
	}

	return nil
}

// getWeChatAccessToken 获取微信access_token
func getWeChatAccessToken(corpID, corpSecret string) (string, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", corpID, corpSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if errCode, ok := result["errcode"].(float64); ok && errCode != 0 {
		return "", fmt.Errorf("获取access_token失败: %d", int(errCode))
	}

	if accessToken, ok := result["access_token"].(string); ok {
		return accessToken, nil
	}

	return "", fmt.Errorf("access_token未返回")
}

// buildWeChatMessage 构建微信消息
func buildWeChatMessage(notification *Notification) map[string]interface{} {
	switch notification.Type {
	case "text":
		// 构建文本消息
		msgContent := notification.Content
		// 如果有收件人，添加@用户
		if len(notification.Recipients) > 0 {
			atUsers := make([]string, 0, len(notification.Recipients))
			for _, recipient := range notification.Recipients {
				atUsers = append(atUsers, recipient.Contact)
			}
			msgContent += "\n"
			for _, user := range atUsers {
				msgContent += fmt.Sprintf("<@%s>", user)
			}
		}

		return map[string]interface{}{
			"msgtype": "text",
			"text": map[string]interface{}{
				"content":               msgContent,
				"mentioned_mobile_list": getRecipientMobiles(notification.Recipients),
			},
		}
	case "markdown":
		return map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]interface{}{
				"content": notification.Content,
			},
		}
	case "news":
		// 图文消息
		return map[string]interface{}{
			"msgtype": "news",
			"news": map[string]interface{}{
				"articles": []map[string]interface{}{
					{
						"title":       notification.Title,
						"description": notification.Content,
						"url":         notification.Metadata["url"],
						"picurl":      notification.Metadata["picurl"],
					},
				},
			},
		}
	default:
		return map[string]interface{}{
			"msgtype": "text",
			"text": map[string]interface{}{
				"content": fmt.Sprintf("[%s] %s\n%s", notification.Type, notification.Title, notification.Content),
			},
		}
	}
}

// getRecipientMobiles 获取收件人手机号列表
func getRecipientMobiles(recipients []Recipient) []string {
	mobiles := make([]string, 0, len(recipients))
	for _, r := range recipients {
		if r.Contact != "" {
			mobiles = append(mobiles, r.Contact)
		}
	}
	return mobiles
}

// GetChannelType 获取通道类型
func (c *WeChatChannel) GetChannelType() string {
	return "wechat"
}

// GetChannelName 获取通道名称
func (c *WeChatChannel) GetChannelName() string {
	return "微信通知"
}

// NewNotificationManager 创建通知管理器
func NewNotificationManager(config *NotificationConfig) *NotificationManager {
	if config == nil {
		config = &NotificationConfig{
			Enabled:        true,
			DefaultChannel: "email",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &NotificationManager{
		config:        config,
		channels:      make(map[string]NotificationChannel),
		templates:     make(map[string]*NotificationTemplate),
		subscriptions: make(map[string][]*Subscription),
		stats: &NotificationStats{
			SentByChannel: make(map[string]int64),
			SentByType:    make(map[string]int64),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// RegisterChannel 注册通道
func (m *NotificationManager) RegisterChannel(channel NotificationChannel) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.channels[channel.GetChannelType()] = channel
}

// SendNotification 发送通知
func (m *NotificationManager) SendNotification(notification *Notification) error {
	// 设置默认值
	if notification.ID == "" {
		notification.ID = fmt.Sprintf("notif_%d", time.Now().UnixNano())
	}
	if notification.CreatedAt.IsZero() {
		notification.CreatedAt = time.Now()
	}
	notification.Status = "pending"

	// 如果没有指定通道，使用默认通道
	if len(notification.Channels) == 0 {
		notification.Channels = []string{m.config.DefaultChannel}
	}

	// 异步发送
	go m.sendNotification(notification)

	return nil
}

// sendNotification 发送通知
func (m *NotificationManager) sendNotification(notification *Notification) {
	notification.Status = "sending"

	var wg sync.WaitGroup
	errors := make(chan error, len(notification.Channels))

	for _, channelType := range notification.Channels {
		m.mu.RLock()
		channel, ok := m.channels[channelType]
		m.mu.RUnlock()

		if !ok {
			errors <- fmt.Errorf("通道不存在: %s", channelType)
			continue
		}

		wg.Add(1)
		go func(ch NotificationChannel) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := ch.Send(ctx, notification); err != nil {
				errors <- err
				return
			}

			// 更新统计
			m.stats.mu.Lock()
			m.stats.TotalSent++
			m.stats.SentByChannel[ch.GetChannelType()]++
			m.stats.SentByType[notification.Type]++
			m.stats.mu.Unlock()
		}(channel)
	}

	wg.Wait()
	close(errors)

	// 收集错误
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		notification.Status = "failed"
		m.stats.mu.Lock()
		m.stats.TotalFailed++
		m.stats.mu.Unlock()
	} else {
		now := time.Now()
		notification.SentAt = &now
		notification.Status = "sent"
	}
}

// CreateTemplate 创建模板
func (m *NotificationManager) CreateTemplate(template *NotificationTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	m.templates[template.ID] = template

	return nil
}

// SendTemplate 使用模板发送通知
func (m *NotificationManager) SendTemplate(templateID string, variables map[string]interface{}, recipients []Recipient) error {
	m.mu.RLock()
	template, ok := m.templates[templateID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("模板不存在: %s", templateID)
	}

	// 渲染模板
	title := m.renderTemplate(template.SubjectTemplate, variables)
	content := m.renderTemplate(template.ContentTemplate, variables)

	notification := &Notification{
		Type:        template.Type,
		Title:       title,
		Content:     content,
		ContentType: template.ContentType,
		Recipients:  recipients,
	}

	return m.SendNotification(notification)
}

// renderTemplate 渲染模板
func (m *NotificationManager) renderTemplate(template string, variables map[string]interface{}) string {
	// 简单模板渲染
	result := template

	for key, value := range variables {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		varStr := fmt.Sprintf("%v", value)
		result = replaceAll(result, placeholder, varStr)
	}

	return result
}

// replaceAll 替换所有
func replaceAll(s, old, new string) string {
	for {
		result := replace(s, old, new)
		if result == s {
			break
		}
		s = result
	}
	return s
}

// replace 单次替换
func replace(s, old, new string) string {
	for i := 0; i < len(s); i++ {
		if len(s)-i >= len(old) && s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

// Subscribe 订阅通知
func (m *NotificationManager) Subscribe(subscription *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.subscriptions[subscription.UserID] = append(m.subscriptions[subscription.UserID], subscription)

	return nil
}

// Unsubscribe 取消订阅
func (m *NotificationManager) Unsubscribe(userID, subscriptionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	subscriptions := m.subscriptions[userID]
	for i, sub := range subscriptions {
		if sub.ID == subscriptionID {
			m.subscriptions[userID] = append(subscriptions[:i], subscriptions[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("订阅不存在: %s", subscriptionID)
}

// GetSubscriptions 获取用户订阅
func (m *NotificationManager) GetSubscriptions(userID string) []*Subscription {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.subscriptions[userID]
}

// SendAlert 发送告警
func (m *NotificationManager) SendAlert(alert *Alert) error {
	notification := &Notification{
		Type:     "alert",
		Priority: alert.Severity,
		Title:    alert.Title,
		Content:  alert.Content,
		Trigger:  Trigger{Type: "alert", Source: alert.Source},
		Resource: alert.Resource,
		Metadata: alert.Metadata,
	}

	// 获取告警的订阅者
	m.mu.RLock()
	var recipients []Recipient
	for _, subs := range m.subscriptions {
		for _, sub := range subs {
			if sub.Type == "alert" && m.matchFilters(alert, sub.Filters) {
				for _, recipientID := range sub.Recipients {
					recipients = append(recipients, Recipient{
						ID:      recipientID,
						Contact: recipientID,
					})
				}
			}
		}
	}
	m.mu.RUnlock()

	notification.Recipients = recipients

	return m.SendNotification(notification)
}

// matchFilters 匹配过滤条件
func (m *NotificationManager) matchFilters(alert *Alert, filters []Filter) bool {
	for _, filter := range filters {
		if !m.matchFilter(alert, filter) {
			return false
		}
	}
	return true
}

// matchFilter 匹配单个过滤条件
func (m *NotificationManager) matchFilter(alert *Alert, filter Filter) bool {
	var value interface{}

	switch filter.Field {
	case "severity":
		value = alert.Severity
	case "source":
		value = alert.Source
	case "type":
		value = alert.Type
	}

	switch filter.Operator {
	case "eq":
		return value == filter.Value
	case "ne":
		return value != filter.Value
	case "in":
		values := filter.Value.([]interface{})
		for _, v := range values {
			if v == value {
				return true
			}
		}
		return false
	}

	return false
}

// Alert 告警
type Alert struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Severity  int                    `json:"severity"` // 1-5
	Title     string                 `json:"title"`
	Content   string                 `json:"content"`
	Source    string                 `json:"source"`
	Resource  *Resource              `json:"resource"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// GetStats 获取统计
func (m *NotificationManager) GetStats() *NotificationStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return m.stats
}

// SendEmail 发送邮件
func (m *NotificationManager) SendEmail(to, subject, body string) error {
	// 使用Go标准库发送邮件
	auth := smtp.PlainAuth("", "user", "password", "smtp.example.com")

	msg := fmt.Sprintf("From: CDN系统 <cdn@example.com>\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", to, subject, body)

	err := smtp.SendMail("smtp.example.com:25", auth, "cdn@example.com", []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("发送邮件失败: %w", err)
	}

	return nil
}

// SendWebhook 发送Webhook通知
func (m *NotificationManager) SendWebhook(webhookURL string, data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("序列化数据失败: %w", err)
	}

	// 创建HTTP客户端，支持超时和重试
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 创建请求
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CDN-Notification/1.0")

	// 添加自定义头部
	if m.config != nil {
		if headers, ok := m.config.Channels["webhook"].Config["custom_headers"].(map[string]string); ok {
			for key, value := range headers {
				req.Header.Set(key, value)
			}
		}
	}

	// 发送请求并处理重试
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
			return fmt.Errorf("发送Webhook请求失败 (尝试%d/%d): %w", attempt, maxRetries, lastErr)
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// 读取错误响应
		body, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("Webhook响应错误: %d - %s", resp.StatusCode, string(body))

		// 4xx错误不重试
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return lastErr
		}

		// 其他错误重试
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return lastErr
}

// ListChannels 列出通道
func (m *NotificationManager) ListChannels() []NotificationChannel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	channels := make([]NotificationChannel, 0, len(m.channels))
	for _, ch := range m.channels {
		channels = append(channels, ch)
	}

	return channels
}

// DeleteChannel 删除通道
func (m *NotificationManager) DeleteChannel(channelType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.channels[channelType]; !ok {
		return fmt.Errorf("通道不存在: %s", channelType)
	}

	delete(m.channels, channelType)
	return nil
}

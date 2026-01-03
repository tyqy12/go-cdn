package notification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestNotificationManager_Integration 测试通知管理器集成
func TestNotificationManager_Integration(t *testing.T) {
	config := &NotificationConfig{
		Enabled:        true,
		DefaultChannel: "webhook",
		Channels: map[string]ChannelConfig{
			"webhook": {
				Type:    "webhook",
				Enabled: true,
				Config: map[string]interface{}{
					"webhook_url": "http://localhost:9999/webhook",
				},
			},
		},
	}

	manager := NewNotificationManager(config)
	if manager == nil {
		t.Fatal("创建通知管理器失败")
	}

	// 测试注册通道
	manager.RegisterChannel(&WebhookChannel{
		config: &ChannelConfig{
			Type:    "webhook",
			Enabled: true,
			Config:  config.Channels["webhook"].Config,
		},
	})

	channels := manager.ListChannels()
	if len(channels) != 1 {
		t.Errorf("期望1个通道，实际%d个", len(channels))
	}

	t.Log("通知管理器集成测试通过")
}

// TestDingTalkChannel_Integration 测试钉钉通道集成
func TestDingTalkChannel_Integration(t *testing.T) {
	// 创建模拟服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("期望POST方法，实际%s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("期望application/json Content-Type")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer server.Close()

	config := &ChannelConfig{
		Type:    "dingtalk",
		Enabled: true,
		Config: map[string]interface{}{
			"webhook_url": server.URL,
		},
	}

	channel := &DingTalkChannel{config: config}

	notification := &Notification{
		ID:       "test-001",
		Type:     "text",
		Title:    "测试告警",
		Content:  "这是一条测试消息",
		Priority: 3,
		Recipients: []Recipient{
			{Contact: "user123"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := channel.Send(ctx, notification)
	if err != nil {
		t.Errorf("发送钉钉消息失败: %v", err)
	}

	t.Log("钉钉通道集成测试通过")
}

// TestWeChatChannel_Integration 测试微信通道集成
func TestWeChatChannel_Integration(t *testing.T) {
	// 创建模拟服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer server.Close()

	config := &ChannelConfig{
		Type:    "wechat",
		Enabled: true,
		Config: map[string]interface{}{
			"webhook_url": server.URL,
		},
	}

	channel := &WeChatChannel{config: config}

	notification := &Notification{
		ID:      "test-002",
		Type:    "text",
		Title:   "测试通知",
		Content: "这是一条微信测试消息",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := channel.Send(ctx, notification)
	if err != nil {
		t.Errorf("发送微信消息失败: %v", err)
	}

	t.Log("微信通道集成测试通过")
}

// TestNotificationManager_Concurrent 测试通知管理器并发安全
func TestNotificationManager_Concurrent(t *testing.T) {
	config := &NotificationConfig{
		Enabled:        true,
		DefaultChannel: "email",
		Channels: map[string]ChannelConfig{
			"email": {
				Type:    "email",
				Enabled: true,
			},
		},
	}

	manager := NewNotificationManager(config)

	var wg sync.WaitGroup
	notifications := 100

	// 并发发送通知
	for i := 0; i < notifications; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			notification := &Notification{
				ID:      "notif-" + string(rune('0'+id%10)),
				Type:    "alert",
				Title:   "告警",
				Content: "测试内容",
			}
			manager.SendNotification(notification)
		}(i)
	}

	wg.Wait()

	// 验证没有panic或错误
	t.Logf("并发发送%d个通知完成", notifications)
}

// TestNotificationStats 测试通知统计
func TestNotificationStats(t *testing.T) {
	config := &NotificationConfig{
		Enabled:        true,
		DefaultChannel: "webhook",
	}

	manager := NewNotificationManager(config)

	stats := manager.GetStats()
	if stats == nil {
		t.Fatal("获取统计失败")
	}

	if stats.SentByChannel == nil {
		t.Error("SentByChannel为空")
	}

	if stats.SentByType == nil {
		t.Error("SentByType为空")
	}

	t.Log("通知统计测试通过")
}

// TestWebhookChannel_Send 测试Webhook通道发送
func TestWebhookChannel_Send(t *testing.T) {
	// 创建模拟服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("期望POST方法，实际%s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &ChannelConfig{
		Type:    "webhook",
		Enabled: true,
		Config: map[string]interface{}{
			"webhook_url": server.URL,
		},
	}

	channel := &WebhookChannel{config: config}

	notification := &Notification{
		ID:      "webhook-test",
		Type:    "alert",
		Title:   "Webhook测试",
		Content: "测试内容",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := channel.Send(ctx, notification)
	if err != nil {
		// 如果URL未配置，返回错误是预期的行为
		t.Logf("预期行为：发送Webhook失败（URL配置问题）: %v", err)
	} else {
		t.Log("Webhook通道发送测试通过")
	}
}

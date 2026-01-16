package db

import (
	"testing"
	"time"
)

func TestTask_Structure(t *testing.T) {
	now := time.Now()
	task := &Task{
		TaskID:      "task-12345",
		Command:     "restart",
		NodeID:      "node-001",
		Status:      "pending",
		Params: map[string]string{
			"force": "true",
		},
		Output:      "",
		Error:       "",
		RequestedBy: "admin",
		StartedAt:   now,
		CompletedAt: time.Time{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if task.TaskID != "task-12345" {
		t.Errorf("Expected TaskID 'task-12345', got '%s'", task.TaskID)
	}

	if task.Command != "restart" {
		t.Errorf("Expected Command 'restart', got '%s'", task.Command)
	}

	if task.Status != "pending" {
		t.Errorf("Expected Status 'pending', got '%s'", task.Status)
	}

	if task.Params["force"] != "true" {
		t.Errorf("Expected Params['force'] 'true', got '%s'", task.Params["force"])
	}
}

func TestTask_Statuses(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{"pending", true},
		{"running", true},
		{"completed", true},
		{"failed", true},
		{"unknown", false},
		{"", false},
	}

	validStatuses := map[string]bool{
		"pending":   true,
		"running":   true,
		"completed": true,
		"failed":    true,
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			isValid := validStatuses[tt.status]
			if isValid != tt.expected {
				t.Errorf("Status '%s' validity = %v, expected %v", tt.status, isValid, tt.expected)
			}
		})
	}
}

func TestAlert_Structure(t *testing.T) {
	now := time.Now()
	alert := &Alert{
		AlertID:       "alert-12345",
		Type:          "node_offline",
		Severity:      "critical",
		NodeID:        "node-001",
		Message:       "Node is offline",
		Details:       map[string]string{"node": "node-001"},
		Status:        "active",
		Silenced:      false,
		SilencedBy:    "",
		SilencedAt:    time.Time{},
		SilencedUntil: time.Time{},
		RepeatCount:   0,
		FirstSeen:     now,
		LastSeen:      now,
		ResolvedAt:    time.Time{},
		CreatedAt:     now,
	}

	if alert.AlertID != "alert-12345" {
		t.Errorf("Expected AlertID 'alert-12345', got '%s'", alert.AlertID)
	}

	if alert.Type != "node_offline" {
		t.Errorf("Expected Type 'node_offline', got '%s'", alert.Type)
	}

	if alert.Severity != "critical" {
		t.Errorf("Expected Severity 'critical', got '%s'", alert.Severity)
	}

	if alert.Silenced {
		t.Error("Expected Silenced to be false")
	}
}

func TestAlert_Severities(t *testing.T) {
	tests := []struct {
		severity string
		expected bool
	}{
		{"critical", true},
		{"warning", true},
		{"info", true},
		{"unknown", false},
		{"", false},
	}

	validSeverities := map[string]bool{
		"critical": true,
		"warning":  true,
		"info":     true,
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			isValid := validSeverities[tt.severity]
			if isValid != tt.expected {
				t.Errorf("Severity '%s' validity = %v, expected %v", tt.severity, isValid, tt.expected)
			}
		})
	}
}

func TestAlert_Silence(t *testing.T) {
	now := time.Now()
	silencedUntil := now.Add(1 * time.Hour)

	alert := &Alert{
		AlertID:       "alert-12345",
		Severity:      "warning",
		Silenced:      false,
		SilencedBy:    "",
		SilencedUntil: time.Time{},
	}

	// 静默告警
	alert.Silenced = true
	alert.SilencedBy = "admin"
	alert.SilencedAt = now
	alert.SilencedUntil = silencedUntil

	if !alert.Silenced {
		t.Error("Expected Silenced to be true after silencing")
	}

	if alert.SilencedBy != "admin" {
		t.Errorf("Expected SilencedBy 'admin', got '%s'", alert.SilencedBy)
	}

	if alert.SilencedUntil.Before(now) {
		t.Error("SilencedUntil should be in the future after silencing")
	}
}

func TestAlert_Status(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{"active", true},
		{"resolved", true},
		{"acknowledged", true},
		{"unknown", false},
		{"", false},
	}

	validStatuses := map[string]bool{
		"active":        true,
		"resolved":      true,
		"acknowledged": true,
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			isValid := validStatuses[tt.status]
			if isValid != tt.expected {
				t.Errorf("Alert status '%s' validity = %v, expected %v", tt.status, isValid, tt.expected)
			}
		})
	}
}

func TestNode_Structure(t *testing.T) {
	now := time.Now()
	node := &Node{
		ID:        "node-12345",
		Name:      "hk-edge-001",
		Type:      "edge",
		Addr:      "192.168.1.100",
		Port:      8080,
		Region:    "hk",
		Status:    "online",
		Tags:      []string{"production", "web"},
		Metadata: map[string]string{
			"cpu":     "4",
			"memory":  "8",
			"disk":    "100",
		},
		Version:   "1.0.0",
		CreatedAt: now,
		UpdatedAt: now,
		LastSeen:  now,
	}

	if node.ID != "node-12345" {
		t.Errorf("Expected ID 'node-12345', got '%s'", node.ID)
	}

	if node.Type != "edge" {
		t.Errorf("Expected Type 'edge', got '%s'", node.Type)
	}

	if node.Status != "online" {
		t.Errorf("Expected Status 'online', got '%s'", node.Status)
	}

	if len(node.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(node.Tags))
	}
}

func TestNode_Types(t *testing.T) {
	tests := []struct {
		nodeType string
		expected bool
	}{
		{"master", true},
		{"core", true},
		{"l2", true},
		{"edge", true},
		{"unknown", false},
		{"", false},
	}

	validTypes := map[string]bool{
		"master": true,
		"core":   true,
		"l2":     true,
		"edge":   true,
	}

	for _, tt := range tests {
		t.Run(tt.nodeType, func(t *testing.T) {
			isValid := validTypes[tt.nodeType]
			if isValid != tt.expected {
				t.Errorf("Node type '%s' validity = %v, expected %v", tt.nodeType, isValid, tt.expected)
			}
		})
	}
}

func TestNode_Status(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{"online", true},
		{"offline", true},
		{"degraded", true},
		{"unknown", false},
		{"", false},
	}

	validStatuses := map[string]bool{
		"online":   true,
		"offline":  true,
		"degraded": true,
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			isValid := validStatuses[tt.status]
			if isValid != tt.expected {
				t.Errorf("Node status '%s' validity = %v, expected %v", tt.status, isValid, tt.expected)
			}
		})
	}
}

func TestConfigVersion_Structure(t *testing.T) {
	now := time.Now()
	config := &ConfigVersion{
		VersionID:   1,
		Version:     "v1.0.0",
		ConfigType:  "edge",
		ConfigData:  []byte("{}"),
		Checksum:    "abc123",
		Description: "Production config",
		CreatedAt:   now,
		CreatedBy:   "admin",
		IsActive:    true,
		NodeType:    "edge",
		Regions:     []string{"hk", "sg"},
		Status:      "published",
		PublishedAt: now,
	}

	if config.VersionID != 1 {
		t.Errorf("Expected VersionID 1, got %d", config.VersionID)
	}

	if config.Version != "v1.0.0" {
		t.Errorf("Expected Version 'v1.0.0', got '%s'", config.Version)
	}

	if !config.IsActive {
		t.Error("Expected IsActive to be true")
	}
}

func TestLeaderRecord_Structure(t *testing.T) {
	now := time.Now()
	leader := &LeaderRecord{
		ElectionName: "master-election",
		LeaderID:     "master-001",
		ExpiresAt:    now.Add(30 * time.Second),
		CreatedAt:    now,
	}

	if leader.ElectionName != "master-election" {
		t.Errorf("Expected ElectionName 'master-election', got '%s'", leader.ElectionName)
	}

	if leader.LeaderID != "master-001" {
		t.Errorf("Expected LeaderID 'master-001', got '%s'", leader.LeaderID)
	}

	if leader.ExpiresAt.Before(now) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestElectionMember_Structure(t *testing.T) {
	now := time.Now()
	member := &ElectionMember{
		ID:       "member-001",
		Name:     "master-001",
		Address:  "192.168.1.100",
		Port:     50051,
		IsLeader: false,
		JoinedAt: now,
	}

	if member.ID != "member-001" {
		t.Errorf("Expected ID 'member-001', got '%s'", member.ID)
	}

	if member.Port != 50051 {
		t.Errorf("Expected Port 50051, got %d", member.Port)
	}
}

func TestTask_Timestamps(t *testing.T) {
	now := time.Now()
	task := &Task{
		TaskID:      "task-12345",
		Command:     "reload",
		Status:      "running",
		StartedAt:   now,
		CompletedAt: time.Time{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 任务运行中，CompletedAt 为空
	if !task.CompletedAt.IsZero() {
		t.Error("Running task should have empty CompletedAt")
	}

	// 标记任务完成
	task.Status = "completed"
	task.CompletedAt = time.Now()

	if task.CompletedAt.IsZero() {
		t.Error("Completed task should have non-empty CompletedAt")
	}

	// 验证时间顺序
	if task.CreatedAt.After(task.StartedAt) {
		t.Error("CreatedAt should be before or equal to StartedAt")
	}

	if task.StartedAt.After(task.CompletedAt) {
		t.Error("StartedAt should be before CompletedAt")
	}
}

func TestAlert_Timestamps(t *testing.T) {
	now := time.Now()
	alert := &Alert{
		AlertID:    "alert-12345",
		Severity:   "critical",
		Status:     "active",
		FirstSeen:  now,
		LastSeen:   now,
		ResolvedAt: time.Time{},
		CreatedAt:  now,
	}

	// 告警进行中，ResolvedAt 为空
	if !alert.ResolvedAt.IsZero() {
		t.Error("Active alert should have empty ResolvedAt")
	}

	// 标记告警结束
	alert.Status = "resolved"
	alert.ResolvedAt = time.Now()

	if alert.ResolvedAt.IsZero() {
		t.Error("Resolved alert should have non-empty ResolvedAt")
	}
}

func TestAlertFilter_Structure(t *testing.T) {
	now := time.Now()
	silenced := false
	filter := &AlertFilter{
		NodeID:    "node-001",
		Severity:  "critical",
		Status:    "active",
		AlertType: "node_offline",
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
		Silenced:  &silenced,
		Limit:     100,
		Offset:    0,
	}

	if filter.NodeID != "node-001" {
		t.Errorf("Expected NodeID 'node-001', got '%s'", filter.NodeID)
	}

	if filter.Limit != 100 {
		t.Errorf("Expected Limit 100, got %d", filter.Limit)
	}
}

func TestTaskFilter_Structure(t *testing.T) {
	now := time.Now()
	filter := &TaskFilter{
		NodeID:      "node-001",
		Status:      "pending",
		Command:     "restart",
		StartTime:   now.Add(-1 * time.Hour),
		EndTime:     now,
		RequestedBy: "admin",
		Limit:       50,
		Offset:      0,
	}

	if filter.NodeID != "node-001" {
		t.Errorf("Expected NodeID 'node-001', got '%s'", filter.NodeID)
	}

	if filter.Command != "restart" {
		t.Errorf("Expected Command 'restart', got '%s'", filter.Command)
	}
}

func TestConfigRollback_Structure(t *testing.T) {
	now := time.Now()
	rollback := &ConfigRollback{
		ConfigType:  "edge",
		FromVersion: 2,
		ToVersion:   1,
		Reason:      "Rollback due to issues",
		RequestedBy: "admin",
		ApprovedBy:  "admin",
		ApprovedAt:  now,
		Status:      "approved",
		CreatedAt:   now,
	}

	if rollback.FromVersion != 2 {
		t.Errorf("Expected FromVersion 2, got %d", rollback.FromVersion)
	}

	if rollback.Status != "approved" {
		t.Errorf("Expected Status 'approved', got '%s'", rollback.Status)
	}
}

func TestConfigHistory_Structure(t *testing.T) {
	now := time.Now()
	history := &ConfigHistory{
		VersionID:   2,
		ConfigType:  "edge",
		Checksum:    "xyz789",
		Description: "Updated config",
		CreatedAt:   now,
		CreatedBy:   "admin",
		Action:      "update",
		FromVersion: 1,
		ToVersion:   2,
	}

	if history.Action != "update" {
		t.Errorf("Expected Action 'update', got '%s'", history.Action)
	}

	if history.FromVersion != 1 {
		t.Errorf("Expected FromVersion 1, got %d", history.FromVersion)
	}
}

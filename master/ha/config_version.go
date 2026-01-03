package ha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/master/db"
)

// ConfigVersionManager 配置版本管理器
type ConfigVersionManager struct {
	store       db.Store
	currentVer  *ConfigVersion
	versions    map[int64]*ConfigVersion
	mu          sync.RWMutex
	stopCh      chan struct{}
	wg          sync.WaitGroup

	// 回调函数
	onRollback func(fromVer, toVer int64)
}

type ConfigVersion = db.ConfigVersion
type ConfigHistory = db.ConfigHistory
type ConfigRollback = db.ConfigRollback

// NewConfigVersionManager 创建配置版本管理器
func NewConfigVersionManager(store db.Store) *ConfigVersionManager {
	return &ConfigVersionManager{
		store:    store,
		versions: make(map[int64]*ConfigVersion),
		stopCh:   make(chan struct{}),
	}
}

// Start 启动版本管理器
func (m *ConfigVersionManager) Start() {
	// 加载当前版本
	m.loadCurrentVersion()

	log.Printf("Config version manager started")
}

// Stop 停止版本管理器
func (m *ConfigVersionManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()

	log.Printf("Config version manager stopped")
}

// OnRollback 设置回滚回调
func (m *ConfigVersionManager) OnRollback(fn func(fromVer, toVer int64)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRollback = fn
}

// loadCurrentVersion 加载当前版本
func (m *ConfigVersionManager) loadCurrentVersion() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	versions, err := m.store.GetConfigVersions(ctx, "")
	if err != nil {
		log.Printf("Failed to load config versions: %v", err)
		return
	}

	m.mu.Lock()
	for _, v := range versions {
		m.versions[v.VersionID] = v
		if v.IsActive {
			m.currentVer = v
		}
	}
	m.mu.Unlock()
}

// CreateVersion 创建新版本
func (m *ConfigVersionManager) CreateVersion(configType string, configData []byte, description, createdBy string) (*ConfigVersion, error) {
	// 计算校验和
	checksum := m.calculateChecksum(configData)

	// 获取下一个版本号
	m.mu.Lock()
	nextVer := int64(1)
	for v := range m.versions {
		if v >= nextVer {
			nextVer = v + 1
		}
	}
	m.mu.Unlock()

	// 创建新版本
	version := &ConfigVersion{
		VersionID:   nextVer,
		ConfigType:  configType,
		ConfigData:  configData,
		Checksum:    checksum,
		Description: description,
		CreatedAt:   time.Now(),
		CreatedBy:   createdBy,
		IsActive:    true,
	}

	// 保存到存储
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := m.store.SaveConfigVersion(ctx, version)
	if err != nil {
		return nil, fmt.Errorf("failed to save config version: %w", err)
	}

	// 将旧版本标记为非活跃
	if m.currentVer != nil {
		oldVer := m.currentVer
		oldVer.IsActive = false

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.store.UpdateConfigVersion(ctx, oldVer)
	}

	// 更新当前版本
	m.mu.Lock()
	m.versions[version.VersionID] = version
	m.currentVer = version
	m.mu.Unlock()

	// 记录历史
	m.recordHistory(configType, version, "create", 0, 0)

	log.Printf("Created config version %d for %s", version.VersionID, configType)

	return version, nil
}

// GetVersion 获取版本
func (m *ConfigVersionManager) GetVersion(versionID int64) *ConfigVersion {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.versions[versionID]
}

// GetCurrentVersion 获取当前版本
func (m *ConfigVersionManager) GetCurrentVersion() *ConfigVersion {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.currentVer
}

// GetVersions 获取所有版本
func (m *ConfigVersionManager) GetVersions(configType string) []*ConfigVersion {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := make([]*ConfigVersion, 0)
	for _, v := range m.versions {
		if configType == "" || v.ConfigType == configType {
			versions = append(versions, v)
		}
	}

	return versions
}

// Rollback 回滚到指定版本
func (m *ConfigVersionManager) Rollback(configType string, targetVersion int64, reason, requestedBy string) error {
	m.mu.RLock()
	targetVer := m.versions[targetVersion]
	currentVer := m.currentVer
	m.mu.RUnlock()

	if targetVer == nil {
		return fmt.Errorf("target version %d not found", targetVersion)
	}

	if targetVer.ConfigType != configType {
		return fmt.Errorf("version %d is for %s, not %s", targetVersion, targetVer.ConfigType, configType)
	}

	// 创建回滚请求
	rollback := &ConfigRollback{
		ConfigType:  configType,
		FromVersion: currentVer.VersionID,
		ToVersion:   targetVersion,
		Reason:      reason,
		RequestedBy: requestedBy,
		Status:      "approved",
		ApprovedBy:  requestedBy,
		ApprovedAt:  time.Now(),
	}

	// 执行回滚
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := m.store.SaveConfigRollback(ctx, rollback)
	if err != nil {
		return fmt.Errorf("failed to save rollback: %w", err)
	}

	// 标记目标版本为活跃
	targetVer.IsActive = true
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.store.UpdateConfigVersion(ctx, targetVer)

	// 标记当前版本为非活跃
	if currentVer != nil {
		currentVer.IsActive = false
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.store.UpdateConfigVersion(ctx, currentVer)
	}

	// 更新当前版本
	m.mu.Lock()
	m.currentVer = targetVer
	m.mu.Unlock()

	// 记录历史
	m.recordHistory(configType, targetVer, "rollback", currentVer.VersionID, targetVersion)

	// 触发回调
	m.mu.RLock()
	onRollback := m.onRollback
	m.mu.RUnlock()

	if onRollback != nil {
		go onRollback(currentVer.VersionID, targetVersion)
	}

	log.Printf("Rolled back config %s from version %d to %d", configType, currentVer.VersionID, targetVersion)

	return nil
}

// GetRollbackRequests 获取回滚请求列表
func (m *ConfigVersionManager) GetRollbackRequests(status string) ([]*ConfigRollback, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.store.GetConfigRollbacks(ctx, status)
}

// GetHistory 获取配置历史
func (m *ConfigVersionManager) GetHistory(configType string, limit int) ([]*ConfigHistory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.store.GetConfigHistory(ctx, configType, limit)
}

// calculateChecksum 计算校验和
func (m *ConfigVersionManager) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// recordHistory 记录历史
func (m *ConfigVersionManager) recordHistory(configType string, version *ConfigVersion, action string, fromVer, toVer int64) {
	history := &ConfigHistory{
		VersionID:   version.VersionID,
		ConfigType:  configType,
		Checksum:    version.Checksum,
		Description: version.Description,
		CreatedAt:   version.CreatedAt,
		CreatedBy:   version.CreatedBy,
		Action:      action,
		FromVersion: fromVer,
		ToVersion:   toVer,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m.store.SaveConfigHistory(ctx, history)
}

// VerifyChecksum 验证校验和
func (m *ConfigVersionManager) VerifyChecksum(versionID int64, data []byte) bool {
	version := m.GetVersion(versionID)
	if version == nil {
		return false
	}

	checksum := m.calculateChecksum(data)
	return checksum == version.Checksum
}

// GetVersionDiff 获取版本差异
func (m *ConfigVersionManager) GetVersionDiff(fromID, toID int64) (*ConfigDiff, error) {
	from := m.GetVersion(fromID)
	to := m.GetVersion(toID)

	if from == nil {
		return nil, fmt.Errorf("version %d not found", fromID)
	}

	if to == nil {
		return nil, fmt.Errorf("version %d not found", toID)
	}

	diff := &ConfigDiff{
		FromVersion: fromID,
		ToVersion:   toID,
		FromChecksum: from.Checksum,
		ToChecksum:   to.Checksum,
		Changed:      from.Checksum != to.Checksum,
	}

	if diff.Changed {
		diff.FromData = from.ConfigData
		diff.ToData = to.ConfigData
	}

	return diff, nil
}

// ConfigDiff 配置差异
type ConfigDiff struct {
	FromVersion int64
	ToVersion   int64
	FromChecksum string
	ToChecksum   string
	Changed     bool
	FromData    []byte
	ToData      []byte
}

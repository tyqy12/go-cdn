package media

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HLSEncryptor HLS加密服务
type HLSEncryptor struct {
	config   *EncryptionConfig
	keyCache map[string]*EncryptionKey
	keyDB    KeyDatabase
	mu       sync.RWMutex
	stats    *EncryptionStats
}

// EncryptionConfig 加密配置
type EncryptionConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 加密方式
	Method string `yaml:"method"` // "aes-128", "aes-192", "aes-256", "sample-aes"

	// 密钥轮转
	KeyRotation bool `yaml:"key_rotation"`

	// 密钥轮转周期
	KeyRotationPeriod time.Duration `yaml:"key_rotation_period"`

	// 密钥过期时间
	KeyExpiryTime time.Duration `yaml:"key_expiry_time"`

	// IV配置
	IVConfig IVConfig `yaml:"iv_config"`

	// URI模式
	URIFormat string `yaml:"uri_format"` // "inline", "external", "key-server"

	// 密钥服务器配置
	KeyServerConfig KeyServerConfig `yaml:"key_server_config"`

	// DRM配置
	DRMConfig DRMConfig `yaml:"drm_config"`
}

// IVConfig IV配置
type IVConfig struct {
	// IV来源
	Source string `json:"source"` // "random", "sequence", "explicit"

	// 显式IV
	ExplicitIV string `json:"explicit_iv"`

	// IV长度
	IVLength int `json:"iv_length"` // 16 bytes for AES
}

// KeyServerConfig 密钥服务器配置
type KeyServerConfig struct {
	// 启用密钥服务器
	Enabled bool `yaml:"enabled"`

	// 密钥服务器地址
	URL string `yaml:"url"`

	// 认证
	AuthConfig AuthConfig `yaml:"auth_config"`

	// 超时
	Timeout time.Duration `yaml:"timeout"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	Type   string `json:"type"` // "basic", "token", "hmac"
	Token  string `json:"token"`
	APIKey string `json:"api_key"`
}

// DRMConfig DRM配置
type DRMConfig struct {
	// 启用Widevine
	Widevine bool `json:"widevine"`

	// Widevine配置
	WidevineConfig *WidevineConfig `json:"widevine_config"`

	// 启用FairPlay
	FairPlay bool `json:"fair_play"`

	// FairPlay配置
	FairPlayConfig *FairPlayConfig `json:"fair_play_config"`

	// 启用PlayReady
	PlayReady bool `json:"play_ready"`

	// PlayReady配置
	PlayReadyConfig *PlayReadyConfig `json:"play_ready_config"`
}

// WidevineConfig Widevine配置
type WidevineConfig struct {
	Provider       string `json:"provider"`
	ServiceAccount string `json:"service_account"`
	PrivateKey     string `json:"private_key"`
	LicenseURL     string `json:"license_url"`
}

// FairPlayConfig FairPlay配置
type FairPlayConfig struct {
	ApplicationID string `json:"application_id"`
	PrivateKey    string `json:"private_key"`
	Certificate   string `json:"certificate"`
	LicenseURL    string `json:"license_url"`
}

// PlayReadyConfig PlayReady配置
type PlayReadyConfig struct {
	LicenseURL string `json:"license_url"`
	Domain     string `json:"domain"`
	XML        string `json:"xml"`
}

// EncryptionKey 加密密钥
type EncryptionKey struct {
	KeyID      string    `json:"key_id"`
	Key        []byte    `json:"key"`
	IV         []byte    `json:"iv"`
	ContentID  string    `json:"content_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UsageCount int       `json:"usage_count"`
	RotatedAt  time.Time `json:"rotated_at"`
}

// KeyDatabase 密钥数据库接口
type KeyDatabase interface {
	StoreKey(key *EncryptionKey) error
	GetKey(keyID string) (*EncryptionKey, error)
	DeleteKey(keyID string) error
	ListKeys(contentID string) ([]*EncryptionKey, error)
}

// HLSManifest HLS清单
type HLSManifest struct {
	Version        string              `json:"version"`
	TargetDuration int                 `json:"target_duration"`
	MediaSequence  int                 `json:"media_sequence"`
	Segments       []*HLSSegment       `json:"segments"`
	VariantStreams []*VariantStream    `json:"variant_streams"`
	Encryption     *ManifestEncryption `json:"encryption"`
}

// HLSSegment HLS片段
type HLSSegment struct {
	URI             string  `json:"uri"`
	Duration        float64 `json:"duration"`
	SequenceNumber  int     `json:"sequence_number"`
	EncryptionKeyID string  `json:"encryption_key_id"`
	Byterange       string  `json:"byterange"`
}

// VariantStream 变体流
type VariantStream struct {
	Name       string `json:"name"`
	Bandwidth  int    `json:"bandwidth"`
	Resolution string `json:"resolution"`
	Codecs     string `json:"codecs"`
	AudioTrack string `json:"audio_track"`
}

// ManifestEncryption 清单加密
type ManifestEncryption struct {
	Method    string   `json:"method"`
	URI       string   `json:"uri"`
	IV        string   `json:"iv"`
	KeyFormat string   `json:"key_format"`
	KeyRanges []string `json:"key_ranges"`
}

// EncryptionStats 加密统计
type EncryptionStats struct {
	TotalKeys        int64 `json:"total_keys"`
	ActiveKeys       int64 `json:"active_keys"`
	TotalEncryptions int64 `json:"total_encryptions"`
	TotalDecryptions int64 `json:"total_decryptions"`
	EncryptBytes     int64 `json:"encrypt_bytes"`
	DecryptBytes     int64 `json:"decrypt_bytes"`
	KeyRotations     int64 `json:"key_rotations"`
	mu               sync.RWMutex
}

// WidevineLicense Widevine许可证
type WidevineLicense struct {
	LicenseRequest  string     `json:"license_request"`
	LicenseResponse string     `json:"license_response"`
	ContentID       string     `json:"content_id"`
	KeyID           string     `json:"key_id"`
	Rights          *DRMRights `json:"rights"`
	ExpiresAt       time.Time  `json:"expires_at"`
}

// DRMRights DRM权限
type DRMRights struct {
	PlayAllowed     bool             `json:"play_allowed"`
	Persistent      bool             `json:"persistent"`
	ExpiresAt       time.Time        `json:"expires_at"`
	PlaybackWindows []PlaybackWindow `json:"playback_windows"`
}

// PlaybackWindow 播放窗口
type PlaybackWindow struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// NewHLSEncryptor 创建HLS加密服务
func NewHLSEncryptor(config *EncryptionConfig) *HLSEncryptor {
	if config == nil {
		config = &EncryptionConfig{
			Enabled:       true,
			Method:        "aes-128",
			KeyRotation:   false,
			KeyExpiryTime: 24 * time.Hour,
		}
	}

	return &HLSEncryptor{
		config:   config,
		keyCache: make(map[string]*EncryptionKey),
		stats:    &EncryptionStats{},
	}
}

// GenerateKey 生成加密密钥
func (e *HLSEncryptor) GenerateKey(contentID string) (*EncryptionKey, error) {
	// 生成随机密钥
	key := make([]byte, 16) // 128-bit
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}

	// 生成随机IV
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("生成IV失败: %w", err)
	}

	// 生成密钥ID
	keyID := generateKeyID()

	encKey := &EncryptionKey{
		KeyID:      keyID,
		Key:        key,
		IV:         iv,
		ContentID:  contentID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(e.config.KeyExpiryTime),
		UsageCount: 0,
	}

	// 缓存密钥
	e.mu.Lock()
	e.keyCache[keyID] = encKey
	e.mu.Unlock()

	// 存储密钥
	if e.keyDB != nil {
		e.keyDB.StoreKey(encKey)
	}

	// 更新统计
	e.stats.mu.Lock()
	e.stats.TotalKeys++
	e.stats.ActiveKeys++
	e.mu.Unlock()

	return encKey, nil
}

// Encrypt 加密数据
func (e *HLSEncryptor) Encrypt(data []byte, key *EncryptionKey) ([]byte, error) {
	// 创建cipher
	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf("创建cipher失败: %w", err)
	}

	// 选择加密模式
	mode := cipher.NewCBCEncrypter(block, key.IV)

	// 填充数据
	paddedData := pkcs7Padding(data, block.BlockSize())

	// 加密
	encrypted := make([]byte, len(paddedData))
	mode.CryptBlocks(encrypted, paddedData)

	// 更新统计
	e.stats.mu.Lock()
	e.stats.TotalEncryptions++
	e.stats.EncryptBytes += int64(len(data))
	e.mu.Unlock()

	return encrypted, nil
}

// Decrypt 解密数据
func (e *HLSEncryptor) Decrypt(data []byte, keyID string) ([]byte, error) {
	// 获取密钥
	key, err := e.getKey(keyID)
	if err != nil {
		return nil, err
	}

	// 创建cipher
	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf("创建cipher失败: %w", err)
	}

	// 选择解密模式
	mode := cipher.NewCBCDecrypter(block, key.IV)

	// 解密
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	// 移除填充
	decrypted = pkcs7Unpadding(decrypted)

	// 更新统计
	e.stats.mu.Lock()
	e.stats.TotalDecryptions++
	e.stats.DecryptBytes += int64(len(data))
	e.mu.Unlock()

	return decrypted, nil
}

// EncryptSegment 加密HLS片段
func (e *HLSEncryptor) EncryptSegment(segmentPath, outputPath, contentID string) (*EncryptedSegment, error) {
	// 读取片段数据
	data, err := os.ReadFile(segmentPath)
	if err != nil {
		return nil, fmt.Errorf("读取片段失败: %w", err)
	}

	// 生成或获取密钥
	key, err := e.GetOrCreateKey(contentID)
	if err != nil {
		return nil, err
	}

	// 加密数据
	encrypted, err := e.Encrypt(data, key)
	if err != nil {
		return nil, err
	}

	// 写入加密后的片段
	err = os.WriteFile(outputPath, encrypted, 0644)
	if err != nil {
		return nil, fmt.Errorf("写入加密片段失败: %w", err)
	}

	return &EncryptedSegment{
		OriginalPath:    segmentPath,
		EncryptedPath:   outputPath,
		EncryptionKeyID: key.KeyID,
		Size:            int64(len(encrypted)),
	}, nil
}

// EncryptedSegment 加密片段
type EncryptedSegment struct {
	OriginalPath    string `json:"original_path"`
	EncryptedPath   string `json:"encrypted_path"`
	EncryptionKeyID string `json:"encryption_key_id"`
	Size            int64  `json:"size"`
}

// GenerateKeyURI 生成密钥URI
func (e *HLSEncryptor) GenerateKeyURI(keyID string) string {
	switch e.config.URIFormat {
	case "inline":
		return fmt.Sprintf("data:application/octet-stream;base64,%s", base64.StdEncoding.EncodeToString([]byte(keyID)))
	case "key-server":
		return fmt.Sprintf("/hls/key/%s.key", keyID)
	default:
		return fmt.Sprintf("/keys/%s.key", keyID)
	}
}

// GenerateIVURI 生成IV URI
func (e *HLSEncryptor) GenerateIVURI(keyID string) string {
	key, err := e.getKey(keyID)
	if err != nil {
		return ""
	}

	return fmt.Sprintf("0x%s", hex.EncodeToString(key.IV))
}

// GenerateMasterPlaylist 生成主播放列表
func (e *HLSEncryptor) GenerateMasterPlaylist(videoID string, streams []*VariantStream) string {
	var sb strings.Builder

	sb.WriteString("#EXTM3U\n")
	sb.WriteString("#EXT-X-VERSION:4\n\n")

	for _, stream := range streams {
		sb.WriteString(fmt.Sprintf("#EXT-X-STREAM-INF:BANDWIDTH=%d,RESOLUTION=%s,CODECS=\"%s\"\n",
			stream.Bandwidth, stream.Resolution, stream.Codecs))
		sb.WriteString(fmt.Sprintf("%s/playlist.m3u8\n", stream.Name))
	}

	return sb.String()
}

// GenerateMediaPlaylist 生成媒体播放列表
func (e *HLSEncryptor) GenerateMediaPlaylist(manifest *HLSManifest) string {
	var sb strings.Builder

	sb.WriteString("#EXTM3U\n")
	sb.WriteString(fmt.Sprintf("#EXT-X-VERSION:%s\n", manifest.Version))
	sb.WriteString(fmt.Sprintf("#EXT-X-TARGETDURATION:%d\n", manifest.TargetDuration))
	sb.WriteString(fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d\n", manifest.MediaSequence))

	// 添加加密信息
	if manifest.Encryption != nil {
		sb.WriteString(fmt.Sprintf("#EXT-X-KEY:METHOD=%s,URI=\"%s\"",
			manifest.Encryption.Method, manifest.Encryption.URI))
		if manifest.Encryption.IV != "" {
			sb.WriteString(fmt.Sprintf(",IV=%s", manifest.Encryption.IV))
		}
		sb.WriteString("\n")
	}

	// 添加片段
	for _, segment := range manifest.Segments {
		if segment.EncryptionKeyID != "" {
			sb.WriteString(fmt.Sprintf("#EXT-X-KEY:METHOD=AES-128,URI=\"%s\",IV=0x%s\n",
				e.GenerateKeyURI(segment.EncryptionKeyID),
				hex.EncodeToString([]byte(segment.EncryptionKeyID))))
		}
		sb.WriteString(fmt.Sprintf("#EXTINF:%.6f,\n", segment.Duration))
		sb.WriteString(fmt.Sprintf("%s\n", segment.URI))
	}

	sb.WriteString("#EXT-X-ENDLIST\n")

	return sb.String()
}

// GetOrCreateKey 获取或创建密钥
func (e *HLSEncryptor) GetOrCreateKey(contentID string) (*EncryptionKey, error) {
	// 尝试从数据库获取
	if e.keyDB != nil {
		keys, err := e.keyDB.ListKeys(contentID)
		if err == nil && len(keys) > 0 {
			return keys[0], nil
		}
	}

	// 生成新密钥
	return e.GenerateKey(contentID)
}

// getKey 获取密钥
func (e *HLSEncryptor) getKey(keyID string) (*EncryptionKey, error) {
	e.mu.RLock()
	key, ok := e.keyCache[keyID]
	e.mu.RUnlock()

	if !ok {
		// 尝试从数据库获取
		if e.keyDB != nil {
			key, err := e.keyDB.GetKey(keyID)
			if err != nil {
				return nil, fmt.Errorf("密钥不存在: %s", keyID)
			}

			// 缓存密钥
			e.mu.Lock()
			e.keyCache[keyID] = key
			e.mu.Unlock()

			return key, nil
		}

		return nil, fmt.Errorf("密钥不存在: %s", keyID)
	}

	// 检查过期
	if time.Now().After(key.ExpiresAt) {
		return nil, fmt.Errorf("密钥已过期: %s", keyID)
	}

	return key, nil
}

// RotateKeys 轮转密钥
func (e *HLSEncryptor) RotateKeys(contentID string) error {
	// 生成新密钥
	if _, err := e.GenerateKey(contentID); err != nil {
		return err
	}

	// 更新统计
	e.stats.mu.Lock()
	e.stats.KeyRotations++
	e.mu.Unlock()

	return nil
}

// WidevineLicenseRequest 生成Widevine许可请求
func (e *HLSEncryptor) WidevineLicenseRequest(contentID, keyID string) (*WidevineLicense, error) {
	if !e.config.DRMConfig.Widevine {
		return nil, fmt.Errorf("Widevine未启用")
	}

	// 生成许可请求
	license := &WidevineLicense{
		ContentID: contentID,
		KeyID:     keyID,
		Rights: &DRMRights{
			PlayAllowed: true,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	return license, nil
}

// ProcessWidevineLicense 处理Widevine许可响应
func (e *HLSEncryptor) ProcessWidevineLicense(licenseResponse []byte) (*WidevineLicense, error) {
	// 检查Widevine是否启用
	if !e.config.DRMConfig.Widevine {
		return nil, fmt.Errorf("Widevine未启用")
	}

	// 检查配置
	if e.config.DRMConfig.WidevineConfig == nil {
		return nil, fmt.Errorf("Widevine配置未设置")
	}

	// 解析许可响应
	var license WidevineLicense
	if err := json.Unmarshal(licenseResponse, &license); err != nil {
		// 如果不是JSON格式，尝试解析为Widevine特定的二进制格式
		// Widevine许可响应通常是protobuf格式，这里简化处理
		license = WidevineLicense{
			LicenseResponse: base64.StdEncoding.EncodeToString(licenseResponse),
			ExpiresAt:       time.Now().Add(24 * time.Hour),
		}
	}

	// 验证许可证
	if license.Rights == nil {
		license.Rights = &DRMRights{
			PlayAllowed: true,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}
	}

	// 生成内容密钥ID
	if license.KeyID == "" && license.ContentID != "" {
		license.KeyID = generateKeyIDFromContent(license.ContentID)
	}

	// 设置过期时间
	if license.ExpiresAt.IsZero() {
		license.ExpiresAt = time.Now().Add(24 * time.Hour)
	}
	if license.Rights.ExpiresAt.IsZero() {
		license.Rights.ExpiresAt = license.ExpiresAt
	}

	return &license, nil
}

// GenerateWidevineRequest 生成Widevine许可请求
func (e *HLSEncryptor) GenerateWidevineRequest(contentID, keyID string, rights *DRMRights) (*WidevineLicense, error) {
	if !e.config.DRMConfig.Widevine {
		return nil, fmt.Errorf("Widevine未启用")
	}

	// 生成请求ID
	requestID := generateKeyID()

	// 构建许可请求
	license := &WidevineLicense{
		LicenseRequest: base64.StdEncoding.EncodeToString([]byte(requestID)),
		ContentID:      contentID,
		KeyID:          keyID,
		Rights:         rights,
	}

	// 设置默认过期时间
	if license.Rights == nil {
		license.Rights = &DRMRights{
			PlayAllowed: true,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}
	}

	if license.Rights.ExpiresAt.IsZero() {
		license.Rights.ExpiresAt = time.Now().Add(24 * time.Hour)
	}

	license.ExpiresAt = license.Rights.ExpiresAt

	return license, nil
}

// ValidateWidevineLicense 验证Widevine许可证
func (e *HLSEncryptor) ValidateWidevineLicense(license *WidevineLicense) bool {
	if license == nil {
		return false
	}

	// 检查是否过期
	if time.Now().After(license.ExpiresAt) {
		return false
	}

	// 检查播放权限
	if license.Rights == nil || !license.Rights.PlayAllowed {
		return false
	}

	// 检查是否在播放窗口内
	if len(license.Rights.PlaybackWindows) > 0 {
		now := time.Now()
		inWindow := false
		for _, window := range license.Rights.PlaybackWindows {
			if now.After(window.StartTime) && now.Before(window.EndTime) {
				inWindow = true
				break
			}
		}
		if !inWindow {
			return false
		}
	}

	return true
}

// GetWidevineKey 获取Widevine密钥用于解密
func (e *HLSEncryptor) GetWidevineKey(license *WidevineLicense) ([]byte, error) {
	// 从许可中提取密钥ID
	if license.KeyID == "" {
		return nil, fmt.Errorf("许可证中缺少KeyID")
	}

	// 获取对应的加密密钥
	key, err := e.getKey(license.KeyID)
	if err != nil {
		return nil, err
	}

	return key.Key, nil
}

// GetStats 获取统计
func (e *HLSEncryptor) GetStats() *EncryptionStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	return e.stats
}

// ExportKey 导出密钥
func (e *HLSEncryptor) ExportKey(keyID string) (string, error) {
	key, err := e.getKey(keyID)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key.Key), nil
}

// ImportKey 导入密钥
func (e *HLSEncryptor) ImportKey(contentID, keyData string) (*EncryptionKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("无效的密钥格式: %w", err)
	}

	keyID := generateKeyID()

	key := &EncryptionKey{
		KeyID:     keyID,
		Key:       keyBytes,
		ContentID: contentID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(e.config.KeyExpiryTime),
	}

	e.mu.Lock()
	e.keyCache[keyID] = key
	e.mu.Unlock()

	if e.keyDB != nil {
		e.keyDB.StoreKey(key)
	}

	return key, nil
}

// generateKeyID 生成密钥ID
func generateKeyID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateKeyIDFromContent 从内容ID生成密钥ID
func generateKeyIDFromContent(contentID string) string {
	hash := sha256.Sum256([]byte(contentID))
	return hex.EncodeToString(hash[:])
}

// pkcs7Padding PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs7Unpadding PKCS7去填充
func pkcs7Unpadding(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return data
	}

	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return data
		}
	}

	return data[:len(data)-padding]
}

// EncryptFile 加密文件
func (e *HLSEncryptor) EncryptFile(inputPath, outputPath, contentID string) error {
	// 读取输入文件
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer inputFile.Close()

	// 获取或创建密钥
	key, err := e.GetOrCreateKey(contentID)
	if err != nil {
		return err
	}

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outputFile.Close()

	// 创建加密器
	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return fmt.Errorf("创建cipher失败: %w", err)
	}

	stream := cipher.NewCBCEncrypter(block, key.IV)

	// 分块加密
	const bufferSize = 64 * 1024 // 64KB
	buffer := make([]byte, bufferSize)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("读取文件失败: %w", err)
		}

		if n == 0 {
			break
		}

		// 填充
		padded := pkcs7Padding(buffer[:n], block.BlockSize())

		// 加密
		encrypted := make([]byte, len(padded))
		stream.CryptBlocks(encrypted, padded)

		// 写入
		if _, err := outputFile.Write(encrypted); err != nil {
			return fmt.Errorf("写入文件失败: %w", err)
		}

		// 更新统计
		e.stats.mu.Lock()
		e.stats.TotalEncryptions++
		e.stats.EncryptBytes += int64(n)
		e.mu.Unlock()
	}

	// 确保加密器flush
	// (CBC模式不需要特殊的flush操作)

	return nil
}

// DecryptFile 解密文件
func (e *HLSEncryptor) DecryptFile(inputPath, outputPath, keyID string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer inputFile.Close()

	key, err := e.getKey(keyID)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return fmt.Errorf("创建cipher失败: %w", err)
	}

	stream := cipher.NewCBCDecrypter(block, key.IV)

	const bufferSize = 64 * 1024 // 64KB
	buffer := make([]byte, bufferSize)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("读取文件失败: %w", err)
		}

		if n == 0 {
			break
		}

		// 解密
		decrypted := make([]byte, n)
		stream.CryptBlocks(decrypted, buffer[:n])

		// 去填充
		unpadded := pkcs7Unpadding(decrypted)

		if _, err := outputFile.Write(unpadded); err != nil {
			return fmt.Errorf("写入文件失败: %w", err)
		}

		e.stats.mu.Lock()
		e.stats.TotalDecryptions++
		e.stats.DecryptBytes += int64(len(unpadded))
		e.mu.Unlock()
	}

	return nil
}

// InitializeKeyDatabase 初始化密钥数据库
func (e *HLSEncryptor) InitializeKeyDatabase(db KeyDatabase) {
	e.keyDB = db
}

// ListContentKeys 列出内容的所有密钥
func (e *HLSEncryptor) ListContentKeys(contentID string) ([]*EncryptionKey, error) {
	if e.keyDB != nil {
		return e.keyDB.ListKeys(contentID)
	}

	// 从缓存中查找
	e.mu.RLock()
	defer e.mu.RUnlock()

	var keys []*EncryptionKey
	for _, key := range e.keyCache {
		if key.ContentID == contentID {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// DeleteKey 删除密钥
func (e *HLSEncryptor) DeleteKey(keyID string) error {
	e.mu.Lock()
	delete(e.keyCache, keyID)
	e.mu.Unlock()

	if e.keyDB != nil {
		return e.keyDB.DeleteKey(keyID)
	}

	e.stats.mu.Lock()
	e.stats.ActiveKeys--
	e.mu.Unlock()

	return nil
}

// CleanupExpiredKeys 清理过期密钥
func (e *HLSEncryptor) CleanupExpiredKeys() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for keyID, key := range e.keyCache {
		if time.Now().After(key.ExpiresAt) {
			delete(e.keyCache, keyID)
			e.stats.ActiveKeys--
		}
	}
}

// CreateHLSWithEncryption 创建加密的HLS文件
func (e *HLSEncryptor) CreateHLSWithEncryption(inputDir, outputDir, contentID string) error {
	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 获取内容的所有TS文件
	files, err := filepath.Glob(filepath.Join(inputDir, "*.ts"))
	if err != nil {
		return fmt.Errorf("获取TS文件失败: %w", err)
	}

	// 获取或创建密钥
	key, err := e.GetOrCreateKey(contentID)
	if err != nil {
		return err
	}

	// 加密每个TS文件
	for i, file := range files {
		outputFile := filepath.Join(outputDir, fmt.Sprintf("segment_%03d.ts", i))

		err = e.EncryptFile(file, outputFile, contentID)
		if err != nil {
			return fmt.Errorf("加密文件失败 %s: %w", file, err)
		}
	}

	// 生成播放列表
	manifest := &HLSManifest{
		Version:        "3",
		TargetDuration: 10,
		MediaSequence:  0,
		Encryption: &ManifestEncryption{
			Method: e.config.Method,
			URI:    e.GenerateKeyURI(key.KeyID),
			IV:     e.GenerateIVURI(key.KeyID),
		},
	}

	// 添加片段信息
	for i := range files {
		manifest.Segments = append(manifest.Segments, &HLSSegment{
			URI:             fmt.Sprintf("segment_%03d.ts", i),
			Duration:        10.0,
			SequenceNumber:  i,
			EncryptionKeyID: key.KeyID,
		})
	}

	// 生成播放列表文件
	playlist := e.GenerateMediaPlaylist(manifest)
	playlistPath := filepath.Join(outputDir, "playlist.m3u8")

	err = os.WriteFile(playlistPath, []byte(playlist), 0644)
	if err != nil {
		return fmt.Errorf("写入播放列表失败: %w", err)
	}

	// 生成主播放列表
	masterPlaylist := e.GenerateMasterPlaylist(contentID, []*VariantStream{
		{
			Name:       "video",
			Bandwidth:  2000000,
			Resolution: "1920x1080",
			Codecs:     "avc1.42001e,mp4a.40.2",
		},
	})

	masterPath := filepath.Join(outputDir, "master.m3u8")

	err = os.WriteFile(masterPath, []byte(masterPlaylist), 0644)
	if err != nil {
		return fmt.Errorf("写入主播放列表失败: %w", err)
	}

	return nil
}

// RSAEncrypt 使用RSA加密AES密钥
func (e *HLSEncryptor) RSAEncrypt(aesKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
}

// RSADecrypt 使用RSA解密AES密钥
func (e *HLSEncryptor) RSADecrypt(encryptedKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
}

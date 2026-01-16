package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// APIKey API密钥结构
type APIKey struct {
	KeyID       string    `json:"key_id" bson:"_id"`
	KeyHash     string    `json:"-" bson:"key_hash"`     // 存储哈希值
	Name        string    `json:"name" bson:"name"`
	Description string    `json:"description" bson:"description"`
	UserID      string    `json:"user_id" bson:"user_id"`
	Role        string    `json:"role" bson:"role"`
	Permissions []string  `json:"permissions" bson:"permissions"`
	Scopes      []string  `json:"scopes" bson:"scopes"`       // 允许的API范围
	ExpiresAt   *time.Time `json:"expires_at" bson:"expires_at"` // 过期时间
	LastUsedAt  *time.Time `json:"last_used_at" bson:"last_used_at"`
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
	CreatedBy   string    `json:"created_by" bson:"created_by"`
	Active      bool      `json:"active" bson:"active"`
}

// APIKeyAuth API密钥认证中间件
type APIKeyAuth struct {
	keys map[string]*APIKey // keyHash -> APIKey
	mu   map[string]*sync.RWMutex
}

// NewAPIKeyAuth 创建API密钥认证器
func NewAPIKeyAuth() *APIKeyAuth {
	return &APIKeyAuth{
		keys: make(map[string]*APIKey),
		mu:   make(map[string]*sync.RWMutex),
	}
}

// GenerateKey 生成新的API密钥
func (a *APIKeyAuth) GenerateKey(name, description, userID, role string, scopes []string, expiresAt *time.Time) (*APIKey, string, error) {
	// 生成随机密钥
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", err
	}
	key := hex.EncodeToString(keyBytes)

	// 计算密钥哈希
	keyHash := hashKey(key)

	// 生成密钥ID
	keyIDBytes := make([]byte, 8)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, "", err
	}
	keyID := hex.EncodeToString(keyIDBytes)

	now := time.Now()
	apiKey := &APIKey{
		KeyID:       keyID,
		KeyHash:     keyHash,
		Name:        name,
		Description: description,
		UserID:      userID,
		Role:        role,
		Permissions: getDefaultPermissions(role),
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		Active:      true,
	}

	// 存储密钥
	a.mu[keyID] = &sync.RWMutex{}
	a.keys[keyHash] = apiKey

	return apiKey, key, nil
}

// hashKey 计算密钥哈希
func hashKey(key string) string {
	// 使用简单的哈希，实际生产中应该使用bcrypt或argon2
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// ValidateKey 验证API密钥
func (a *APIKeyAuth) ValidateKey(key string) (*APIKey, bool) {
	keyHash := hashKey(key)

	apiKey, ok := a.keys[keyHash]
	if !ok {
		return nil, false
	}

	// 检查是否激活
	if !apiKey.Active {
		return nil, false
	}

	// 检查是否过期
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, false
	}

	// 更新最后使用时间
	now := time.Now()
	apiKey.LastUsedAt = &now

	return apiKey, true
}

// GetKey 获取API密钥信息（不包含密钥本身）
func (a *APIKeyAuth) GetKey(keyID string) (*APIKey, bool) {
	a.mu[keyID].RLock()
	defer a.mu[keyID].RUnlock()

	for _, key := range a.keys {
		if key.KeyID == keyID {
			// 返回副本，不包含敏感信息
			return &APIKey{
				KeyID:       key.KeyID,
				Name:        key.Name,
				Description: key.Description,
				UserID:      key.UserID,
				Role:        key.Role,
				Permissions: key.Permissions,
				Scopes:      key.Scopes,
				ExpiresAt:   key.ExpiresAt,
				LastUsedAt:  key.LastUsedAt,
				CreatedAt:   key.CreatedAt,
				Active:      key.Active,
			}, true
		}
	}
	return nil, false
}

// RevokeKey 撤销API密钥
func (a *APIKeyAuth) RevokeKey(keyID string) bool {
	a.mu[keyID].Lock()
	defer a.mu[keyID].Unlock()

	for hash, key := range a.keys {
		if key.KeyID == keyID {
			key.Active = false
			delete(a.keys, hash)
			return true
		}
	}
	return false
}

// APIKeyAuthMiddleware 创建API密钥认证中间件
func APIKeyAuthMiddleware(auth *APIKeyAuth, requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 header 或 query 参数获取 API key
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "missing_api_key",
				"message": "API key is required",
			})
			c.Abort()
			return
		}

		// 验证密钥
		key, valid := auth.ValidateKey(apiKey)
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_api_key",
				"message": "Invalid or expired API key",
			})
			c.Abort()
			return
		}

		// 检查作用域
		if len(requiredScopes) > 0 {
			hasScope := false
			for _, scope := range requiredScopes {
				for _, keyScope := range key.Scopes {
					if scope == keyScope || keyScope == "*" {
						hasScope = true
						break
					}
				}
			}
			if !hasScope {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "insufficient_scope",
					"message": "API key doesn't have required scope",
					"required": requiredScopes,
				})
				c.Abort()
				return
			}
		}

		// 设置用户信息到上下文
		c.Set("user_id", key.UserID)
		c.Set("user_role", key.Role)
		c.Set("api_key_id", key.KeyID)
		c.Set("auth_type", "api_key")

		c.Next()
	}
}

// getDefaultPermissions 获取角色默认权限
func getDefaultPermissions(role string) []string {
	switch role {
	case RoleSuperAdmin, RoleAdmin:
		return []string{
			PermissionNodesView, PermissionNodesManage, PermissionNodesDeploy,
			PermissionConfigsView, PermissionConfigsManage,
			PermissionCommandsView, PermissionCommandsExec,
			PermissionMetricsView,
			PermissionAlertsView, PermissionAlertsManage,
			PermissionUsersView, PermissionUsersManage,
			PermissionSystemView, PermissionSystemManage,
		}
	case RoleOperator:
		return []string{
			PermissionNodesView, PermissionNodesDeploy,
			PermissionConfigsView,
			PermissionCommandsView, PermissionCommandsExec,
			PermissionMetricsView,
			PermissionAlertsView,
		}
	case RoleViewer:
		return []string{
			PermissionNodesView,
			PermissionConfigsView,
			PermissionMetricsView,
			PermissionAlertsView,
		}
	default:
		return []string{PermissionNodesView}
	}
}

// APIKeyAuthFromHeader 从 Authorization header 提取 API Key（Bearer 格式）
func APIKeyAuthFromHeader(auth *APIKeyAuth) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// 没有 Authorization header，继续处理（可能使用 JWT）
			c.Next()
			return
		}

		// 检查是否为 API Key 格式（Bearer 开头）
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			// 不是 Bearer 格式，继续处理
			c.Next()
			return
		}

		token := parts[1]

		// 尝试作为 API Key 验证
		// API Key 是 64 字符的十六进制字符串
		if len(token) == 64 {
			key, valid := auth.ValidateKey(token)
			if valid {
				c.Set("user_id", key.UserID)
				c.Set("user_role", key.Role)
				c.Set("api_key_id", key.KeyID)
				c.Set("auth_type", "api_key")
				c.Next()
				return
			}
		}

		// 不是有效的 API Key，继续处理（可能是 JWT）
		c.Next()
	}
}

// APIKeyHash API密钥哈希工具
type APIKeyHash struct {
	salt string
}

// NewAPIKeyHash 创建密钥哈希器
func NewAPIKeyHash(salt string) *APIKeyHash {
	if salt == "" {
		saltBytes := make([]byte, 16)
		rand.Read(saltBytes)
		salt = hex.EncodeToString(saltBytes)
	}
	return &APIKeyHash{salt: salt}
}

// Hash 计算密钥哈希
func (h *APIKeyHash) Hash(key string) string {
	combined := h.salt + key
	hVal := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hVal[:])
}

// Compare 比较密钥
func (h *APIKeyHash) Compare(key, hash string) bool {
	computedHash := []byte(h.Hash(key))
	storedHash := []byte(hash)
	return subtle.ConstantTimeCompare(computedHash, storedHash) == 1
}

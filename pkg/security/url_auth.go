package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// URLAuth URL鉴权服务
type URLAuth struct {
	config     *AuthConfig
	secrets    map[string]*SecretKey
	tokenCache *TokenCache
	mu         sync.RWMutex
}

// AuthConfig 鉴权配置
type AuthConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 鉴权方式
	AuthType string `yaml:"auth_type"` // "sign", "token", "ip_whitelist", "referer"

	// 签名配置
	SignConfig SignConfig `yaml:"sign_config"`

	// Token配置
	TokenConfig TokenConfig `yaml:"token_config"`

	// 白名单配置
	WhiteListConfig WhiteListConfig `yaml:"white_list_config"`

	// Referer配置
	RefererConfig RefererConfig `yaml:"referer_config"`

	// 过期时间
	ExpiryTime time.Duration `yaml:"expiry_time"`

	// 时钟偏移容差
	ClockSkewTolerance time.Duration `yaml:"clock_skew_tolerance"`
}

// SignConfig 签名配置
type SignConfig struct {
	// 启用签名验证
	Enabled bool `yaml:"enabled"`

	// 签名算法
	Algorithm string `yaml:"algorithm"` // "hmac-sha1", "hmac-sha256", "md5"

	// 密钥
	SecretKey string `yaml:"secret_key"`

	// 签名字段名
	SignParamName string `yaml:"sign_param_name"` // "sign"

	// 时间戳字段名
	TimestampParamName string `yaml:"timestamp_param_name"` // "t"

	// 签名字段位置
	SignLocation string `yaml:"sign_location"` // "query", "header", "cookie"

	// 签名字段顺序
	SignFields []string `yaml:"sign_fields"`
}

// TokenConfig Token配置
type TokenConfig struct {
	// 启用Token验证
	Enabled bool `yaml:"enabled"`

	// Token长度
	TokenLength int `yaml:"token_length"`

	// Token过期时间
	ExpiryTime time.Duration `yaml:"expiry_time"`

	// Token前缀
	TokenPrefix string `yaml:"token_prefix"`

	// Token字段名
	TokenParamName string `yaml:"token_param_name"`
}

// WhiteListConfig 白名单配置
type WhiteListConfig struct {
	// 启用IP白名单
	Enabled bool `yaml:"enabled"`

	// 白名单列表
	IPWhitelist []string `yaml:"ip_whitelist"`

	// CIDR格式
	CIDRWhitelist []string `yaml:"cidr_whitelist"`

	// 域名白名单
	DomainWhitelist []string `yaml:"domain_whitelist"`
}

// RefererConfig Referer配置
type RefererConfig struct {
	// 启用Referer验证
	Enabled bool `yaml:"enabled"`

	// 空Referer处理
	AllowEmptyReferer bool `yaml:"allow_empty_referer"`

	// 允许的Referer域名
	AllowedReferers []string `yaml:"allowed_referers"`

	// 阻止的Referer模式
	BlockedReferers []string `yaml:"blocked_referers"`
}

// SecretKey 密钥
type SecretKey struct {
	KeyID     string    `json:"key_id"`
	Key       string    `json:"key"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
}

// TokenCache Token缓存
type TokenCache struct {
	cache map[string]*CachedToken
	mu    sync.RWMutex
}

// CachedToken 缓存的Token
type CachedToken struct {
	Token      string    `json:"token"`
	UserID     string    `json:"user_id"`
	Resource   string    `json:"resource"`
	ExpiresAt  time.Time `json:"expires_at"`
	AccessedAt time.Time `json:"accessed_at"`
}

// AuthResult 鉴权结果
type AuthResult struct {
	Success   bool                   `json:"success"`
	Reason    string                 `json:"reason"`
	AuthType  string                 `json:"auth_type"`
	UserID    string                 `json:"user_id"`
	ExpiresAt time.Time              `json:"expires_at"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewURLAuth 创建URL鉴权服务
func NewURLAuth(config *AuthConfig) *URLAuth {
	if config == nil {
		config = &AuthConfig{
			Enabled:    true,
			AuthType:   "sign",
			ExpiryTime: 3600 * time.Second,
		}
	}

	return &URLAuth{
		config:     config,
		secrets:    make(map[string]*SecretKey),
		tokenCache: &TokenCache{cache: make(map[string]*CachedToken)},
	}
}

// GenerateSign 生成签名
func (auth *URLAuth) GenerateSign(resourceURL, secretKey string, expiresAt int64) (string, string, error) {
	// 构建签名字符串
	signStr := auth.buildSignString(resourceURL, expiresAt)

	// 计算签名
	var signature string
	switch auth.config.SignConfig.Algorithm {
	case "hmac-sha1":
		signature = auth.hmacSign(signStr, secretKey, "sha1")
	case "hmac-sha256":
		signature = auth.hmacSign(signStr, secretKey, "sha256")
	case "md5":
		signature = auth.md5Sign(signStr + secretKey)
	default:
		signature = auth.hmacSign(signStr, secretKey, "sha1")
	}

	return signStr, signature, nil
}

// buildSignString 构建签名字符串
func (auth *URLAuth) buildSignString(resourceURL string, expiresAt int64) string {
	// 标准格式: {method}&{path}&{expires}
	var sb strings.Builder
	sb.WriteString(resourceURL)
	sb.WriteString("&")
	sb.WriteString(fmt.Sprintf("%d", expiresAt))

	return sb.String()
}

// hmacSign HMAC签名
func (auth *URLAuth) hmacSign(data, key, algo string) string {
	var h func() interface{}
	switch algo {
	case "sha1":
		h = func() interface{} {
			h := hmac.New(sha1.New, []byte(key))
			h.Write([]byte(data))
			return hex.EncodeToString(h.Sum(nil))
		}
	case "sha256":
		h = func() interface{} {
			h := hmac.New(sha256.New, []byte(key))
			h.Write([]byte(data))
			return hex.EncodeToString(h.Sum(nil))
		}
	default:
		return ""
	}

	result := h()
	if s, ok := result.(string); ok {
		return s
	}
	return ""
}

// md5Sign MD5签名
func (auth *URLAuth) md5Sign(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySign 验证签名
func (auth *URLAuth) VerifySign(resourceURL, signature string, timestamp int64) *AuthResult {
	// 检查时间戳
	now := time.Now().Unix()
	if int64(math.Abs(float64(now-timestamp))) > int64(auth.config.ClockSkewTolerance.Seconds()) {
		return &AuthResult{
			Success:  false,
			Reason:   "时间戳已过期",
			AuthType: "sign",
		}
	}

	// 重新生成签名
	_, expectedSign, err := auth.GenerateSign(resourceURL, auth.config.SignConfig.SecretKey, timestamp)
	if err != nil {
		return &AuthResult{
			Success:  false,
			Reason:   "生成签名失败",
			AuthType: "sign",
		}
	}

	// 比较签名
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSign)) != 1 {
		return &AuthResult{
			Success:  false,
			Reason:   "签名验证失败",
			AuthType: "sign",
		}
	}

	return &AuthResult{
		Success:   true,
		Reason:    "签名验证通过",
		AuthType:  "sign",
		ExpiresAt: time.Unix(timestamp, 0),
	}
}

// GenerateToken 生成Token
func (auth *URLAuth) GenerateToken(userID, resource string) (string, error) {
	// 生成随机Token
	tokenBytes := make([]byte, auth.config.TokenConfig.TokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := auth.config.TokenConfig.TokenPrefix + base64.URLEncoding.EncodeToString(tokenBytes)

	// 缓存Token
	auth.tokenCache.mu.Lock()
	auth.tokenCache.cache[token] = &CachedToken{
		Token:      token,
		UserID:     userID,
		Resource:   resource,
		ExpiresAt:  time.Now().Add(auth.config.TokenConfig.ExpiryTime),
		AccessedAt: time.Now(),
	}
	auth.tokenCache.mu.Unlock()

	return token, nil
}

// VerifyToken 验证Token
func (auth *URLAuth) VerifyToken(token, resource string) *AuthResult {
	auth.tokenCache.mu.RLock()
	cached, exists := auth.tokenCache.cache[token]
	auth.tokenCache.mu.RUnlock()

	if !exists {
		return &AuthResult{
			Success:  false,
			Reason:   "Token不存在",
			AuthType: "token",
		}
	}

	if time.Now().After(cached.ExpiresAt) {
		// 删除过期Token
		auth.tokenCache.mu.Lock()
		delete(auth.tokenCache.cache, token)
		auth.tokenCache.mu.Unlock()

		return &AuthResult{
			Success:  false,
			Reason:   "Token已过期",
			AuthType: "token",
		}
	}

	if cached.Resource != "" && cached.Resource != resource {
		return &AuthResult{
			Success:  false,
			Reason:   "资源不匹配",
			AuthType: "token",
		}
	}

	// 更新访问时间
	auth.tokenCache.mu.Lock()
	cached.AccessedAt = time.Now()
	auth.tokenCache.mu.Unlock()

	return &AuthResult{
		Success:   true,
		Reason:    "Token验证通过",
		AuthType:  "token",
		UserID:    cached.UserID,
		ExpiresAt: cached.ExpiresAt,
	}
}

// VerifyReferer 验证Referer
func (auth *URLAuth) VerifyReferer(referer, targetURL string) *AuthResult {
	if !auth.config.RefererConfig.Enabled {
		return &AuthResult{
			Success:  true,
			Reason:   "Referer验证已禁用",
			AuthType: "referer",
		}
	}

	// 空Referer处理
	if referer == "" {
		if auth.config.RefererConfig.AllowEmptyReferer {
			return &AuthResult{
				Success:  true,
				Reason:   "允许空Referer",
				AuthType: "referer",
			}
		}
		return &AuthResult{
			Success:  false,
			Reason:   "禁止空Referer访问",
			AuthType: "referer",
		}
	}

	// 解析Referer
	refURL, err := url.Parse(referer)
	if err != nil {
		return &AuthResult{
			Success:  false,
			Reason:   "无效的Referer格式",
			AuthType: "referer",
		}
	}

	// 检查阻止列表
	for _, blocked := range auth.config.RefererConfig.BlockedReferers {
		if strings.Contains(referer, blocked) {
			return &AuthResult{
				Success:  false,
				Reason:   "Referer被阻止",
				AuthType: "referer",
			}
		}
	}

	// 检查允许列表
	for _, allowed := range auth.config.RefererConfig.AllowedReferers {
		if refURL.Host == allowed || strings.HasSuffix(refURL.Host, "."+allowed) {
			return &AuthResult{
				Success:  true,
				Reason:   "Referer验证通过",
				AuthType: "referer",
			}
		}
	}

	return &AuthResult{
		Success:  false,
		Reason:   "Referer不在允许列表",
		AuthType: "referer",
	}
}

// Authenticate 综合鉴权
func (auth *URLAuth) Authenticate(req *AuthRequest) *AuthResult {
	switch auth.config.AuthType {
	case "sign":
		return auth.authenticateBySign(req)
	case "token":
		return auth.authenticateByToken(req)
	case "ip_whitelist":
		return auth.authenticateByIP(req)
	case "referer":
		return auth.authenticateByReferer(req)
	default:
		return &AuthResult{
			Success: false,
			Reason:  "未知的鉴权方式",
		}
	}
}

// AuthRequest 鉴权请求
type AuthRequest struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	IP        string            `json:"ip"`
	UserAgent string            `json:"user_agent"`
	Referer   string            `json:"referer"`
	Headers   map[string]string `json:"headers"`
	Query     map[string]string `json:"query"`
}

// authenticateBySign 签名鉴权
func (auth *URLAuth) authenticateBySign(req *AuthRequest) *AuthResult {
	// 获取签名参数
	sign := req.Query[auth.config.SignConfig.SignParamName]
	timestampStr := req.Query[auth.config.SignConfig.TimestampParamName]

	if sign == "" || timestampStr == "" {
		return &AuthResult{
			Success:  false,
			Reason:   "缺少签名参数",
			AuthType: "sign",
		}
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return &AuthResult{
			Success:  false,
			Reason:   "无效的时间戳",
			AuthType: "sign",
		}
	}

	return auth.VerifySign(req.URL, sign, timestamp)
}

// authenticateByToken Token鉴权
func (auth *URLAuth) authenticateByToken(req *AuthRequest) *AuthResult {
	token := req.Query[auth.config.TokenConfig.TokenParamName]
	if token == "" {
		token = req.Headers["Authorization"]
	}

	if token == "" {
		return &AuthResult{
			Success:  false,
			Reason:   "缺少Token",
			AuthType: "token",
		}
	}

	return auth.VerifyToken(token, req.URL)
}

// authenticateByIP IP白名单鉴权
func (auth *URLAuth) authenticateByIP(req *AuthRequest) *AuthResult {
	for _, allowedIP := range auth.config.WhiteListConfig.IPWhitelist {
		if req.IP == allowedIP {
			return &AuthResult{
				Success:  true,
				Reason:   "IP在白名单中",
				AuthType: "ip_whitelist",
			}
		}
	}

	return &AuthResult{
		Success:  false,
		Reason:   "IP不在白名单中",
		AuthType: "ip_whitelist",
	}
}

// authenticateByReferer Referer鉴权
func (auth *URLAuth) authenticateByReferer(req *AuthRequest) *AuthResult {
	return auth.VerifyReferer(req.Referer, req.URL)
}

// AddSecretKey 添加密钥
func (auth *URLAuth) AddSecretKey(keyID, key, algorithm string) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	auth.secrets[keyID] = &SecretKey{
		KeyID:     keyID,
		Key:       key,
		Algorithm: algorithm,
		CreatedAt: time.Now(),
		Active:    true,
	}
}

// RemoveSecretKey 移除密钥
func (auth *URLAuth) RemoveSecretKey(keyID string) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	delete(auth.secrets, keyID)
}

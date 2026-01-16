package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ChallengeVerifier 挑战验证器
type ChallengeVerifier struct {
	mu         sync.RWMutex
	challenges map[string]*ChallengeSession
	config     *SecurityChallengeConfig
	logger     Logger
	stats      ChallengeStats
}

// SecurityChallengeConfig 安全挑战配置
type SecurityChallengeConfig struct {
	Enabled        bool
	SecretKey      string
	CookieName     string
	CookieExpiry   time.Duration
	MaxAttempts    int
	WindowDuration time.Duration
	RateLimit      int64
	Paths          []string // 需要挑战的路径
	ExcludedPaths  []string // 排除挑战的路径
}

// ChallengeSession 挑战会话
type ChallengeSession struct {
	Token         string
	ClientIP      string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Attempts      int
	Verified      bool
	ChallengeData map[string]string
}

// ChallengeStats 挑战统计
type ChallengeStats struct {
	TotalChallenges int64
	TotalVerified   int64
	TotalFailed     int64
	ActiveSessions  int
	mu              sync.RWMutex
}

// NewChallengeVerifier 创建挑战验证器
func NewChallengeVerifier(config *SecurityChallengeConfig) *ChallengeVerifier {
	if config == nil {
		config = &SecurityChallengeConfig{
			Enabled:       true,
			SecretKey:     generateSecretKey(),
			CookieName:    "gocdn_challenge",
			CookieExpiry:  1 * time.Hour,
			MaxAttempts:   3,
			WindowDuration: 1 * time.Minute,
			RateLimit:     10,
			Paths:         []string{"/admin", "/api/login", "/api/admin"},
			ExcludedPaths: []string{"/api/health", "/api/public"},
		}
	}

	return &ChallengeVerifier{
		challenges: make(map[string]*ChallengeSession),
		config:     config,
		logger:     &DefaultLogger{},
	}
}

// NeedChallenge 检查是否需要挑战
func (cv *ChallengeVerifier) NeedChallenge(req *http.Request) bool {
	if !cv.config.Enabled {
		return false
	}

	path := req.URL.Path

	// 检查是否排除
	for _, excluded := range cv.config.ExcludedPaths {
		if strings.HasPrefix(path, excluded) {
			return false
		}
	}

	// 检查是否需要挑战
	for _, p := range cv.config.Paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	return false
}

// GenerateChallenge 生成挑战
func (cv *ChallengeVerifier) GenerateChallenge(w http.ResponseWriter, req *http.Request) error {
	clientIP := getClientIP(req)

	// 生成 token
	token := cv.generateToken()

	// 创建挑战会话
	session := &ChallengeSession{
		Token:         token,
		ClientIP:      clientIP,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(cv.config.CookieExpiry),
		Attempts:      0,
		Verified:      false,
		ChallengeData: make(map[string]string),
	}

	cv.mu.Lock()
	cv.challenges[token] = session
	cv.stats.TotalChallenges++
	cv.stats.ActiveSessions = len(cv.challenges)
	cv.mu.Unlock()

	// 发送 JS 挑战
	return cv.sendJSChallenge(w, req, token)
}

// sendJSChallenge 发送 JS 挑战
func (cv *ChallengeVerifier) sendJSChallenge(w http.ResponseWriter, req *http.Request, token string) error {
	// 生成 nonce
	nonce := cv.generateToken()[:16]

	// 生成 challenge string
	challenge := cv.generateChallengeString(nonce)

	// 保存挑战数据
	cv.mu.Lock()
	if session, ok := cv.challenges[token]; ok {
		session.ChallengeData["nonce"] = nonce
		session.ChallengeData["challenge"] = challenge
	}
	cv.mu.Unlock()

	// 生成 JavaScript 响应
	jsCode := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Verification Required</title>
    <script>
        function solve() {
            var nonce = "%s";
            var challenge = "%s";
            var result = "";
            for (var i = 0; i < challenge.length; i++) {
                result += String.fromCharCode(challenge.charCodeAt(i) ^ nonce.charCodeAt(i %% nonce.length));
            }
            return result;
        }
        function submit() {
            var result = solve();
            document.cookie = "%s=" + result + "; path=/; max-age=3600";
            location.reload();
        }
    </script>
</head>
<body>
    <h1>Verification Required</h1>
    <p>Please complete the verification to access this resource.</p>
    <p>Click the button below to verify:</p>
    <button onclick="submit()">Verify</button>
    <noscript>
        <p>JavaScript is required for verification.</p>
    </noscript>
</body>
</html>`, nonce, challenge, cv.config.CookieName)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusUnauthorized)
	_, err := w.Write([]byte(jsCode))
	return err
}

// VerifyChallenge 验证挑战
func (cv *ChallengeVerifier) VerifyChallenge(req *http.Request) (bool, string) {
	// 获取 token
	token := req.Header.Get("X-Challenge-Token")
	if token == "" {
		cookie, err := req.Cookie(cv.config.CookieName)
		if err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		return false, "no_token"
	}

	cv.mu.Lock()
	session, ok := cv.challenges[token]
	if !ok {
		cv.mu.Unlock()
		return false, "invalid_token"
	}
	cv.mu.Unlock()

	// 检查过期
	if time.Now().After(session.ExpiresAt) {
		cv.mu.Lock()
		delete(cv.challenges, token)
		cv.stats.ActiveSessions = len(cv.challenges)
		cv.mu.Unlock()
		return false, "expired"
	}

	// 检查尝试次数
	if session.Attempts >= cv.config.MaxAttempts {
		return false, "max_attempts"
	}

	// 验证 token
	if cv.verifyToken(token, req) {
		session.Verified = true
		cv.stats.TotalVerified++
		return true, "verified"
	}

	session.Attempts++
	cv.stats.TotalFailed++
	return false, "invalid_proof"
}

// IsVerified 检查是否已验证
func (cv *ChallengeVerifier) IsVerified(req *http.Request) bool {
	token := req.Header.Get("X-Challenge-Token")
	if token == "" {
		cookie, err := req.Cookie(cv.config.CookieName)
		if err != nil {
			return false
		}
		token = cookie.Value
	}

	cv.mu.RLock()
	session, ok := cv.challenges[token]
	verified := ok && session.Verified && time.Now().Before(session.ExpiresAt)
	cv.mu.RUnlock()

	return verified
}

// generateToken 生成 token
func (cv *ChallengeVerifier) generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// generateSecretKey 生成密钥
func generateSecretKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateChallengeString 生成挑战字符串
func (cv *ChallengeVerifier) generateChallengeString(nonce string) string {
	data := cv.config.SecretKey + nonce + time.Now().Format(time.RFC3339)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// verifyToken 验证 token
func (cv *ChallengeVerifier) verifyToken(token string, req *http.Request) bool {
	cv.mu.RLock()
	session, ok := cv.challenges[token]
	cv.mu.RUnlock()

	if !ok || !session.Verified {
		return false
	}

	// 验证客户端 IP 一致性
	clientIP := getClientIP(req)
	if session.ClientIP != clientIP {
		return false
	}

	return true
}

// GetStats 获取统计
func (cv *ChallengeVerifier) GetStats() ChallengeStats {
	cv.stats.mu.RLock()
	defer cv.stats.mu.RUnlock()

	cv.stats.ActiveSessions = len(cv.challenges)
	return cv.stats
}

// Cleanup 清理过期会话
func (cv *ChallengeVerifier) Cleanup() {
	now := time.Now()

	cv.mu.Lock()
	for token, session := range cv.challenges {
		if now.After(session.ExpiresAt) {
			delete(cv.challenges, token)
		}
	}
	cv.stats.ActiveSessions = len(cv.challenges)
	cv.mu.Unlock()
}

// Reset 重置
func (cv *ChallengeVerifier) Reset() {
	cv.mu.Lock()
	cv.challenges = make(map[string]*ChallengeSession)
	cv.stats = ChallengeStats{}
	cv.mu.Unlock()
}

// SetConfig 设置配置
func (cv *ChallengeVerifier) SetConfig(config *SecurityChallengeConfig) {
	cv.mu.Lock()
	cv.config = config
	cv.mu.Unlock()
}

// GetConfig 获取配置
func (cv *ChallengeVerifier) GetConfig() *SecurityChallengeConfig {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	return cv.config
}

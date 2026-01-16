# AI CDN Tunnel - 安全指南

## 目录

- [1. 安全架构](#1-安全架构)
- [2. 认证授权](#2-认证授权)
- [3. 传输安全](#3-传输安全)
- [4. 网络安全](#4-网络安全)
- [5. 应用安全](#5-应用安全)
- [6. 数据安全](#6-数据安全)
- [7. 监控与审计](#7-监控与审计)
- [8. 安全配置](#8-安全配置)
- [9. 应急响应](#9-应急响应)

---

## 1. 安全架构

### 1.1 安全设计原则

| 原则 | 说明 |
|------|------|
| **最小权限** | 只授予必要的权限 |
| **纵深防御** | 多层安全防护 |
| **默认安全** | 默认配置应为安全的 |
| **开放设计** | 不依赖代码保密 |
| **故障安全** | 失败时保持安全状态 |

### 1.2 安全分层

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层安全                              │
│         认证 / 授权 / 输入验证 / 输出编码                     │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      传输层安全                              │
│              TLS 1.3 / mTLS / 证书验证                       │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      网络层安全                              │
│         防火墙 / DDoS防护 / IP 白名单                        │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      基础设施安全                            │
│          容器安全 / 密钥管理 / 审计日志                       │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 威胁模型

| 威胁 | 场景 | 防护措施 |
|------|------|----------|
| **未授权访问** | 攻击者访问管理 API | JWT 认证、RBAC |
| **数据泄露** | 敏感信息暴露 | 加密、访问控制 |
| **DDoS 攻击** | 服务拒绝 | 限流、CDN 防护 |
| **中间人攻击** | 流量劫持 | TLS 加密 |
| **注入攻击** | SQL/命令注入 | 输入验证 |
| **凭证泄露** | Token 泄露 | 短过期、轮换 |

---

## 2. 认证授权

### 2.1 JWT 认证

> **注意**: 当前 JWT 中间件为空实现，需要完善

#### 2.1.1 Token 结构

```go
type JWTClaims struct {
    UserID    string   `json:"user_id"`
    Username  string   `json:"username"`
    Roles     []string `json:"roles"`
    ExpiresAt int64    `json:"expires_at"`
    IssuedAt  int64    `json:"issued_at"`
}
```

#### 2.1.2 Token 生成

```go
func GenerateToken(user *User, secret string) (string, error) {
    claims := JWTClaims{
        UserID:    user.ID,
        Username:  user.Username,
        Roles:     user.Roles,
        ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
        IssuedAt:  time.Now().Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(secret))
}
```

#### 2.1.3 Token 验证中间件

```go
func JWTAuth(secret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "code":    40101,
                "message": "missing authorization header",
            })
            return
        }

        // 解析 Bearer Token
        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "code":    40102,
                "message": "invalid authorization format",
            })
            return
        }

        tokenString := parts[1]
        claims, err := ValidateToken(tokenString, secret)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "code":    40103,
                "message": "invalid or expired token",
            })
            return
        }

        // 将用户信息写入上下文
        c.Set("user_id", claims.UserID)
        c.Set("username", claims.Username)
        c.Set("roles", claims.Roles)

        c.Next()
    }
}
```

### 2.2 RBAC 授权

```go
// 角色定义
const (
    RoleAdmin  = "admin"      // 管理员：所有权限
    RoleOperator = "operator" // 操作员：节点管理
    RoleViewer = "viewer"     // 查看者：只读权限
)

// 权限检查
func RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRoles, exists := c.Get("roles")
        if !exists {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "code":    40301,
                "message": "access denied",
            })
            return
        }

        userRoleList := userRoles.([]string)
        for _, requiredRole := range roles {
            for _, userRole := range userRoleList {
                if userRole == requiredRole || userRole == RoleAdmin {
                    c.Next()
                    return
                }
            }
        }

        c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
            "code":    40302,
            "message": "insufficient permissions",
        })
    }
}

// 使用示例
func SetupRoutes(r *gin.Engine) {
    admin := r.Group("/api/v1")
    admin.Use(JWTAuth(secret))
    admin.Use.RequireRole(RoleAdmin)

    admin.POST("/nodes", CreateNode)
    admin.DELETE("/nodes/:id", DeleteNode)
}
```

### 2.3 API Key 认证

```go
type APIKeyAuth struct {
    HeaderName string
    Keys       map[string]*APIKeyInfo
}

type APIKeyInfo struct {
    KeyID       string
    Secret      string
    Permissions []string
    ExpiresAt   time.Time
    Enabled     bool
}

func APIKeyAuthMiddleware(auth *APIKeyAuth) gin.HandlerFunc {
    return func(c *gin.Context) {
        keyID := c.GetHeader(auth.HeaderName)
        if keyID == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "code":    40104,
                "message": "missing API key",
            })
            return
        }

        keyInfo, exists := auth.Keys[keyID]
        if !exists || !keyInfo.Enabled {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "code":    40105,
                "message": "invalid API key",
            })
            return
        }

        if time.Now().After(keyInfo.ExpiresAt) {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "code":    40106,
                "message": "API key expired",
            })
            return
        }

        c.Set("key_id", keyID)
        c.Set("permissions", keyInfo.Permissions)

        c.Next()
    }
}
```

---

## 3. 传输安全

### 3.1 TLS 配置

```go
// 生成自签名证书（仅开发环境）
func GenerateSelfSignedCert() (*tls.Certificate, error) {
    cert := &x509.Certificate{
        SerialNumber:          big.NewInt(1),
        Subject:               pkix.Name{Organization: []string{"AI CDN"}},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(24 * time.Hour * 365),
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        DNSNames:              []string{"localhost", "*.ai-cdn.local"},
    }

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }

    certDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
    if err != nil {
        return nil, err
    }

    return &tls.Certificate{
        Certificate: [][]byte{certDER},
        PrivateKey:  privateKey,
    }
}
```

### 3.2 生产环境 TLS 配置

```yaml
# config/tls.yml
tls:
  # 证书文件路径
  cert_file: /etc/ai-cdn/certs/server.crt
  key_file: /etc/ai-cdn/certs/server.key

  # 证书链文件
  ca_file: /etc/ai-cdn/certs/ca.crt

  # TLS 版本
  min_version: "1.3"
  max_version: "1.3"

  # 密码套件
  cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_AES_128_GCM_SHA256"
    - "TLS_CHACHA20_POLY1305_SHA256"

  # 客户端认证
  client_auth: "require-and-verify-client-cert-if-given"

  # OCSP Stapling
  ocsp_stapling: true
```

### 3.3 gRPC TLS 配置

```go
func CreateGRPCServer() *grpc.Server {
    // 加载证书
    cert, err := tls.LoadX509KeyPair(
        "/etc/ai-cdn/certs/server.crt",
        "/etc/ai-cdn/certs/server.key",
    )
    if err != nil {
        log.Fatalf("Failed to load TLS certificate: %v", err)
    }

    // 创建 TLS 配置
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientAuth:   tls.NoClientCert,
        MinVersion:   tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
    }

    return grpc.NewServer(
        grpc.Creds(credentials.NewTLS(tlsConfig)),
    )
}
```

---

## 4. 网络安全

### 4.1 IP 白名单/黑名单

```go
type AccessControl struct {
    whitelist      map[string]bool
    blacklist      map[string]bool
    subnetWhitelist map[string]*net.IPNet
    subnetBlacklist map[string]*net.IPNet
    mu             sync.RWMutex
}

func (ac *AccessControl) AllowIP(ip string) bool {
    ac.mu.RLock()
    defer ac.mu.RUnlock()

    // 检查黑名单
    if ac.blacklist[ip] {
        return false
    }

    // 检查子网黑名单
    for _, subnet := range ac.subnetBlacklist {
        if subnet.Contains(net.ParseIP(ip)) {
            return false
        }
    }

    // 检查白名单
    if ac.whitelist[ip] {
        return true
    }

    // 检查子网白名单
    for _, subnet := range ac.subnetWhitelist {
        if subnet.Contains(net.ParseIP(ip)) {
            return true
        }
    }

    // 默认拒绝
    return false
}
```

### 4.2 DDoS 防护

```go
type DDoSProtection struct {
    config          *DDoSConfig
    ipCounter       map[string]*RateCounter
    globalCounter   *RateCounter
    blockedIPs      map[string]time.Time
    mu              sync.RWMutex
}

type DDoSConfig struct {
    GlobalRateLimit    int             // 全局限流: 10000 req/s
    GlobalBurstSize    int             // 突发: 20000
    PerIPRateLimit     int             // 单 IP 限流: 100 req/s
    PerIPBurstSize     int             // 单 IP 突发: 200
    BlockDuration      time.Duration   // 封锁时间: 5m
    DetectionWindow    time.Duration   // 检测窗口: 1s
}

func (p *DDoSProtection) CheckRequest(ip string) (bool, string) {
    // 检查是否被封锁
    if p.isBlocked(ip) {
        return false, "IP is temporarily blocked"
    }

    // 全局限流检查
    if !p.globalCounter.Allow() {
        p.blockIP(ip, "global rate limit exceeded")
        return false, "rate limit exceeded"
    }

    // 单 IP 限流检查
    counter := p.getIPCounter(ip)
    if !counter.Allow() {
        p.blockIP(ip, "per-ip rate limit exceeded")
        return false, "rate limit exceeded"
    }

    return true, ""
}

func (p *DDoSProtection) blockIP(ip, reason string) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.blockedIPs[ip] = time.Now().Add(p.config.BlockDuration)
    log.Warnf("IP %s blocked: %s", ip, reason)
}
```

### 4.3 5秒盾（高频访问限制）

```go
type FiveSecondShield struct {
    config     *ShieldConfig
    visitorMap map[string]*VisitorInfo
    whiteList  map[string]bool
    blackList  map[string]bool
    mu         sync.RWMutex
    stats      *ShieldStats
}

type ShieldConfig struct {
    Enabled:       true,
    WindowSize:    5 * time.Second,
    MaxRequests:   10,
    BlockDuration: 60 * time.Second,
    Algorithm:     "sliding_window", // token_bucket | sliding_window
}

func (s *FiveSecondShield) CheckRequest(ip string) (bool, string) {
    // 检查白名单
    if s.whiteList[ip] {
        return true, ""
    }

    // 检查黑名单
    if s.blackList[ip] {
        return false, "IP in blacklist"
    }

    visitor, exists := s.visitorMap[ip]

    if !exists {
        visitor = &VisitorInfo{
            IP:           ip,
            RequestCount: 1,
            FirstRequest: time.Now(),
        }
        s.visitorMap[ip] = visitor
        return true, ""
    }

    // 检查是否在封锁期
    if visitor.Blocked && time.Now().Before(visitor.BlockExpiry) {
        return false, "too many requests, please try later"
    }

    // 重置封锁状态
    if visitor.Blocked {
        visitor.Blocked = false
        visitor.RequestCount = 0
    }

    // 更新访问信息
    visitor.RequestCount++
    visitor.LastRequest = time.Now()

    // 检查是否超出限制
    windowStart := time.Now().Add(-s.config.WindowSize)
    if visitor.FirstRequest.Before(windowStart) {
        visitor.RequestCount = 1
        visitor.FirstRequest = time.Now()
    }

    if visitor.RequestCount > s.config.MaxRequests {
        visitor.Blocked = true
        visitor.BlockExpiry = time.Now().Add(s.config.BlockDuration)
        return false, "too many requests"
    }

    return true, ""
}
```

---

## 5. 应用安全

### 5.1 输入验证

```go
// 请求验证器
type NodeValidator struct{}

func (v *NodeValidator) ValidateCreateNode(req *CreateNodeRequest) error {
    if req.Name == "" {
        return fmt.Errorf("name is required")
    }

    if len(req.Name) > 63 {
        return fmt.Errorf("name must be less than 63 characters")
    }

    if !regexp.MustCompile(`^[a-zA-Z0-9-_]+$`).MatchString(req.Name) {
        return fmt.Errorf("name must contain only alphanumeric characters, hyphens and underscores")
    }

    if req.Region == "" {
        return fmt.Errorf("region is required")
    }

    validRegions := map[string]bool{
        "hk": true, "cn": true, "us": true, "sg": true,
    }
    if !validRegions[req.Region] {
        return fmt.Errorf("invalid region")
    }

    return nil
}

// 使用示例
func CreateNode(c *gin.Context) {
    var req CreateNodeRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "code":    40001,
            "message": "invalid request body",
        })
        return
    }

    validator := &NodeValidator{}
    if err := validator.ValidateCreateNode(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "code":    40002,
            "message": err.Error(),
        })
        return
    }

    // 处理请求...
}
```

### 5.2 SQL 注入防护

```go
// 使用参数化查询（MongoDB 原生支持）
func GetNode(ctx context.Context, nodeID string) (*Node, error) {
    // MongoDB 使用 BSON，自动防止注入
    filter := bson.M{"_id": nodeID}
    var node Node
    err := nodes.FindOne(ctx, filter).Decode(&node)
    return &node, err
}

// 避免：不要拼接查询字符串
// 错误示例
// query := "db.nodes.find({_id: '" + nodeID + "'})"  // 危险！
```

### 5.3 命令注入防护

```go
// 避免使用 exec.Command 执行用户输入
// 正确做法：使用白名单验证

func ExecuteCommand(cmd string, allowedCommands map[string]bool) error {
    if !allowedCommands[cmd] {
        return fmt.Errorf("command not allowed")
    }

    // 使用预定义的命令
    switch cmd {
    case "reload":
        return reloadConfig()
    case "restart":
        return restartService()
    case "status":
        return getStatus()
    default:
        return fmt.Errorf("unknown command")
    }
}

// 避免：不要直接执行用户输入的命令
// 错误示例
// cmd := exec.Command("bash", "-c", userInput)  // 危险！
```

### 5.4 XSS 防护

```go
import "html/template"

// 使用 html/template 自动转义
var tmpl = template.Must(template.New("page").Parse(`
{{define "node"}}
<div>{{.Name}}</div>
<div>{{.Description}}</div>
{{end}}
`))

// 输出 JSON 时使用 HTMLEscape
func WriteJSON(w http.ResponseWriter, data interface{}) {
    jsonBytes, _ := json.Marshal(data)
    w.Header().Set("Content-Type", "application/json")
    w.Write(jsonBytes)
}

// 设置安全响应头
func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Next()
    }
}
```

---

## 6. 数据安全

### 6.1 敏感数据加密

```go
// 使用 AES-256-GCM 加密
type Encryption struct {
    key []byte
}

func NewEncryption(key []byte) *Encryption {
    if len(key) != 32 {
        panic("key must be 32 bytes")
    }
    return &Encryption{key: key}
}

func (e *Encryption) Encrypt(plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

func (e *Encryption) Decrypt(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
```

### 6.2 密码哈希

```go
// 使用 bcrypt 哈希密码
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
```

### 6.3 密钥管理

```bash
# 使用环境变量存储密钥
export JWT_SECRET="your-jwt-secret-here"
export ENCRYPTION_KEY="your-32-byte-encryption-key"
export DB_PASSWORD="your-database-password"

# 或使用密钥管理服务
# - HashiCorp Vault
# - AWS Secrets Manager
# - Azure Key Vault
# - GCP Secret Manager
```

---

## 7. 监控与审计

### 7.1 安全审计日志

```go
type AuditLogger struct {
    logger *logs.Logger
}

type AuditEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    UserID      string    `json:"user_id"`
    Username    string    `json:"username"`
    Action      string    `json:"action"`
    Resource    string    `json:"resource"`
    ResourceID  string    `json:"resource_id"`
    IP          string    `json:"ip"`
    UserAgent   string    `json:"user_agent"`
    Success     bool      `json:"success"`
    Error       string    `json:"error,omitempty"`
}

func (l *AuditLogger) Log(event *AuditEvent) {
    l.logger.WithFields(logs.Fields{
        "type":      "audit",
        "user_id":   event.UserID,
        "username":  event.Username,
        "action":    event.Action,
        "resource":  event.Resource,
        "resource_id": event.ResourceID,
        "ip":        event.IP,
        "success":   event.Success,
        "error":     event.Error,
    }).Info("audit event")
}

// 使用示例
func CreateNode(c *gin.Context) {
    userID, _ := c.Get("user_id")
    username, _ := c.Get("username")

    event := &AuditEvent{
        Timestamp:  time.Now(),
        UserID:     userID.(string),
        Username:   username.(string),
        Action:     "create_node",
        Resource:   "node",
        ResourceID: req.ID,
        IP:         c.ClientIP(),
        UserAgent:  c.GetHeader("User-Agent"),
        Success:    true,
    }

    auditLogger.Log(event)
}
```

### 7.2 安全监控指标

```go
// 安全相关 Prometheus 指标
var (
    authRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_requests_total",
            Help: "Total number of authentication requests",
        },
        []string{"status", "method"},
    )

    authLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "auth_latency_seconds",
            Help:    "Authentication request latency",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method"},
    )

    blockedIPsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "blocked_ips_total",
            Help: "Total number of blocked IPs",
        },
    )

    rateLimitHitsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "rate_limit_hits_total",
            Help: "Total number of rate limit hits",
        },
        []string{"type"},
    )
)
```

### 7.3 告警规则

```yaml
# config/rules/security-alerts.yml
groups:
- name: security-alerts
  rules:
  # 认证失败告警
  - alert: HighAuthFailureRate
    expr: rate(auth_requests_total{status="failure"}[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "认证失败率过高"

  # IP 被封锁告警
  - alert: HighBlockRate
    expr: rate(blocked_ips_total[5m]) > 10
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "IP 封锁频率过高，可能正在遭受攻击"

  # 限流告警
  - alert: RateLimitHits
    expr: rate(rate_limit_hits_total[5m]) > 100
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "限流触发频率过高"
```

---

## 8. 安全配置

### 8.1 生产环境安全配置

```yaml
# config/security.yml
security:
  # JWT 配置
  jwt:
    secret: "${JWT_SECRET}"  # 从环境变量读取
    expiration: 1h           # 短过期时间
    refresh_expiration: 24h

  # TLS 配置
  tls:
    enabled: true
    min_version: "1.3"
    cert_file: "/etc/ai-cdn/certs/server.crt"
    key_file: "/etc/ai-cdn/certs/server.key"

  # 访问控制
  access_control:
    enabled: true
    default_policy: "deny"
    whitelist:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"

  # DDoS 防护
  ddos_protection:
    enabled: true
    global_rate_limit: 10000
    global_burst: 20000
    per_ip_limit: 100
    per_ip_burst: 200
    block_duration: 5m

  # 5秒盾
  five_second_shield:
    enabled: true
    window_size: 5s
    max_requests: 10
    block_duration: 60s

  # 日志
  audit:
    enabled: true
    level: "info"
    output: "file"
    path: "/var/log/ai-cdn/audit.log"
```

### 8.2 安全检查清单

- [ ] 启用 TLS 1.3
- [ ] 使用强密码 (>16字符)
- [ ] 启用 JWT 认证
- [ ] 配置 IP 白名单
- [ ] 启用 DDoS 防护
- [ ] 启用审计日志
- [ ] 定期轮换密钥
- [ ] 禁用不必要的服务
- [ ] 配置防火墙规则
- [ ] 启用安全响应头

---

## 9. 应急响应

### 9.1 应急响应流程

```
1. 检测 → 2. 分类 → 3. 遏制 → 4. 根除 → 5. 恢复 → 6. 复盘
```

### 9.2 常见应急场景

#### 9.2.1 疑似入侵

```bash
# 1. 隔离受影响节点
# 2. 保存证据（日志、内存转储）
# 3. 检查未授权访问
# 4. 重置凭证
# 5. 更新安全策略
```

#### 9.2.2 DDoS 攻击

```bash
# 1. 启用更严格的限流
# 2. 启用 IP 封锁
# 3. 启用 CDN 防护
# 4. 监控攻击流量
# 5. 联系 ISP
```

#### 9.2.3 数据泄露

```bash
# 1. 识别泄露范围
# 2. 遏制泄露
# 3. 通知受影响方
# 4. 调查根因
# 5. 修复漏洞
```

### 9.3 紧急联系人

| 角色 | 职责 | 联系 |
|------|------|------|
| 安全负责人 | 决策协调 | security@example.com |
| 运维负责人 | 系统恢复 | ops@example.com |
| 开发负责人 | 代码修复 | dev@example.com |

---

## 附录

### A. 安全相关配置参数

| 参数 | 类型 | 默认值 | 安全级别 |
|------|------|--------|----------|
| `jwt.secret` | string | - | 高 |
| `tls.cert_file` | path | - | 高 |
| `access_control.whitelist` | list | [] | 中 |
| `ddos.global_rate_limit` | int | 10000 | 中 |
| `five_second_shield.max_requests` | int | 10 | 中 |

### B. 安全测试工具

| 工具 | 用途 |
|------|------|
| OWASP ZAP | Web 漏洞扫描 |
| Nmap | 端口扫描 |
| Wireshark | 网络分析 |
| Burp Suite | API 测试 |
| Ghidra | 二进制分析 |

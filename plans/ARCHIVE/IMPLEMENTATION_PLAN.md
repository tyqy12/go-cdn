# GoCDN 动态内容 CDN 防攻击系统 - 实施计划

## 文档信息

| 项目 | 内容 |
|------|------|
| 项目名称 | GoCDN Dynamic Content CDN Defense System |
| 版本 | v1.5 (修订版) |
| 创建日期 | 2025-01-03 |
| 修订日期 | 2026-01-03 |
| 状态 | 规划中 |

---

## 1. 项目概述

### 1.1 背景

纯动态内容 CDN 防攻击是业界难题。传统 CDN 依赖缓存加速，但动态内容无法缓存，源站直接暴露，易受攻击。本项目旨在构建一套完整的动态内容 CDN 防攻击系统，利用 gost 强大的代理能力实现流量分发和清洗。

### 1.2 项目目标

**核心目标：**
- 构建基于 gost 的动态流量分发系统（零缓存转发）
- 实现智能流量分类（正常/可疑/攻击）
- 支持流量自动分流到清洗节点
- 具备源站保护和故障自动转移能力

### 1.3 性能指标（v1 可验收目标）

> **注意：** 以下指标为 v1 版本可达成的工程目标。ML 高级指标 (>99% 准确率、<0.1% 误杀、<1ms 分类延迟) 和 10Gbps 清洗吞吐属于 v2/v3 增强目标，需配合上游高防引流和真实数据闭环后方可验收。

| 指标 | v1 目标值 | v2/v3 增强目标 | 说明 |
|------|----------|----------------|------|
| 请求延迟增加 | < 10ms | < 5ms | 端到端转发延迟增量 |
| 基础防护准确率 | > 90% | > 95% | 基于规则/行为分析的检测 |
| ML 检测准确率 | - | > 99% | v2 目标，需数据闭环 |
| 误杀率 | < 1% | < 0.1% | v1 基于规则，v2 基于 ML |
| 分类延迟 | < 5ms | < 1ms | 规则引擎级，ML 推理单独计量 |
| 清洗吞吐 | 1-2Gbps | > 10Gbps | v1 受限于接入带宽 |
| 系统可用性 | > 99.9% | > 99.99% | 单节点到多节点冗余 |

---

## 2. 动态内容设计原则

> **核心约束：** 动态内容（API、个性化页面、SSE/WebSocket、LLM 对话等）不可缓存/很难安全缓存，导致：
> - 边缘节点必须做更多数据面工作（连接复用、协议栈优化、负载均衡、会话粘性）
> - 抗 CC 重点从"缓存吸收"变成"回源前识别并切断"
> - 挑战验证适用面变窄，API/SDK/LLM 客户端无法执行 JS/Captcha
> - 请求合并/去重仅对幂等 GET 安全，对 POST/个性化请求禁止合并

### 2.1 TLS 终止策略

| 模式 | 适用场景 | 防护能力 | 实现复杂度 |
|------|----------|----------|------------|
| **L4 四层转发** | 只需连接级限速、IP 控制 | L4 限速、黑白名单 | 低 |
| **L7 七层代理** | 需要路径规则、JS/Captcha、WAF | 完整 L7 防护、挑战验证 | 中 |

**本系统设计：**
- **默认模式：L7 代理** - Edge 必须终止 TLS 以获取 HTTP 可见性，支持完整的 L7 防护规则
- **可选模式：L4 透传** - 对纯 TCP/UDP 服务（如数据库代理），仅做四层转发

### 2.2 挑战验证适用边界

| 业务类型 | 路径模式 | 可用挑战 | 禁用场景 |
|----------|----------|----------|----------|
| Web 页面 | `/*.html`, `/*.htm` | JS Challenge, Captcha | - |
| 静态资源 | `/static/*`, `/assets/*` | JS Challenge | - |
| API 端点 | `/api/*` | **禁止 JS/Captcha** | SDK 调用、机器对机器 |
| LLM 对话 | `/v1/chat/*` | **禁止所有挑战** | 客户端无法执行 JS |
| 登录认证 | `/api/login`, `/api/auth/*` | 速率限制、行为分析 | 禁止 Captcha（影响体验） |

> **原则：** 挑战验证必须配置"适用路径白名单"，未明确配置的路径默认禁用挑战。

### 2.3 请求合并去重约束

**仅对以下请求可安全合并：**
- ✅ 幂等 GET 请求（无副作用）
- ✅ 相同 cache-key（Query 参数、关键 Header、身份态 Cookie 等价）
- ✅ 相同请求体（POST 幂等场景）

**禁止合并：**
- ❌ POST/PUT/DELETE 等有副作用请求
- ❌ 携带强个性化身份态的请求
- ❌ 带时间戳/序列号等可变参数的请求

---

## 3. 系统架构

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                          用户请求                                     │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Edge 边缘节点集群                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    流量分析层                                 │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │   │
│  │  │ 5秒盾限流 │  │ 行为分析 │  │ 规则引擎 │  │ 挑战验证 │    │   │
│  │  │ 速率限制 │  │ 画像分析 │  │ 黑白名单 │  │ (限Web)  │    │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    gost 隧道转发层                           │   │
│  │  - HTTP/HTTPS/SOCKS5/TCP/UDP 隧道 (L7/L4)                   │   │
│  │  - TLS 终止 + HTTP 可见性                                    │   │
│  │  - 智能流量分发 + 故障转移                                    │   │
│  │  - 连接池管理                                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
            ▼                     ▼                     ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   正常流量        │  │   可疑流量       │  │   攻击流量       │
│   业务服务器      │  │   挑战验证       │  │   清洗节点       │
│   (源站)          │  │   (限Web)        │  │   (隔离区)       │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

### 3.2 数据面形态（需 M0 确认）

| 配置项 | 选项 | 当前设计 |
|--------|------|----------|
| TLS 终止 | Edge 终止 / 透传 | Edge 终止（L7 代理模式） |
| HTTP 版本 | HTTP/1.1, H2；H3 | **v1: HTTP/1.1 + H2**（必须）；**H3: v2 可选**（单独里程碑） |
| 实时协议 | WS, SSE | 支持 |
| 挑战策略 | JS/Captcha / 禁用 | 按路径配置（见 2.2） |
| 高防牵引 | DNS / Anycast / BGP 牵引 | **必须落地**（见 3.4），否则“高防清洗”无法闭环 |
| 清洗模式 | Sinkhole / Scrubbing（回注放行） | **v1: Sinkhole 必须**；Scrubbing（回注）作为 v1.5+ 可选增强 |
| 回注方案 | GRE / IPIP / 专线 | 由 M0 确认（推荐：GRE 回注到 Edge/Origin 私网入口） |

### 3.3 组件职责

| 组件 | 职责 | 技术栈 | 状态 |
|------|------|--------|------|
| **Traffic Classifier** | 流量分类、异常检测 | Go + 规则引擎 | 框架已完成 |
| **Tunnel Manager** | gost 隧道管理 | Go + gost v3 | 框架已完成 |
| **Traffic Distributor** | 流量分发、路由选择 | Go | 待开发 |
| **Cleaning Node** | 攻击流量处置（Sinkhole）/ 回注对接（Scrubbing） | Go | 占位实现 |
| **Challenge Manager** | 挑战验证管理（限 Web） | Go | 占位实现 |
| **Monitor Dashboard** | 监控面板 | Vue3 + Grafana | 框架已完成 |

> **技术栈对齐：** 本系统使用 Vue3（而非 React）作为前端框架，与 `web-admin/` 目录保持一致。

### 3.4 高防牵引与清洗数据面（M0 必须确认）

> **结论先行：** “动态内容 CDN 防攻击”要做到**高防清洗**，必须补齐网络层数据面闭环：**牵引（steering）→ 清洗（scrubbing）→ 回注（reinjection）→ 回切（fallback）**。  
> 本项目的 Go/gost 侧更适合承载 **L7 可见性、业务侧风控与精细分流**；带宽型 DDoS（>1-2Gbps）应由**上游高防/清洗中心**消化（BGP 牵引/Anycast/云高防）。

#### 3.4.1 两条数据面：正常转发 vs 触发清洗

**A) 正常路径（未牵引）**

```
Client ──(DNS/Anycast)──> Edge(L7终止+分类) ──> Origin(源站私网入口)
```

**B) 清洗路径（牵引后）**

```
Client ──(BGP牵引/高防IP)──> Scrubbing Center(上游清洗)
                                  │
                                  ├─(过滤恶意/限速/丢弃)
                                  │
                                  └─(GRE/IPIP 回注)──> Edge 或 Origin 私网入口
```

> **关键点：** 若缺少“回注到业务侧”的明确网络路径与访问控制，清洗只能变成“黑洞丢弃”，无法称为“清洗放行”。

#### 3.4.2 牵引触发与回切（控制面）

**触发信号（建议至少三类，避免误触发）：**
- **链路/边界指标：** 入方向带宽、PPS、SYN/ACK 比例、连接建立速率
- **应用指标：** 5xx/超时飙升、队列堆积、CPU/FD/连接数打满
- **业务风控指标：** 规则命中率异常、单 AS/单网段/单 UA 指纹异常聚集

**牵引策略（M0 要决定“谁来做、怎么做”）：**
- DNS 切换：易用但切换慢、粒度粗（适合区域级降级/备切）
- Anycast：低时延但回程/对称性复杂（适合常态化 POP）
- BGP 牵引：针对 DDoS 最常见的工程手段（需与运营商/云高防协同）

**回切策略（必须写进验收）：**
- 需要“稳定窗口 + 抖动保护”，避免频繁牵引/回切引发二次故障
- 回切后持续观测一段时间，确认攻击已结束或降到 Edge 可承载范围

#### 3.4.3 源站保护（高防闭环的硬前提）

无论是否使用清洗中心，必须满足至少一条（M0 决策并落地）：
- 源站仅接受来自 **Edge/回注网段** 的入站（安全组/ACL/防火墙白名单）
- 源站对公网不可达（私网/VPC/专线），Edge 作为唯一入口

> 否则攻击者可绕过 Edge/清洗链路直打源站，“源站隐藏”无法成立。

---

## 4. 里程碑式实施计划

### 4.1 里程碑概览

| 里程碑 | 目标 | 工期 | 验收重点 |
|--------|------|------|----------|
| **M0** | 明确数据面形态 | 3-5 天 | **TLS/协议/挑战策略 + 高防牵引/回注闭环确认** |
| **M1** | 零缓存稳定转发 + 源站隐藏 | 2-3 周 | 可用性 > 99.9%，故障切换 |
| **M2** | 确定性防护落地 | 2-3 周 | 误伤 < 1%，基础检测 > 90% |
| **M3** | 可观测性 + 增强项 | 2 周 | 监控完整，ML 探索 |

### 4.2 M0: 数据面形态确认（3-5 天）

> **目标：** 在进入开发前，明确系统的数据面形态，这是后续一切工作的前提。

**任务清单：**

| 序号 | 任务 | 输出物 |
|------|------|--------|
| M0.1 | 确定 Edge TLS 终止策略 | 架构决策文档 |
| M0.2 | 确定支持的动态协议清单 | 协议支持矩阵 |
| M0.3 | 定义 API vs Browser 路径边界 | 路径分类配置 |
| M0.4 | 确定挑战验证的路径白名单 | 挑战策略配置 |
| M0.5 | 确认 gost 版本（v2.11+ vs v3） | 版本锁定 |
| M0.6 | 明确高防牵引方式（DNS/Anycast/BGP） | 数据面决策文档 |
| M0.7 | 明确清洗路径（上游高防/清洗中心） | 牵引/回注拓扑图 |
| M0.8 | 明确回注方案（GRE/IPIP/专线）与 MTU 策略 | 回注参数与约束清单 |
| M0.9 | 源站保护策略落地（仅允许 Edge/回注网段） | 安全组/ACL 规则说明 |
| M0.10 | 牵引触发/回切策略定义（含抖动保护） | 触发阈值与演练方案 |

**验收标准：**
- [ ] TLS 终止策略已文档化
- [ ] 协议支持矩阵已定义
- [ ] 挑战验证路径白名单已配置
- [ ] gost 版本已锁定并测试兼容
- [ ] 高防牵引方式已选型并完成最小可用连通性验证
- [ ] 清洗路径与回注拓扑已文档化（含 GRE/IPIP 端点）
- [ ] 源站保护策略已落地（源站不可被公网绕过直连）
- [ ] 牵引/回切演练用例已定义（含抖动保护与回切窗口）

---

### 4.3 M1: 零缓存稳定转发 + 源站隐藏（2-3 周）

> **目标：** 构建"动态内容 CDN"核心可用性基础设施——边缘节点稳定转发、源站隐藏、故障自动切换、连接型抗攻击。

#### 4.3.1 核心设计原则

**零缓存转发的本质挑战：**
- 无法利用缓存吸收流量，所有请求必须回源
- 边缘节点承担完整的数据面处理压力
- 连接管理、超时控制、资源隔离成为关键
- 故障切换必须在毫秒级完成，保证业务连续性

**架构约束：**
- 动态内容必须保持端到端透传，不做任何缓存
- 支持多种协议栈的优雅降级与协议感知
- 源站必须完全隐藏，不可被公网直接访问
- 故障转移过程对客户端透明

#### 4.3.2 任务拆解

| 序号 | 任务 | 技术深度要求 | 工期 | 依赖 | 关键产出 |
|------|------|------------|------|------|---------|
| **1.1** | **项目工程化基础** | Go Module、目录结构、Makefile、Dockerfile、CI/CD | 2天 | - | 项目脚手架、构建流水线 |
| **1.2** | **配置管理体系** | 多源配置加载、热更新机制、配置校验、版本回滚 | 3天 | - | 配置模块、配置热更新接口 |
| **1.3** | **gost v3 隧道管理** | 生命周期管理、状态机、资源池、优雅关闭 | 5天 | - | 隧道管理器、状态监控 |
| **1.4** | **TLS 终止优化** | TLS 1.3、OCSP Stapling、证书预加载、Session Cache | 3天 | 1.3 | TLS 处理器、证书管理器 |
| **1.5** | **连接池与复用** | 连接复用、长连接管理、Keep-Alive 优化、连接预热 | 3天 | 1.3 | 连接池管理器、连接复用策略 |
| **1.6** | **多策略负载均衡** | 轮询、加权、最少连接、IP Hash、一致性哈希 | 3天 | 1.3 | 负载均衡策略集合 |
| **1.7** | **多层健康检查** | TCP 连接、HTTP 健康探针、TLS 握手、应用层心跳 | 2天 | 1.3 | 健康检查引擎 |
| **1.8** | **故障转移引擎** | 自动检测、决策算法、无缝切换、回滚机制 | 2天 | 1.7 | 故障转移控制器 |
| **1.9** | **连接型抗攻击防护** | 连接限速、慢连接防护、超时控制、资源隔离 | 2天 | 1.4 | 连接保护引擎、限流器 |
| **1.10** | **核心模块单元测试** | 覆盖率 > 75%、Mock 外部依赖、性能基准测试 | 3天 | 1.1-1.9 | 测试套件、覆盖率报告 |

#### 4.3.3 技术深化设计

**1.3 gost v3 隧道管理深度设计**

```go
// 隧道状态机
type TunnelState string

const (
    TunnelStateInitializing TunnelState = "initializing"
    TunnelStateActive       TunnelState = "active"
    TunnelStateDegraded     TunnelState = "degraded"
    TunnelStateDraining     TunnelState = "draining"
    TunnelStateTerminated   TunnelState = "terminated"
)

// 隧道管理器核心接口
type TunnelManager interface {
    // 创建隧道，支持协议配置与资源配额
    CreateTunnel(ctx context.Context, config *TunnelConfig) (*Tunnel, error)
    
    // 优雅关闭隧道，先排空连接后销毁
    GracefulShutdown(ctx context.Context, tunnelID string) error
    
    // 强制关闭隧道，立即终止所有连接
    ForceShutdown(ctx context.Context, tunnelID string) error
    
    // 查询隧道状态与实时指标
    GetTunnelStatus(ctx context.Context, tunnelID string) (*TunnelStatus, error)
    
    // 热更新隧道配置，平滑切换不停服务
    UpdateConfig(ctx context.Context, tunnelID string, config *TunnelConfig) error
    
    // 批量操作，支持原子性
    BatchCreate(ctx context.Context, configs []*TunnelConfig) ([]*Tunnel, error)
}

// 隧道实时指标
type TunnelMetrics struct {
    ConnectionCount     atomic.Int64  // 当前连接数
    BytesTransferred    atomic.Uint64 // 已传输字节数
    RequestCount        atomic.Uint64 // 请求计数
    ErrorCount          atomic.Uint64 // 错误计数
    LatencyP50          atomic.Duration
    LatencyP99          atomic.Duration
    HealthScore         atomic.Float64 // 健康评分 0-100
}
```

**1.4 TLS 终止性能优化**

```go
// TLS 配置优化
type TLSConfig struct {
    MinVersion    uint16              // tls.VersionTLS12
    MaxVersion    uint16              // tls.VersionTLS13
    CipherSuites  []uint16            // 现代密码套件
    CurvePreferences []tls.CurveID    // X25519, P256, P384
    
    // Session Cache
    SessionCache   tls.ClientSessionCache
    
    // OCSP Stapling
    OCSPStapling   bool
    
    // 证书预加载
    CertPreload    bool
    
    // 证书自动轮换
    CertAutoRotate bool
    CertWatcher    CertWatcher
}

// TLS 握手优化
func (s *TLSServer) optimizeHandshake(conn net.Conn) *tls.Conn {
    tlsConn := tls.Server(conn, s.config)
    
    // 启用 Session Ticket
    tlsConn.SetSessionCache(s.sessionCache)
    
    // 启用 OCSP Stapling
    if s.config.OCSPStapling {
        tlsConn.SetOCSPResponse(s.getOCSPResponse())
    }
    
    return tlsConn
}
```

**1.5 连接池与复用设计**

```go
// 连接池配置
type ConnectionPoolConfig struct {
    MaxIdleConnections     int           // 最大空闲连接数
    MaxActiveConnections   int           // 最大活跃连接数
    IdleTimeout            time.Duration // 空闲超时
    MaxConnectionAge       time.Duration // 连接最大生命周期
    MaxConnectionLifetime  time.Duration // 连接最大存活时间
    WaitTimeout            time.Duration // 获取连接等待超时
    KeepAliveInterval      time.Duration // TCP Keep-Alive 间隔
    KeepAliveTimeout       time.Duration // TCP Keep-Alive 超时
}

// 连接复用策略
type ConnectionReuseStrategy interface {
    // 判断连接是否可复用
    CanReuse(conn *Connection, req *http.Request) bool
    
    // 选择最优连接
    SelectConnection(pool *ConnectionPool, req *http.Request) (*Connection, error)
    
    // 连接健康检查
    HealthCheck(conn *Connection) error
}

// HTTP/2 多路复用连接池
type HTTP2ConnectionPool struct {
    *ConnectionPool
    streams     map[uint32]*Stream // 活跃流
    maxStreams  int               // 每个连接最大流数
    streamMutex sync.RWMutex
}
```

**1.6 多策略负载均衡**

```go
// 负载均衡策略接口
type LoadBalancer interface {
    // 选择目标节点
    Select(targets []*Target, req *http.Request) (*Target, error)
    
    // 健康状态更新
    UpdateHealth(targetID string, healthy bool)
    
    // 权重动态调整
    AdjustWeight(targetID string, weight int) error
}

// 加权最少连接策略
type WeightedLeastConnections struct {
    sync.RWMutex
    targets map[string]*WeightedTarget
}

type WeightedTarget struct {
    *Target
    Weight       int
    ActiveConns  int
    Capacity     int
}

func (lb *WeightedLeastConnections) Select(targets []*Target, req *http.Request) (*Target, error) {
    lb.RLock()
    defer lb.RUnlock()
    
    var selected *WeightedTarget
    minScore := math.MaxFloat64
    
    for _, t := range lb.targets {
        // 计算负载分数：活跃连接数 / 权重
        if t.Healthy {
            score := float64(t.ActiveConns) / float64(t.Weight)
            if score < minScore {
                minScore = score
                selected = t
            }
        }
    }
    
    if selected == nil {
        return nil, ErrNoHealthyTarget
    }
    
    selected.ActiveConns++
    return selected.Target, nil
}
```

**1.7 多层健康检查**

```go
// 健康检查类型
type HealthCheckType string

const (
    HealthCheckTCP     HealthCheckType = "tcp"
    HealthCheckHTTP    HealthCheckType = "http"
    HealthCheckTLS     HealthCheckType = "tls"
    HealthCheckApp     HealthCheckType = "app"
)

// 健康检查配置
type HealthCheckConfig struct {
    Type          HealthCheckType
    Interval      time.Duration
    Timeout       time.Duration
    UnhealthyThreshold int // 连续失败阈值
    HealthyThreshold   int // 连续成功阈值
    
    // HTTP 特有配置
    HTTPPath      string
    HTTPMethod    string
    ExpectedCodes []int
    ExpectedBody  string
    
    // TLS 特有配置
    TLSServerName string
    
    // 应用层配置
    AppCheckFunc  func(ctx context.Context) error
}

// 健康检查结果
type HealthCheckResult struct {
    TargetID      string
    Healthy       bool
    Latency       time.Duration
    Error         error
    Timestamp     time.Time
    ConsecutiveFailures int
    ConsecutiveSuccesses int
}
```

**1.8 故障转移引擎**

```go
// 故障转移策略
type FailoverStrategy string

const (
    FailoverStrategyAuto       FailoverStrategy = "auto"
    FailoverStrategyManual     FailoverStrategy = "manual"
    FailoverStrategyActiveOnly FailoverStrategy = "active_only"
)

// 故障转移控制器
type FailoverController struct {
    config       *FailoverConfig
    healthStore  HealthStore
    decisionTree DecisionTree
    stateMachine *StateMachine
    metrics      *FailoverMetrics
}

type FailoverConfig struct {
    Strategy       FailoverStrategy
    SwitchTimeout  time.Duration
    RollbackDelay  time.Duration
    MaxRollbacks   int
    StickySessions bool
}

// 故障决策树
type DecisionNode interface {
    Evaluate(ctx context.Context, input *FailoverInput) (*FailoverDecision, error)
}

// 故障决策
type FailoverDecision struct {
    Action      FailoverAction
    Target      string
    Reason      string
    Confidence  float64
    Rollback    *FallbackPlan
}

type FailoverAction string

const (
    ActionSwitch       FailoverAction = "switch"
    ActionGracefulSwitch FailoverAction = "graceful_switch"
    ActionRollback     FailoverAction = "rollback"
    ActionScaleUp      FailoverAction = "scale_up"
    ActionNoAction     FailoverAction = "no_action"
)
```

**1.9 连接型抗攻击防护**

```go
// 连接限制配置
type ConnectionLimitConfig struct {
    // 全局限制
    GlobalMaxConnections    int
    GlobalMaxConnectionRate int // 每秒最大连接建立速率
    
    // 每客户端限制
    PerClientMaxConnections int
    PerClientMaxRate       int
    
    // 慢连接防护
    SlowConnectionThreshold time.Duration // 连接建立超时
    SlowReadThreshold       time.Duration // 读取超时
    SlowWriteThreshold      time.Duration // 写入超时
    
    // Header 限制
    MaxHeaderSize    int64
    MaxHeadersCount  int
    
    // 请求体限制
    MaxRequestBodySize int64
}

// 连接保护引擎
type ConnectionProtectionEngine struct {
    config          *ConnectionLimitConfig
    globalLimiter   *RateLimiter
    clientLimiters  *sync.Map // map[string]*RateLimiter
    slowConnDetector *SlowConnectionDetector
    resourceMonitor  *ResourceMonitor
}

// 慢连接检测
type SlowConnectionDetector struct {
    thresholds map[time.Duration]int
    tracker    *ConnectionTracker
}

func (d *SlowConnectionDetector) Detect(conn *Connection) bool {
    elapsed := time.Since(conn.EstablishedAt)
    bytesRead := conn.BytesRead.Load()
    
    // 计算读取速率
    rate := float64(bytesRead) / elapsed.Seconds()
    
    // 检测慢速攻击
    if rate < d.thresholds[elapsed] {
        return true
    }
    
    return false
}
```

#### 4.3.4 产出物清单

| 目录/文件 | 描述 | 关键功能 |
|-----------|------|---------|
| `pkg/config/` | 配置管理体系 | 多源加载、热更新、版本管理 |
| `pkg/config/loader.go` | 配置加载器 | 支持文件、环境变量、动态配置中心 |
| `pkg/config/watcher.go` | 配置监听器 | 实时监听配置变更、触发热更新 |
| `pkg/tunnel/` | 隧道管理模块 | 隧道生命周期管理 |
| `pkg/tunnel/manager.go` | 隧道管理器 | 创建、销毁、状态管理 |
| `pkg/tunnel/state.go` | 隧道状态机 | 状态转换逻辑 |
| `pkg/tunnel/pool.go` | 隧道资源池 | 连接复用、资源管理 |
| `pkg/forward/` | 转发处理层 | 协议转发、TLS 终止 |
| `pkg/forward/tls.go` | TLS 处理器 | TLS 1.3、证书管理 |
| `pkg/forward/connpool.go` | 连接池 | HTTP/1.1、HTTP/2 连接复用 |
| `pkg/forward/lb/` | 负载均衡 | 多种负载均衡策略 |
| `pkg/forward/lb/roundrobin.go` | 轮询策略 | 基础轮询 |
| `pkg/forward/lb/weighted.go` | 加权策略 | 加权轮询、加权最少连接 |
| `pkg/forward/lb/hash.go` | 哈希策略 | IP Hash、一致性哈希 |
| `pkg/health/` | 健康检查模块 | 多层健康检测 |
| `pkg/health/checker.go` | 健康检查器 | TCP、HTTP、TLS、应用层检查 |
| `pkg/health/store.go` | 健康状态存储 | 状态持久化、查询 |
| `pkg/failover/` | 故障转移模块 | 自动故障切换 |
| `pkg/failover/controller.go` | 故障转移控制器 | 决策引擎、状态管理 |
| `pkg/failover/decision.go` | 故障决策树 | 智能故障判断 |
| `pkg/protection/` | 连接保护模块 | 连接型抗攻击 |
| `pkg/protection/limiter.go` | 连接限流器 | 全局、客户端级别限流 |
| `pkg/protection/slowconn.go` | 慢连接检测器 | Slowloris 防护 |
| `cmd/gost/` | gost v3 集成 | gost 代理集成与定制 |
| `cmd/gost/main.go` | 主程序 | 程序入口 |
| `cmd/gost/server.go` | 服务器实现 | 监听、转发逻辑 |
| `internal/metrics/` | 指标采集 | Prometheus 指标 |
| `tests/integration/` | 集成测试 | 端到端测试 |
| `tests/benchmark/` | 性能测试 | 基准测试 |

#### 4.3.5 性能指标要求

| 指标类型 | 指标名称 | 目标值 | 测量方法 |
|---------|---------|--------|---------|
| **延迟** | 端到端转发延迟增量 | P95 < 10ms | 对比直连源站 |
| **延迟** | TLS 握手延迟 | P95 < 50ms | TLS 1.3 + Session Cache |
| **吞吐** | 单节点吞吐能力 | > 1Gbps | 压测工具验证 |
| **吞吐** | 并发连接数 | > 100,000 | 长连接压测 |
| **可用性** | 故障切换时间 | < 5s | 模拟节点故障 |
| **可用性** | 配置热更新延迟 | < 100ms | 配置变更验证 |
| **稳定性** | 内存使用 | < 8GB (8C服务器) | 7x24 监控 |
| **稳定性** | CPU 使用率 | < 70% (正常负载) | 持续监控 |
| **可靠性** | 错误率 | < 0.1% | 错误日志统计 |
| **可靠性** | 连接成功率 | > 99.9% | 连接建立监控 |

#### 4.3.6 验收标准

**功能性验收：**
- [ ] Edge 节点支持 HTTPS 终止（TLS 1.3），获取完整 HTTP 可见性
- [ ] 隧道管理器支持创建、销毁、查询、热更新、批量操作
- [ ] 完整支持 HTTP/1.1、HTTP/2、WebSocket、SSE 协议
- [ ] 连接型抗攻击策略生效：慢连接、连接洪泛不导致 Edge 资源耗尽
- [ ] 故障转移时间 < 5s，切换过程对客户端透明
- [ ] 源站完全隐藏，无法从公网直接访问

**性能验收：**
- [ ] 单节点吞吐 > 1Gbps（8C16G 配置）
- [ ] 并发连接数 > 100,000（长连接场景）
- [ ] 端到端转发延迟增量 P95 < 10ms
- [ ] TLS 握手延迟 P95 < 50ms（含 Session Cache）
- [ ] 内存使用 < 8GB（7x24 小时稳定性测试）
- [ ] CPU 使用率 < 70%（正常负载）

**质量验收：**
- [ ] 单元测试覆盖率 > 75%
- [ ] 核心模块集成测试覆盖率 > 80%
- [ ] 性能基准测试建立并持续跟踪
- [ ] 混沌工程测试：节点故障、网络分区、资源耗尽

**可观测性验收：**
- [ ] Prometheus 指标采集完整：QPS、延迟、错误率、连接数、资源使用
- [ ] 结构化日志：请求日志、错误日志、审计日志
- [ ] 分布式追踪：TraceID 全链路传递
- [ ] 健康检查接口：/healthz、/readyz、/livez

**稳定性验收：**
- [ ] 7x24 小时压力测试通过
- [ ] 系统可用性 > 99.9%
- [ ] 配置热更新成功率 100%
- [ ] 故障自动恢复成功率 > 99%

#### 4.3.7 测试策略

**单元测试：**
- 每个模块独立测试，Mock 外部依赖
- 覆盖率目标 > 75%，核心模块 > 85%
- 使用 table-driven tests 进行场景覆盖
- 基准测试跟踪性能回归

**集成测试：**
- 端到端测试：客户端 → Edge → 源站
- 协议兼容性测试：HTTP/1.1、H2、WS、SSE
- 故障场景测试：节点故障、网络分区、资源耗尽
- 性能测试：吞吐、延迟、并发

**压力测试：**
- 使用 wrk、vegeta 等工具进行压力测试
- 模拟正常流量：1K-10K QPS
- 模拟攻击流量：连接洪泛、慢连接、超大请求
- 资源边界测试：内存、CPU、文件描述符

**混沌工程：**
- 节点故障：随机 kill 进程、断网
- 网络分区：延迟、丢包、抖动
- 资源耗尽：OOM、CPU 100%、磁盘满
- 依赖故障：DNS 失败、连接超时

#### 4.3.8 部署与运维

**部署方案：**
```yaml
# Docker 部署
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gocdn-edge
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: edge
        image: gocdn/edge:v1.0
        resources:
          requests:
            cpu: 4000m
            memory: 8Gi
          limits:
            cpu: 8000m
            memory: 16Gi
        ports:
        - containerPort: 443
          protocol: TCP
        env:
        - name: GOCDN_CONFIG
          value: "/config/config.yaml"
        volumeMounts:
        - name: config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: gocdn-config
```

**监控指标：**
```go
// Prometheus 指标
var (
    RequestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "gocdn_requests_total",
            Help: "Total number of requests",
        },
        []string{"method", "path", "status"},
    )
    
    RequestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "gocdn_request_duration_seconds",
            Help:    "Request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "path"},
    )
    
    ActiveConnections = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "gocdn_active_connections",
            Help: "Number of active connections",
        },
    )
    
    TunnelHealthScore = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "gocdn_tunnel_health_score",
            Help: "Tunnel health score (0-100)",
        },
        []string{"tunnel_id"},
    )
)
```

**告警规则：**
```yaml
groups:
- name: gocdn-alerts
  rules:
  - alert: HighErrorRate
    expr: rate(gocdn_requests_total{status=~"5.."}[5m]) > 0.01
    for: 2m
    annotations:
      summary: "High error rate detected"
  
  - alert: SlowResponseTime
    expr: histogram_quantile(0.95, gocdn_request_duration_seconds) > 1
    for: 5m
    annotations:
      summary: "P95 response time too high"
  
  - alert: TunnelUnhealthy
    expr: gocdn_tunnel_health_score < 50
    for: 1m
    annotations:
      summary: "Tunnel health score low"
  
  - alert: HighCPUUsage
    expr: rate(process_cpu_seconds_total[5m]) > 0.8
    for: 5m
    annotations:
      summary: "CPU usage high"
```

---

### 4.4 M2: 确定性防护落地（2-3 周）

> **目标：** 确定性防护先落地——连接数限制、速率限制、分区限流、基础行为打分。把误伤控制在可接受范围（<1%）。

**任务清单：**

| 序号 | 任务 | 描述 | 工期 | 依赖 |
|------|------|------|------|------|
| 2.1 | 基础限流器 | 连接数/IP 限制、速率限制 | 3天 | M1 |
| 2.2 | 行为分析器 | UA/Referer/频率分析 | 4天 | - |
| 2.3 | 规则引擎 | 黑白名单、路径规则 | 3天 | - |
| 2.4 | 分区限流 | 按路径/租户限流 | 3天 | 2.1 |
| 2.5 | 挑战验证（Web） | JS Challenge（限白名单路径） | 3天 | - |
| 2.6 | 清洗节点框架 | Sinkhole 处置 +（可选）Scrubbing 回注对接 | 3天 | - |
| 2.7 | 基础评分系统 | 多维度行为评分 | 2天 | 2.2 |

> **注意：** ML 异常检测作为 v2/v3 增强项，不在 M2 关键路径上。

**清洗策略（规则引擎）：**

```yaml
cleaning_rules:
  # 速率限制（通用）
  - name: rate_limit
    match:
      path_regex: ".*"
    conditions:
      - threshold: 1000  # 每秒请求数
      - window: 1s
    action: rate_limit
    limit_mode: per_ip

  # 连接数限制
  - name: connection_limit
    match:
      path_regex: ".*"
    conditions:
      - max_connections: 100
    action: block

  # Web 页面 JS 挑战（仅限白名单路径）
  - name: web_js_challenge
    match:
      path_regex: "\\.(html?|htm|css|js|png|jpg)$"
    conditions:
      - suspicious_score: > 60
    action: challenge
    challenge_type: js

  # API 禁用挑战（仅限流）
  - name: api_rate_limit
    match:
      path_regex: "/api/.*"
    conditions:
      - threshold: 100
      - window: 1s
    action: rate_limit
    # 禁止 challenge_type: js/captcha

  # 暴力破解防护
  - name: brute_force
    match:
      path_regex: "(/api)?/login"
    conditions:
      - threshold: 10
      - window: 60s
    action: block
    duration: 3600s

  # 对接上游清洗中心（Scrubbing 模式示例，需 M0 数据面已落地）
  - name: steer_to_scrubbing
    match:
      path_regex: ".*"
    conditions:
      - bandwidth_spike: true
      - pps_spike: true
    action: steer_to_scrubbing
    # 说明：该动作属于“控制面牵引”，不建议在应用层闭环承诺 10Gbps
```

**验收标准（M2）：**
- [ ] 支持 5+ 种攻击类型检测（基于规则）
- [ ] 基础防护检测准确率 > 90%
- [ ] 误杀率 < 1%
- [ ] JS Challenge 仅对 Web 路径生效，API 路径禁用
- [ ] 清洗吞吐达到接入带宽上限（1-2Gbps，口径见 8.4）
- [ ] Scrubbing 模式（如启用）可回注放行，业务侧可用性不劣化
- [ ] 支持动态规则热更新

---

### 4.5 M3: 可观测性 + 增强项（2 周）

> **目标：** 完整的可观测性 + ML 探索 + 请求合并（仅幂等 GET）。

**任务清单：**

| 序号 | 任务 | 描述 | 工期 | 依赖 |
|------|------|------|------|------|
| 3.1 | 指标采集 | Prometheus 指标 | 2天 | - |
| 3.2 | 日志系统 | 结构化日志 | 2天 | - |
| 3.3 | Vue3 面板 | 监控 Dashboard | 3天 | 3.1 |
| 3.4 | 告警系统 | 阈值告警 | 2天 | 3.1 |
| 3.5 | API 网关 | 管理 API | 2天 | - |
| 3.6 | 请求合并（探索） | 幂等 GET 请求合并 | 3天 | M1 |

**请求合并策略（探索性）：**

```yaml
request_collapse:
  enabled: false  # 默认禁用，需业务确认
  
  rules:
    # 仅对幂等 GET 开启
    - match:
        method: "GET"
        path_regex: "/api/public/.*"
      conditions:
        - require:
            - idempotent: true
            - no_auth_headers: true  # 无 Authorization 等强身份 Header
      action: enable_collapse
      collapse_window: 100ms  # 合并窗口
      max_collapse_count: 10  # 最大合并数
      
  # 禁止合并的场景（自动排除）
  disabled_patterns:
    - "/api/user/*"        # 个性化请求
    - "/api/*/order/*"     # 订单相关
    - "/api/*/payment/*"   # 支付相关
    - "POST"
    - "PUT"
    - "DELETE"
```

**验收标准（M3）：**
- [ ] 实时流量监控
- [ ] 攻击事件告警
- [ ] 7 天数据保留
- [ ] API 接口完整（与 `docs/API.md` 对齐）
- [ ] 请求合并功能可用（仅限幂等 GET）
- [ ] Vue3 监控面板完整

---

## 5. 时间规划

### 5.1 甘特图

```
周次    |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |
--------|-----|-----|-----|-----|-----|-----|-----|-----|
M0      | ███ | ███ |     |     |     |     |     |     |
M1      |     |     | ███ | ███ | ███ |     |     |     |
M2      |     |     |     |     | ███ | ███ | ███ |     |
M3      |     |     |     |     |     |     | ███ | ███ |
--------|-----|-----|-----|-----|-----|-----|-----|-----|
里程碑   |     |  M1 |     |     |  M2 |     |  M3 |     |
```

### 5.2 里程碑时间线

| 里程碑 | 时间 | 交付物 | 状态 |
|--------|------|--------|------|
| M0: 数据面确认 | 第 1-2 周 | 架构决策 + 配置 | 待开始 |
| M1: 稳定转发 | 第 3-5 周 | TLS 终止 + 隧道 + 故障切换 | 待开始 |
| M2: 防护落地 | 第 5-7 周 | 规则引擎 + 限流 + 清洗 | 待开始 |
| M3: 可观测性 | 第 7-8 周 | 监控面板 + API + 请求合并 | 待开始 |

---

## 6. 资源需求

### 6.1 人力资源

| 角色 | 人数 | 职责 |
|------|------|------|
| 项目负责人 | 1 | 整体规划、进度管理 |
| 后端开发 | 2-3 | 核心功能开发 |
| 前端开发 | 1 | Vue3 监控面板 |
| 运维工程师 | 0.5 | 部署、监控 |

> **ML 工程师：** v1 阶段暂不需要专职 ML 工程师，ML 功能作为 v2/v3 增强项引入。

### 6.2 服务器资源

**开发测试环境：**

| 类型 | 数量 | 配置 |
|------|------|------|
| 开发机 | 4 | 4C8G |
| 测试服务器 | 2 | 8C16G |

**生产环境：**

| 类型 | 数量 | 配置 | 备注 |
|------|------|------|------|
| Edge 节点 | 3+ | 8C16G | 核心流量处理，需 BGP/Anycast |
| 清洗节点 | 2 | 16C32G | 大流量清洗 |
| 数据库 | 2 | 4C8G | Redis + MongoDB |
| 监控服务器 | 1 | 4C8G | Vue3 + Prometheus + Grafana |

> **10Gbps 清洗吞吐说明：** 若需达到 10Gbps 清洗能力，需配合：
> - 上游高防/运营商清洗（BGP 牵引）
> - GRE/IPIP 等引流方案
> - 或在网络边界部署专业清洗设备
> 单靠应用层无法支撑 10Gbps 带宽型 DDoS。

> **高防对接前置（M0 必须确认）：**
> - 牵引 IP/网段（公告前缀、黑洞/牵引策略、回切策略）
> - 清洗中心对接方式（云高防/运营商/自建清洗 POP）
> - 回注链路参数（GRE/IPIP 对端、MTU、路由、可观测性与故障止损）

### 6.3 软件依赖

| 软件 | 版本 | 用途 | 备注 |
|------|------|------|------|
| Go | 1.21+ | 开发语言 | |
| **gost** | **v3.x** | 代理隧道 | 与仓库 `cmd/gost/*` 对齐 |
| MongoDB | 6.0+ | 数据存储 | |
| Redis | 7.0+ | 缓存、会话 | |
| Prometheus | 2.45+ | 指标采集 | |
| Grafana | 10.0+ | 可视化 | |

> **版本对齐：** 本系统使用 gost **v3.x**（与仓库 `cmd/gost/*` 保持一致），而非 gost 2.11+。

---

## 7. 风险与缓解

### 7.1 技术风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| TLS 终止性能开销 | 延迟增加 | 中 | 证书预热、连接复用、硬件加速 |
| 挑战误伤 API 流量 | API 不可用 | 高 | 严格路径白名单，默认禁用 |
| 请求合并导致数据错乱 | 业务异常 | 中 | 仅限幂等 GET，强制白名单 |
| 10Gbps 清洗无法达成 | 防护失效 | 高 | 明确 10Gbps 需上游引流，非应用层独力承担 |
| ML 指标无法达成 | 延期 | 中 | ML 作为 v2 目标，v1 基于规则 |
| 牵引/回切误触发 | 全站波动、可用性下降 | 中 | 触发信号多维度交叉验证 + 抖动保护 + 人工一键止损 |
| 回注 MTU/分片问题 | 丢包、长尾延迟 | 中 | M0 明确 MTU 策略 + 回注链路压测 + 端到端抓包验证 |
| Anycast/BGP 回程不对称 | 会话异常、状态丢失 | 中 | 会话无状态化优先 + 粘性策略兜底 + 必要时走专线/区域收敛 |
| L4 连接型攻击压垮 Edge | 连接耗尽、无法进入 L7 | 高 | 连接建立速率/并发连接上限 + 超时策略 + 上游高防兜底 |

### 7.2 进度风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| M0 数据面决策延迟 | 后续开发受阻 | 提前组织架构评审，预留缓冲 |
| 需求变更 | 进度延期 | 充分沟通、MVP 优先、敏捷迭代 |
| 技术难点 | 进度延期 | 提前预研、专家咨询、适当简化 |

---

## 8. 验收标准

### 8.0 M0 验收标准（高防清洗闭环）

- [ ] 高防牵引方式（DNS/Anycast/BGP）已选型并完成连通性验证
- [ ] 清洗中心 →（GRE/IPIP/专线）→ Edge/Origin 的回注路径已跑通（含 MTU/丢包/抖动测试）
- [ ] 源站保护策略已落地：源站仅接受来自 Edge/回注网段的入站访问
- [ ] 牵引触发与回切策略已定义，并至少完成 1 次演练（含抖动保护与回切窗口）

### 8.1 M1 验收标准

- [ ] Edge 支持 HTTPS 终止（获取 HTTP 可见性）
- [ ] 隧道管理器支持创建/销毁/查询/热更新
- [ ] 支持 HTTP/1.1、H2、WebSocket、SSE
- [ ] 连接型抗压策略生效（慢连接/连接洪泛不导致 Edge 资源耗尽）
- [ ] 故障切换时间 < 5s
- [ ] 单元测试覆盖率 > 70%
- [ ] 系统可用性 > 99.9%

### 8.2 M2 验收标准

- [ ] 支持 5+ 种攻击类型检测（基于规则）
- [ ] 基础防护检测准确率 > 90%
- [ ] 误杀率 < 1%
- [ ] JS Challenge 仅对 Web 路径生效，API 路径禁用
- [ ] 清洗吞吐达到接入带宽上限（1-2Gbps，口径见 8.4）
- [ ] Scrubbing 模式（如启用）可回注放行，业务侧可用性不劣化
- [ ] 支持动态规则热更新

### 8.3 M3 验收标准

- [ ] 实时流量监控
- [ ] 攻击事件告警
- [ ] 7 天数据保留
- [ ] API 接口完整（JWT 中间件已实现）
- [ ] 请求合并功能可用（仅限幂等 GET）
- [ ] Vue3 监控面板完整

### 8.4 指标口径（必须固化，否则无法验收）

> **原则：** 指标必须给出“样本来源 + 统计口径 + 统计窗口”，否则“准确率/误杀率”会变成主观争论。

**基础防护检测准确率（M2）：**
- 定义：在“带标签数据集”上，对请求的二分类（正常/攻击）结果统计 `(TP + TN) / (TP + TN + FP + FN)`
- 数据集来源：`回放真实流量样本（脱敏） + 合成攻击流量 + 压测流量` 的混合集合
- 统计口径：以“请求”为单位；同时必须补充“按关键路径分组”（登录/下单/支付/开放API/静态页）

**误杀率（M2）：**
- 定义：在“正常流量样本”上，被拦截/被挑战/被限流到不可用的比例 `FP / NormalTotal`
- 口径要求：分别给出“整体误杀率”与“关键业务路径误杀率”（关键路径阈值可更严格）

**清洗吞吐（M2）：**
- 定义：Edge 在开启防护规则后可稳定处理的入口吞吐（Gbps 或 PPS），以 `P95` 或稳定区间均值给出
- 约束：v1 目标为 1-2Gbps（接入带宽上限），带宽型 DDoS 依赖上游清洗中心

**延迟增量（M1）：**
- 定义：同一测试场景下，“直连源站”与“经 Edge 转发”的 `P95` 延迟差值
- 要求：必须区分长连接（WS/SSE）与短连接（普通 HTTP 请求）的统计口径

---

## 9. 后续规划

### 9.1 v2.0 规划

| 功能 | 描述 | 优先级 | 依赖 |
|------|------|--------|------|
| **ML 异常检测** | 99%+ 准确率，<0.1% 误杀 | **高** | 真实流量数据闭环 |
| **WAF 增强** | SQLi/XSS 等 L7 规则 | 中 | TLS 终止已完成 |
| **请求合并** | 幂等 GET 自动合并 | 中 | 业务协议约束 |
| **分布式部署** | 多区域 Edge 节点 | 中 | - |

### 9.2 v3.0 规划

| 功能 | 描述 | 备注 |
|------|------|------|
| 10Gbps 清洗 | 需上游高防引流 | 网络层协同 |
| 智能 DNS | 基于延迟的智能解析 | 需 DNS 能力 |
| 自动化运维 | 一键扩缩容 | 需 K8s 集成 |

### 9.3 长期目标

- 打造完整的动态内容 CDN 解决方案
- 支持多云部署
- 商业化运营

---

## 10. 附录

### 10.1 与仓库现状对齐

| 项目 | 计划文档 | 仓库现状 | 对齐结果 |
|------|----------|----------|----------|
| 前端框架 | ~~React~~ | Vue3 | ✅ 已改为 Vue3 |
| gost 版本 | ~~2.11+~~ | v3.x | ✅ 已改为 v3.x |
| 管理后台 | - | `web-admin/` | ✅ 已对齐 |
| API 文档 | - | `docs/API.md` | ✅ 验收时需对齐 |

### 10.2 当前占位/简化实现

| 文件 | 状态 | 需完善 |
|------|------|--------|
| `pkg/security/advanced_cc_protection.go` | 占位 | ML 功能需 v2 实现 |
| `pkg/security/shield.go` | 基础实现 | 需补充挑战验证路径过滤 |
| `docs/API.md:59` | JWT 中间件为空实现 | M3 需补齐 |

### 10.3 参考文档

- [gost 官方文档](https://gost.run/)
- [gost v3 发布说明](https://github.com/ginuerzh/gost/releases)
- [Vue3 文档](https://vuejs.org/)
- [Grafana 文档](https://grafana.com/docs/)

### 10.4 术语表

| 术语 | 说明 |
|------|------|
| Edge Node | 边缘节点 |
| Cleaning Node | 清洗节点 |
| gost | Go 语言实现的代理工具（v3.x） |
| 5秒盾 | 5秒内限制请求次数的防护（已改为通用限流） |
| CC 攻击 | Challenge Collapsar，应用层请求洪泛/资源耗尽攻击（区别于带宽型 DDoS） |
| TLS 终止 | Edge 节点解密 HTTPS，获取明文 HTTP |
| 幂等 GET | 多次调用结果相同的 GET 请求 |
| L4/L7 | 四层（传输层）/ 七层（应用层） |

---

## 11. 验证与测试

### 11.1 关键验证项

| 验证项目 | 验证方法 | 所属里程碑 | 优先级 |
|----------|----------|------------|--------|
| gost v3 性能测试 | 压测 TLS 终止、隧道转发延迟 | M1 | 高 |
| 高防牵引/回切演练 | 触发牵引→验证可访问→回切→验证恢复（含抖动保护） | M0 | 高 |
| 回注连通性与 MTU | GRE/IPIP 建链 + MTU/丢包/抖动测试，必要时抓包验证 | M0 | 高 |
| 规则引擎误杀率测试 | 模拟正常流量 + 攻击流量，统计误杀率 | M2 | 高 |
| 故障切换演练 | 模拟节点宕机，验证切换时间 < 5s | M1 | 高 |
| 路径白名单验证 | 确保 API 路径不会触发 JS Challenge | M2 | 高 |
| 清洗策略正确性 | Sinkhole 丢弃/限速生效；Scrubbing 模式下可回注放行且不影响正常业务 | M2 | 高 |
| L4 连接型抗压 | 模拟 SYN/连接洪泛、慢连接（slowloris/慢POST），验证 Edge 不被连接耗尽 | M1 | 高 |
| 请求合并安全性 | 验证幂等 GET 合并无副作用 | M3 | 中 |
| 高并发承载测试 | 10万+ 并发连接稳定性 | M1 | 中 |
| 监控指标完整性 | 验证 QPS、延迟、攻击事件数等指标采集 | M3 | 中 |

### 11.2 M0 架构评审

> **建议：** M0 结束时组织一次架构评审，邀请安全、运维、业务方参与，确保数据面形态决策得到各方认可。

**评审议程：**
1. TLS 终止策略确认
2. 协议支持矩阵评审
3. 挑战路径白名单讨论
4. gost 版本兼容性验证
5. 高防牵引/回注闭环确认（含 MTU/回切/止损）
6. 源站保护策略确认（不可绕过直连）
7. 风险识别与缓解措施确认

---

## 12. 技术深化设计

> **说明：** 本章节针对关键技术点进行深化设计，确保系统稳定性与防护效果。

### 12.1 TLS 终止性能与证书管理

**性能优化策略：**

| 优化项 | 策略 | 预期效果 |
|--------|------|----------|
| TLS 1.3 启用 | 默认启用 TLS 1.3，减少握手延迟 | 握手时间减少 40% |
| 硬件加速 | 利用 CPU AES-NI 指令集 | 加解密性能提升 2-3 倍 |
| 证书预热 | 启动时预加载证书到内存 | 首请求延迟降低 |
| 连接复用 | 启用 HTTP/2 Multiplexing | 减少 TLS 握手开销 |
| Session Cache | 启用 TLS Session 缓存 | 重复连接复用 |

**证书管理方案：**

```yaml
cert_management:
  # 证书来源
  sources:
    - type: "file"           # 本地文件
      path: "/certs/*.pem"
    - type: "k8s_secret"     # Kubernetes Secret
      namespace: "gocdn"
    - type: "lets_encrypt"   # Let's Encrypt 自动签发
      enabled: true
      
  # 自动续期
  auto_renewal:
    enabled: true
    before_expire: "30d"     # 提前 30 天续期
    
  # 证书分发
  distribution:
    method: "secret_update"  # Secret 更新触发热加载
    reload_signal: "SIGHUP"
```

### 12.2 路径匹配引擎设计

**匹配能力：**

| 匹配类型 | 语法示例 | 适用场景 |
|----------|----------|----------|
| 前缀匹配 | `/api/*` | API 路径批量匹配 |
| 精确匹配 | `/api/user/info` | 特定端点 |
| 正则匹配 | `/api/v\\d+/.*` | 版本化 API |
| 通配符 | `/*.html` | 静态页面 |
| 组合条件 | `method:GET + path:/api/public/*` | 方法 + 路径 |

**匹配优先级：**

1. 精确匹配（最高优先级）
2. 前缀匹配
3. 正则匹配
4. 通配符匹配（最低优先级）

**验证工具：**

```bash
# 规则匹配测试工具
$ ./rule-tester --rule "path_regex:/api/.*" --path "/api/users/123"
# 输出: MATCH - rule_id: api_rate_limit

$ ./rule-tester --rule "path_regex:/api/.*" --path "/static/index.html"
# 输出: NO MATCH
```

### 12.3 请求合并安全性设计

**安全约束：**

```yaml
request_collapse:
  enabled: false  # 默认禁用
  
  # 必须满足的条件
  requirements:
    - method: "GET"                    # 仅 GET
    - idempotent: true                  # 幂等性确认
    - no_auth_headers: true             # 无 Authorization
    - no_session_cookies: true          # 无会话 Cookie
    
  # 额外的安全检查
  security_checks:
    - check_cache_control: true         # 检查 Cache-Control 头
    - check_etag: true                  # 检查 ETag
    - exclude_user_specific: true       # 排除用户个性化参数
    
  # TraceID 串联
  trace:
    enabled: true
    trace_id_prefix: "collapse_"
    log_merged_requests: true
```

**业务方声明：**

```yaml
# 业务方需明确声明可合并的接口
collapse_whitelist:
  - path: "/api/public/config"
    reason: "全局配置接口，无个性化数据"
    approved_by: "backend-team-lead"
  - path: "/api/public/news/list"
    reason: "新闻列表，5分钟缓存可接受"
    approved_by: "product-manager"
```

### 12.4 清洗节点与回注数据面设计（Sinkhole / Scrubbing）

> **说明：** 本项目的“清洗”包含两种模式，必须在 M0 固化数据面与验收口径：  
> - **Sinkhole（丢弃隔离）**：命中即丢弃/限速，强调“保命与隔离”，不承诺放行回源  
> - **Scrubbing（清洗回注）**：在隔离区过滤后，把“可疑但可能为真”的流量**回注放行**到 Edge/Origin

#### 12.4.1 Sinkhole（丢弃隔离）网络形态

```
Client -> Edge(分类命中攻击) -> Cleaning Zone(Sinkhole) -> Drop
```

**隔离原则：**
- Sinkhole 节点部署在独立 VLAN/子网，**默认无出站权限**
- 节点保持**无状态、可丢弃**，不持久化业务数据
- 支持**流量镜像 + 分析**（离线取样），用于规则优化与攻击样本沉淀

#### 12.4.2 Scrubbing（清洗回注）网络形态

```
Client -> Scrubbing Center(上游清洗/本地清洗区)
              │
              ├─ 过滤/限速/丢弃恶意
              │
              └─ GRE/IPIP 回注 -> Edge 或 Origin 私网入口 -> Origin 服务
```

**回注原则：**
- Scrubbing 区允许出站，但**仅允许到回注端点**（GRE/IPIP 对端 / 专线网关）
- 回注链路必须在 M0 固化：端点、路由、MTU、丢包/抖动基线
- 若业务需要会话粘性，优先在 Edge 做粘性；Scrubbing 区尽量保持无状态

#### 12.4.3 源站访问控制（必须落地）

无论 Sinkhole 还是 Scrubbing，源站都必须满足“不可绕过直连”：
- 源站安全组/ACL：仅允许来自 Edge 网段与回注网段的入站
- 或源站仅在私网/VPC 中可达，Edge 作为唯一公网入口

> **验收建议：** 通过公网直接访问源站 IP/域名应失败；通过 Edge/回注链路访问应成功。

### 12.5 高可用与故障切换设计

**多活隧道架构：**

```go
type TunnelCluster struct {
    Tunnels     []*Tunnel      `json:"tunnels"`
    HealthCheck HealthChecker  `json:"-"`
    LBStrategy  LBStrategy     `json:"lb_strategy"`
    
    // 多活配置
    ActiveMode  string         `json:"active_mode"`  // "active-active" | "active-standby"
    Weight      map[string]int `json:"weight"`       // 隧道权重
}
```

**故障切换策略：**

| 场景 | 处理策略 |
|------|----------|
| 单隧道故障 | 自动切换到其他健康隧道（< 1s） |
| 多数隧道故障 | 触发告警，启动降级模式 |
| 整个 Edge 故障 | DNS 自动切换到其他节点 |
| 网络分区 | 基于权重重新分配流量 |

**会话粘性保持：**

```yaml
session_sticky:
  enabled: true
  methods:
    - cookie: "GOCDN_STICKY"    # 基于 Cookie
    - ip_hash: true              # 基于 IP
    - header: "X-Forwarded-For" # 基于 Header
  
  sticky_timeout: "30m"         # 粘性超时时间
```

**混沌工程测试用例：**

```yaml
chaos_tests:
  - name: "single_tunnel_failure"
    action: "kill_tunnel"
    expected_switch_time: "< 5s"
    
  - name: "network_partition"
    action: "block_port"
    expected_recovery: "< 10s"
    
  - name: "certificate_expiry"
    action: "expire_cert"
    expected_behavior: "auto_rotate"
```

### 12.6 ML 数据闭环准备

**v1 阶段埋点采集：**

```go
// 特征采集接口
type FeatureCollector interface {
    // 基础特征
    RequestFeatures(req *http.Request) map[string]float64
    
    // 行为序列
    BehavioralSequence(sessionID string) []Action
    
    // 攻击标签
    AttackLabel(req *http.Request, verdict string)
}

// 采集指标
var MLFeatures = []string{
    "request_rate",           // 请求频率
    "ua_suspicious_score",    // UA 可疑度
    "path_entropy",           // 路径熵值
    "response_time_avg",      // 响应时间
    "error_rate",             // 错误率
    "session_duration",       // 会话时长
    "geo_anomaly_score",      // 地理异常
    "request_size_avg",       // 请求大小
    "header_variety",         // Header 多样性
}
```

**数据流程：**

```
请求 → 特征提取 → 存储(Redis/Mongo) → 离线训练 → 模型部署 → 在线推理
                                              ↑
                                              │
                                      人工标注/反馈
```

**v2 ML 架构草图：**

```
┌──────────────────────────────────────────────────────────────┐
│                    ML Pipeline                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  数据采集  │→│ 特征工程  │→│  模型训练  │→│  模型部署  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│       ↓              ↓              ↓              ↓        │
│  Redis/Mongo    Feature Store    MLflow       TensorServing │
│                                                              │
│  ←────────────── 反馈闭环 ───────────────→                  │
│       人工标注 / 自动标注 / 效果评估                         │
└──────────────────────────────────────────────────────────────┘
```

---

*文档版本: v1.5*
*最后更新: 2026-01-03*

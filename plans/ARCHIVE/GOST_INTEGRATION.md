# GoCDN + gost 深度集成设计方案

## 1. 功能裁剪清单

### 1.1 gost 核心模块分类

#### 必需模块 (Essential)
| 模块 | 功能 | CDN 用途 | 保留/改造 |
|------|------|----------|----------|
| `listener` | 连接监听 | 接收客户端连接 | **保留** |
| `handler` | 请求处理 | 核心转发逻辑 | **保留** |
| `connector` | 目标连接 | 连接上游服务器 | **保留** |
| `dialer` | 拨号器 | 建立上游连接 | **保留** |
| `common/bufpool` | 缓冲区池 | 高性能内存管理 | **保留** |
| `logger` | 日志接口 | 统一日志输出 | **改造** - 对接 CDN 日志 |
| `metadata` | 元数据 | 请求上下文传递 | **保留** |

#### 重要模块 (Important)
| 模块 | 功能 | CDN 用途 | 保留/改造 |
|------|------|----------|----------|
| `ingress` | 入口路由 | 多域名路由 | **保留** |
| `routing` | HTTP 路由 | 路径/主机匹配 | **改造** - 整合到 distribute |
| `selector` | 节点选择 | 负载均衡/故障转移 | **改造** - 复用现有实现 |
| `hop` | 跳板选择 | 多上游切换 | **改造** - 整合到 failover |
| `chain` | 链式代理 | 多跳转发 | **保留** - CDN 节点互联 |

#### 可选模块 (Optional)
| 模块 | 功能 | CDN 用途 | 决策 |
|------|------|----------|------|
| `auth` | 认证 | 客户端认证 | **可选** - 按需启用 |
| `bypass` | 旁路 | IP 白名单 | **可选** |
| `limiter` | 限流 | DoS 防护 | **改造** - 整合到安全模块 |
| `metrics` | 指标 | 监控数据 | **改造** - 对接 CDN 监控 |
| `observer` | 观察者 | 事件统计 | **改造** - 简化使用 |

#### 边缘特性 (Edge-Specific) - **可移除**
| 模块 | 功能 | 原因 |
|------|------|------|
| `recorder` | 数据录制 | 调试用途，增加体积 |
| `sd` | 服务发现 | CDN 使用固定配置 |
| `router` | 网络路由 | 复杂路由，CDN 不需要 |
| `hosts` | 主机映射 | 使用 DNS 替代 |
| `resolver` | DNS 解析 | 使用系统 DNS |

### 1.2 gost x 协议处理器

#### CDN 必需的协议
| 协议 | 路径 | 用途 | 决策 |
|------|------|------|------|
| HTTP | `handler/http/` | 基础 HTTP 代理 | **保留** |
| HTTPS | `handler/http/` + TLS | TLS 终止 | **保留** |
| Forward | `handler/forward/` | TCP/UDP 转发 | **保留** |

#### CDN 可选的协议
| 协议 | 用途 | 决策 |
|------|------|------|
| SOCKS5 | 客户端协议兼容 | **可选** |
| Shadowsocks | 兼容旧客户端 | **可选** |
| QUIC/HTTP3 | 新一代协议 | **保留** |
| DNS | DNS 代理 | **可选** |

#### CDN 不需要的协议
| 协议 | 原因 |
|------|------|
| SSH | 远程管理，非转发用途 |
| TUN/TAP | 网络层隧道 |
| Serial | 串口转发 |
| Relay | 中继协议 |

---

## 2. 插件化嵌入方案

### 2.1 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                      GoCDN 节点架构                              │
├─────────────────────────────────────────────────────────────────┤
│  请求入口层                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  HTTP    │  │  HTTPS   │  │  QUIC    │  │  Gateway │         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘         │
│       │             │             │             │                │
│       └─────────────┴──────┬──────┴─────────────┘                │
│                            │                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              gost 嵌入式运行时 (gost.Runtime)              │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐      │   │
│  │  │ Handler │  │ Listener │  │ Dialer  │  │ Connector│      │   │
│  │  │ Registry│  │ Registry │  │ Registry│  │ Registry │      │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              CDN 安全与流量处理层                          │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │   │
│  │  │ Traffic  │  │ Security │  │  Health  │  │  Failover │  │   │
│  │  │Distribute│  │  Shield  │  │  Checker │  │  Manager  │  │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              转发引擎 (pkg/forward)                        │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │   │
│  │  │ ConnPool │  │   LB     │  │ Forwarder│                 │   │
│  │  └──────────┘  └──────────┘  └──────────┘                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                            │                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              上游连接层                                     │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │   │
│  │  │  Origin  │  │  Master  │  │  Peer    │                 │   │
│  │  │  Server  │  │   Node   │  │   CDN    │                 │   │
│  │  └──────────┘  └──────────┘  └──────────┘                 │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件设计

#### 2.2.1 gost.Runtime - 嵌入式运行时

```go
package gostx

import (
    "context"
    "sync"

    "github.com/go-gost/core/handler"
    "github.com/go-gost/core/listener"
    "github.com/go-gost/core/logger"
    "github.com/go-gost/core/registry"
    "github.com/go-gost/x/handler/forward"
    "github.com/go-gost/x/handler/http"
)

// Runtime gost 嵌入式运行时
type Runtime struct {
    mu         sync.RWMutex
    handlers   map[string]handler.Handler
    listeners  map[string]listener.Listener
    dialers    map[string]dialer.Dialer
    connectors map[string]connector.Connector
    logger     logger.Logger
    options    RuntimeOptions
}

// RuntimeOptions 运行时选项
type RuntimeOptions struct {
    Logger        logger.Logger
    HandlerPrefix string // 默认: "cdn"
    AutoRegister  bool   // 是否自动注册默认处理器
}

// NewRuntime 创建运行时
func NewRuntime(opts ...RuntimeOption) *Runtime {
    r := &Runtime{
        handlers:   make(map[string]handler.Handler),
        listeners:  make(map[string]listener.Listener),
        dialers:    make(map[string]dialer.Dialer),
        connectors: make(map[string]connector.Connector),
        logger:     logger.Default(),
    }

    for _, opt := range opts {
        opt(r)
    }

    if r.options.AutoRegister {
        r.registerDefaults()
    }

    return r
}

// RegisterHandler 注册处理器
func (r *Runtime) RegisterHandler(name string, h handler.Handler) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.handlers[name] = h
}

// GetHandler 获取处理器
func (r *Runtime) GetHandler(name string) (handler.Handler, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    h, ok := r.handlers[name]
    return h, ok
}

// ServeHTTP 实现 http.Handler 接口
func (r *Runtime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // 从路由获取处理器
    h, ok := r.matchHandler(req)
    if !ok {
        http.Error(w, "No handler found", http.StatusNotFound)
        return
    }

    // 调用 gost handler
    ctx := context.WithValue(req.Context(), logger.LoggerKey, r.logger)
    if err := h.Handle(ctx, w, req); err != nil {
        r.logger.Errorf("handler error: %v", err)
    }
}

// registerDefaults 注册默认处理器
func (r *Runtime) registerDefaults() {
    // HTTP 处理器
    r.RegisterHandler("http", &http.Handler{
        Director: http.DefaultDirector,
    })

    // Forward 处理器 (TCP/UDP)
    r.RegisterHandler("forward", &forward.Handler{})
}
```

#### 2.2.2 Handler 接口适配器

```go
package gostx

import (
    "net/http"

    "github.com/go-gost/core/handler"
    "github.com/go-gost/core/metadata"
)

// Adapter handler 到 http.Handler 的适配器
type Adapter struct {
    h    handler.Handler
    md   metadata.Metadata
}

// NewAdapter 创建适配器
func NewAdapter(h handler.Handler) *Adapter {
    return &Adapter{h: h}
}

// Handle 实现 Handler 接口
func (a *Adapter) Handle(w http.ResponseWriter, req *http.Request) {
    ctx := req.Context()
    if a.md != nil {
        ctx = metadata.NewContext(ctx, a.md)
    }

    if err := a.h.Handle(ctx, w, req); err != nil {
        // 错误处理
    }
}
```

#### 2.2.3 连接管理器集成

```go
package gostx

import (
    "net"

    "github.com/go-gost/core/connector"
    "github.com/go-gost/core/dialer"
)

// ConnManager 连接管理器 - 桥接 gost 和 CDN 连接池
type ConnManager struct {
    pool     *forward.ConnPool // CDN 连接池
    selector *forward.LoadBalancer
}

// Dial 实现 dialer.Dialer 接口
func (cm *ConnManager) Dial(ctx context.Context, network, addr string, opts ...dialer.DialOption) (net.Conn, error) {
    return cm.pool.Get(ctx, network, addr)
}

// Connect 实现 connector.Connector 接口
func (cm *ConnManager) Connect(ctx context.Context, network, addr string, opts ...connector.ConnectOption) (net.Conn, error) {
    return cm.pool.Get(ctx, network, addr)
}
```

### 2.3 请求处理流水线

```
客户端请求 ──> 入口 (HTTP/HTTPS/QUIC)
                    │
                    ▼
            ┌─────────────────┐
            │  gost.Runtime   │  ◄── 路由匹配
            │  Handler.Registry│
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  HandlerAdapter │  ◄── 协议适配
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │ TrafficClassify │  ◄── 流量分类
            └────────┬────────┘
                     │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    ┌─────────┐ ┌─────────┐ ┌─────────┐
    │  Normal │ │Suspi-   │ │ Attack  │
    │         │ │ cious   │ │         │
    └────┬────┘ └────┬────┘ └────┬────┘
         │           │           │
         ▼           ▼           ▼
    ┌─────────────────────────────────┐
    │       Security Shield           │  ◄── WAF, Rate Limit
    └─────────────────────────────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  ConnManager    │  ◄── 连接池获取
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  LoadBalancer   │  ◄── 节点选择
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │   HealthCheck   │  ◄── 健康检查
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │   Failover      │  ◄── 故障转移
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  Origin Server  │  ──> 上游服务器
            └─────────────────┘
```

---

## 3. 渐进式迁移路线图

### 3.1 第一阶段: 引入期 (Week 1-2)

**目标**: 建立 gost 运行时调用关系，不改变原有代码结构

#### 任务清单
- [ ] 创建 `pkg/gostx/` 目录结构
- [ ] 实现 `gostx.Runtime` 基础框架
- [ ] 集成 gost handler registry 到 CDN
- [ ] 配置 gost listener 为可选入口
- [ ] 建立日志桥接 (gost logger → CDN logger)

#### 代码变更
```go
// pkg/gostx/runtime.go (新文件)
package gostx

type Runtime struct {
    // 空的运行时框架
}
```

#### 验证标准
- [ ] CDN 启动时 gost 运行时初始化成功
- [ ] 日志能够从 gost 模块输出到 CDN 日志系统
- [ ] 原有功能完全不受影响

### 3.2 第二阶段: 对接期 (Week 3-4)

**目标**: 对接 gost 日志、配置、监控子系统

#### 任务清单
- [ ] 实现 gost logger 接口适配器
- [ ] 统一配置加载 (gost config → CDN config)
- [ ] 集成 gost metrics 到 CDN Prometheus
- [ ] 将 gost observer 事件接入 CDN 事件系统
- [ ] 实现 gost connector/dialer 到 CDN connPool 的桥接

#### 代码变更
```go
// pkg/gostx/logger.go
type LoggerAdapter struct {
    cdnLogger *zap.Logger
}

func (l *LoggerAdapter) Debug(msg string, args ...any) {
    l.cdnLogger.Sugar().Debugf(msg, args...)
}

// pkg/gostx/metrics.go
type MetricsAdapter struct {
    registry *prometheus.Registry
}
```

#### 验证标准
- [ ] 所有 gost 日志使用 CDN 日志格式
- [ ] gost 内部指标可从 /metrics 端点获取
- [ ] 配置热重载生效于 gost 模块

### 3.3 第三阶段: 精简期 (Week 5-6)

**目标**: 移除未被引用的 gost 模块，优化体积

#### 任务清单
- [ ] 分析 gost 依赖关系，标记未使用的模块
- [ ] 移除 `recorder`, `sd`, `router`, `hosts`, `resolver`
- [ ] 简化 gost x 包导入 (只导入需要的协议)
- [ ] 使用 Go 条件编译减少最终二进制体积
- [ ] 优化 gost 初始化顺序 (懒加载)

#### 精简后的 go.mod 依赖
```go
require (
    // 只保留必需的模块
    "github.com/go-gost/core v0.3.3"  // 只用 core 接口
    "github.com/go-gost/x v0.8.1"     // 只用 handler, listener
)
```

#### 验证标准
- [ ] 二进制体积减少 30% 以上
- [ ] 启动时间降低 20% 以上
- [ ] 所有功能测试通过

### 3.4 里程碑检查点

| 阶段 | 时间 | 验收标准 | 风险点 |
|------|------|----------|--------|
| P1 引入期 | Week 1-2 | gost.Runtime 正常初始化，日志桥接成功 | 接口兼容性 |
| P2 对接期 | Week 3-4 | metrics 采集正常，配置热加载生效 | 性能开销 |
| P3 精简期 | Week 5-6 | 体积减少 30%，启动时间降低 20% | 功能缺失 |

---

## 4. 集成接口定义

### 4.1 Handler 接口

```go
// 由 gost 提供，CDN 实现
type Handler interface {
    Handle(ctx context.Context, w http.ResponseWriter, r *http.Request) error
    Init(md metadata.Metadata) error
}
```

### 4.2 Listener 接口

```go
// 由 gost 提供，CDN 实现
type Listener interface {
    Addr() net.Addr
    Accept() (net.Conn, error)
    Close() error
}
```

### 4.3 Logger 接口

```go
// 由 gost 提供，CDN 实现
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
    Fatal(msg string, args ...any)
}
```

---

## 5. 配置文件集成

### 5.1 gost 配置节

```yaml
# config/cdn.yml
gost:
  enabled: true
  runtime:
    handler_prefix: "cdn"
    auto_register: true
  handlers:
    - name: http
      enabled: true
    - name: forward
      enabled: true
  listeners:
    - name: tcp
      addr: ":8080"
      protocol: tcp
    - name: tls
      addr: ":8443"
      protocol: tls
  metrics:
    enabled: true
    path: "/metrics"
```

---

## 6. 监控与可观测性

### 6.1 集成指标

```go
// gost 模块指标
gost_handler_requests_total{handler="http",status="success"}
gost_handler_requests_total{handler="http",status="error"}
gost_conn_pool_connections_active{handler="forward"}
gost_conn_pool_connections_idle{handler="forward"}
gost_runtime_goroutines_total
```

### 6.2 健康检查端点

```go
// /health/gost 检查 gost 运行时健康状态
{
    "status": "healthy",
    "runtime": {
        "goroutines": 42,
        "handlers": {
            "http": "active",
            "forward": "active"
        }
    }
}
```

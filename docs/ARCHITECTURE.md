# AI CDN Tunnel - 技术架构文档

## 目录

- [1. 项目概述](#1-项目概述)
- [2. 系统架构](#2-系统架构)
- [3. 核心模块](#3-核心模块)
- [4. 通信协议](#4-通信协议)
- [5. 数据模型](#5-数据模型)
- [6. 安全架构](#6-安全架构)
- [7. 部署架构](#7-部署架构)
- [8. 监控告警](#8-监控告警)

---

## 1. 项目概述

### 1.1 项目简介

AI CDN Tunnel 是一个专为 AI 大语言模型（LLM）对话系统设计的高性能 CDN 隧道转发系统。基于 gost v3 框架构建，实现了 Master-Agent 架构来统一管理分布式 CDN 节点。

### 1.2 核心特性

| 特性 | 说明 |
|------|------|
| **高并发** | 支持 100,000+ 并发连接 |
| **低延迟** | P99 延迟 < 100ms |
| **零缓存** | 实时转发，无缓存层 |
| **多协议** | QUIC/WebSocket/TCP/TLS |
| **主控管理** | Master 统一管理 Agent |
| **配置中心** | 版本管理、热下发 |
| **监控告警** | Prometheus 集成 |
| **可视化** | Vue3 管理后台 |

### 1.3 性能指标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 并发连接数 | 100,000+ | 单节点 |
| QPS | 500,000+ | 全节点 |
| P99 延迟 | < 100ms | 端到端 |
| 可用性 | 99.9% | SLA 保证 |
| 内存使用 | < 8GB | 单节点 |

---

## 2. 系统架构

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Master 主控节点                               │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    控制平面 (Control Plane)                    │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │ Web API  │  │ gRPC服务 │  │ 配置中心 │  │ 监控中心 │       │  │
│  │  │ :8080    │  │ :50051   │  │ MongoDB  │  │ Prometheus│      │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │  │
│  │                                                               │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │ 节点管理 │  │ 告警中心 │  │ Redis缓存│  │ 任务队列 │       │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                           gRPC/HTTP2
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│ Agent 香港-1  │         │ Agent 香港-2  │         │ Agent 大陆-1  │
│  (边缘节点)    │         │  (边缘节点)    │         │  (核心节点)    │
├───────────────┤         ├───────────────┤         ├───────────────┤
│ ┌───────────┐ │         │ ┌───────────┐ │         │ ┌───────────┐ │
│ │  gost     │ │         │ │  gost     │ │         │ │  gost     │ │
│ │ :443/8080 │ │         │ │ :443/8080 │ │         │ │ :8443/8444│ │
│ └───────────┘ │         │ └───────────┘ │         │ └───────────┘ │
└───────────────┘         └───────────────┘         └───────────────┘
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                                    ▼
                          ┌─────────────────┐
                          │   LLM 源站服务   │
                          │     :8000       │
                          └─────────────────┘
```

### 2.2 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层 (Application)                    │
│                    Web Admin / API Client                    │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      控制平面 (Control Plane)                │
│  Master: API网关 / 配置管理 / 节点管理 / 监控采集            │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      代理平面 (Proxy Plane)                  │
│  Agent: 协议转换 / 流量转发 / 安全过滤 / 负载均衡            │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      数据平面 (Data Plane)                   │
│  gost: QUIC/WebSocket/TCP/TLS 隧道转发                      │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 节点类型

| 节点类型 | 位置 | 职责 | 典型端口 |
|----------|------|------|----------|
| **边缘节点 (Edge)** | 香港/海外 | 接收客户端连接、TLS 卸载、协议转换 | 443 (QUIC), 8080 (WS) |
| **核心节点 (Core)** | 大陆 | 转发到源站、认证、限流 | 8443 (QUIC), 8444 (WS) |
| **Master 主控** | 任意 | 统一管理、配置下发、监控采集 | 8080 (HTTP), 50051 (gRPC) |

---

## 3. 核心模块

### 3.1 Master 模块 (`master/`)

#### 3.1.1 模块结构

```
master/
├── config/           # 配置管理
│   └── config.go    # Master配置加载
├── db/              # 数据库操作
│   └── db.go        # MongoDB操作封装
├── handler/         # HTTP处理器
│   └── handler.go   # API处理器实现
├── health/          # 健康检查
│   ├── health_check.go
│   ├── failover.go
│   └── autoscale.go
├── ha/              # 高可用
│   ├── election.go  # 领导者选举
│   └── config_version.go
├── monitor/         # 监控采集
│   └── monitor.go
├── node/            # 节点管理
│   └── node.go
├── scripts/         # 部署脚本
│   └── deploy.go
└── templates/       # 配置模板
    └── gost_configs.go
```

#### 3.1.2 核心组件

**Node Manager** (`master/node/node.go`)
- 节点注册与注销
- 节点状态管理（online/offline/degraded）
- 节点标签管理
- 节点心跳检测

**Monitor** (`master/monitor/monitor.go`)
- 采集节点指标（连接数、流量、延迟）
- 聚合监控数据
- 触发告警

**Config Manager** (`master/config/`)
- 配置版本管理
- 配置下发
- 配置回滚

### 3.2 Agent 模块 (`agent/`)

#### 3.2.1 模块结构

```
agent/
├── config/          # Agent配置
│   └── config.go   # Agent配置加载
├── heartbeat/       # 心跳管理
│   └── heartbeat.go
├── status/          # 状态上报
│   └── status.go
└── updater/         # 配置更新
    └── updater.go
```

#### 3.2.2 核心组件

**Heartbeat Sender** (`agent/heartbeat/heartbeat.go`)
- 定期发送心跳到 Master
- 报告节点状态
- 检测连接断开

**Status Reporter** (`agent/status/status.go`)
- 采集本地指标（CPU、内存、连接数）
- 定期上报到 Master
- 异常告警

**Config Updater** (`agent/updater/updater.go`)
- 监听 Master 配置变更
- 自动应用新配置
- 平滑重启 gost 服务

### 3.3 公共包 (`pkg/`)

| 包名 | 功能 |
|------|------|
| `accesscontrol` | IP 白名单/黑名单管理 |
| `batch` | 批量操作管理 |
| `billing` | 计费管理 |
| `cache` | 高级缓存管理 |
| `defense` | 高防 IP 管理 |
| `dns` | 智能 DNS |
| `e2e` | 端到端测试 |
| `edge` | 边缘计算 |
| `http3` | QUIC/HTTP3 服务 |
| `iplib` | IP 地理信息库 |
| `layer4` | L4 代理 |
| `logs` | 日志分析 |
| `media` | HLS 加密 |
| `monitor` | 监控服务 |
| `node` | L2 节点管理 |
| `notification` | 通知管理 |
| `performance` | 性能优化 |
| `resource` | 资源管理 |
| `security` | 安全防护 |
| `stats` | 统计面板 |
| `storage` | 对象存储 |
| `tlsutil` | TLS 工具 |

---

## 4. 通信协议

### 4.1 gRPC 服务定义

```protobuf
// AgentService 定义
service AgentService {
    // 注册节点
    rpc Register(RegisterRequest) returns (RegisterResponse)

    // 心跳
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse)

    // 配置下发
    rpc PushConfig(PushConfigRequest) returns (PushConfigResponse)

    // 指令流 (双向流)
    rpc ExecuteCommand(stream CommandRequest) returns (stream CommandResponse)

    // 获取状态
    rpc GetStatus(StatusRequest) returns (StatusResponse)

    // 上报状态
    rpc ReportStatus(StatusRequest) returns (StatusResponse)
}
```

### 4.2 消息格式

#### 4.2.1 注册请求/响应

```go
// RegisterRequest
message RegisterRequest {
    string node_id = 1;      // 节点ID
    string node_name = 2;    // 节点名称
    string node_type = 3;    // edge | core
    string region = 4;       // hk | cn | us | sg
    string ip = 5;           // 节点IP
    map<string, string> metadata = 6;  // 节点元数据
}

// RegisterResponse
message RegisterResponse {
    bool success = 1;
    string message = 2;
    string master_version = 3;
    string node_id = 4;
}
```

#### 4.2.2 心跳请求/响应

```go
// HeartbeatRequest
message HeartbeatRequest {
    string node_id = 1;
    int64 timestamp = 2;
    string status = 3;  // online | offline | degraded
    map<string, string> metrics = 4;  // 节点指标
}

// HeartbeatResponse
message HeartbeatResponse {
    bool success = 1;
    string command = 2;          // 待执行命令
    bool config_updated = 3;     // 配置是否更新
    string config_version = 4;   // 配置版本
}
```

#### 4.2.3 命令请求/响应

```go
// CommandRequest
message CommandRequest {
    string command_id = 1;
    string command = 2;      // reload | restart | stop | status | logs
    map<string, string> params = 3;
}

// CommandResponse
message CommandResponse {
    string command_id = 1;
    bool success = 2;
    string output = 3;
    string error = 4;
}
```

### 4.3 连接优化

```go
// Keepalive 配置
type KeepaliveConfig struct {
    // 客户端参数
    Time:                10 * time.Second    // 发送ping间隔
    Timeout:             30 * time.Second    // 超时时间
    PermitWithoutStream: true                // 允许无流量的keepalive

    // 服务端参数
    MaxConnectionIdle:     5 * time.Minute
    MaxConnectionAge:      30 * time.Minute
    MaxConnectionAgeGrace: 5 * time.Second
    Time:                  1 * time.Minute
    Timeout:               20 * time.Second
}
```

---

## 5. 数据模型

### 5.1 MongoDB 集合

| 集合名 | 说明 | 索引 |
|--------|------|------|
| `leaders` | 领导者选举记录 | election_name, expires_at |
| `election_members` | 选举成员 | election_name |
| `config_versions` | 配置版本 | version (unique) |
| `config_rollbacks` | 配置回滚记录 | status, config_type |
| `config_history` | 配置历史 | config_type |
| `nodes` | 节点信息 | status, region |

### 5.2 数据结构

#### 5.2.1 Node 节点

```go
type Node struct {
    ID        string            `bson:"_id"`          // 节点ID
    Name      string            `bson:"name"`         // 节点名称
    Type      string            `bson:"type"`         // edge | core
    Region    string            `bson:"region"`       // hk | cn | us | sg
    Addr      string            `bson:"addr"`         // 地址
    Port      int               `bson:"port"`         // 端口
    Status    string            `bson:"status"`       // online | offline | degraded
    Tags      []string          `bson:"tags"`         // 标签
    Metadata  map[string]string `bson:"metadata"`     // 元数据
    Version   string            `bson:"version"`      // 配置版本
    CreatedAt time.Time         `bson:"created_at"`   // 创建时间
    UpdatedAt time.Time         `bson:"updated_at"`   // 更新时间
    LastSeen  time.Time         `bson:"last_seen"`    // 最后活跃时间
}
```

#### 5.2.2 ConfigVersion 配置版本

```go
type ConfigVersion struct {
    VersionID   int64     `bson:"version_id"`    // 版本ID
    Version     string    `bson:"version"`       // 版本号
    ConfigType  string    `bson:"config_type"`   // 配置类型
    ConfigData  []byte    `bson:"config_data"`   // 配置数据
    Checksum    string    `bson:"checksum"`      // 校验和
    Description string    `bson:"description"`   // 描述
    CreatedAt   time.Time `bson:"created_at"`    // 创建时间
    CreatedBy   string    `bson:"created_by"`    // 创建者
    IsActive    bool      `bson:"is_active"`     // 是否激活
    NodeType    string    `bson:"node_type"`     // 节点类型
    Regions     []string  `bson:"regions"`       // 适用区域
    Status      string    `bson:"status"`        // draft | published | deprecated
    PublishedAt time.Time `bson:"published_at"`  // 发布时间
}
```

#### 5.2.3 ConfigHistory 配置历史

```go
type ConfigHistory struct {
    VersionID   int64     `bson:"version_id"`
    ConfigType  string    `bson:"config_type"`
    Checksum    string    `bson:"checksum"`
    Description string    `bson:"description"`
    CreatedAt   time.Time `bson:"created_at"`
    CreatedBy   string    `bson:"created_by"`
    Action      string    `bson:"action"`        // create | publish | rollback
    FromVersion int64     `bson:"from_version"`
    ToVersion   int64     `bson:"to_version"`
}
```

---

## 6. 安全架构

### 6.1 安全特性

| 特性 | 说明 |
|------|------|
| **TLS 加密** | 所有通信使用 TLS 1.3 |
| **JWT 认证** | API 接口 JWT 认证 |
| **IP 白名单** | 限制管理接口访问 |
| **限流保护** | 防止 DDoS/CC 攻击 |
| **5秒盾** | 高频访问限制 |
| **CC 防护** | CC 攻击防护 |

### 6.2 防护机制

#### 6.2.1 FiveSecondShield (5秒盾)

```go
type ShieldConfig struct {
    Enabled:       true,                    // 启用
    WindowSize:    5 * time.Second,         // 时间窗口
    MaxRequests:   10,                      // 最大请求数
    BlockDuration: 60 * time.Second,        // 封锁时间
    Algorithm:     "sliding_window",        // 算法: token_bucket | sliding_window
    WhiteList:     []string,                // 白名单IP
    BlackList:     []string,                // 黑名单IP
    StrictMode:    false,                   // 严格模式
}
```

#### 6.2.2 CC 防护

```go
type CCProtectionConfig struct {
    Enabled:       true,
    RateLimit:     1000,                    // 每秒请求限制
    BurstSize:     2000,                    // 突发限制
    BlockDuration: 300 * time.Second,       // 封锁时间
    CheckInterval: 1 * time.Second,         // 检查间隔
}
```

### 6.3 认证流程

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────▶│   API    │────▶│  Master  │
└──────────┘     │  Gateway │     │   DB     │
                 └──────────┘     └──────────┘
                       │
                       ▼
                 ┌──────────┐
                 │   JWT    │
                 │ 验证     │
                 └──────────┘
```

---

## 7. 部署架构

### 7.1 单节点部署

```
┌─────────────────────────────────────────┐
│              Master Server               │
│  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │  Master  │  │ MongoDB  │  │ Redis  │ │
│  │ :8080/   │  │ :27017   │  │ :6379  │ │
│  │ :50051   │  └──────────┘  └────────┘ │
│  └──────────┘                           │
│  ┌──────────┐  ┌──────────┐            │
│  │Grafana   │  │Prometheus│            │
│  │ :3000    │  │ :9090    │            │
│  └──────────┘  └──────────┘            │
└─────────────────────────────────────────┘
```

### 7.2 集群部署

```
                    ┌─────────────────┐
                    │   负载均衡器     │
                    │    (Nginx)      │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  Master #1    │  │  Master #2    │  │  Master #3    │
│   (Leader)    │  │   (Follower)  │  │   (Follower)  │
│  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │
│  │ MongoDB │  │  │  │ MongoDB │  │  │  │ MongoDB │  │
│  │ (Replica│  │  │  │ (Replica│  │  │  │ (Replica│  │
│  │  Set)   │  │  │  │  Set)   │  │  │  │  Set)   │  │
│  └─────────┘  │  │  └─────────┘  │  │  └─────────┘  │
└───────────────┘  └───────────────┘  └───────────────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
      ┌───────────┐  ┌───────────┐  ┌───────────┐
      │Agent HK-1 │  │Agent HK-2 │  │Agent CN-1 │
      │  (Edge)   │  │  (Edge)   │  │  (Core)   │
      └───────────┘  └───────────┘  └───────────┘
```

### 7.3 端口说明

| 端口 | 协议 | 服务 | 说明 |
|------|------|------|------|
| 80 | TCP | HTTP | Web 管理界面 |
| 443 | TCP | QUIC | 边缘节点 HTTPS/QUIC |
| 8080 | TCP | HTTP | Master API |
| 8443 | TCP | QUIC | 核心节点 QUIC |
| 50051 | TCP | gRPC | Master gRPC |
| 9090 | TCP | HTTP | Prometheus |
| 3000 | TCP | HTTP | Grafana |
| 27017 | TCP | MongoDB | 数据库 |
| 6379 | TCP | Redis | 缓存 |

---

## 8. 监控告警

### 8.1 监控指标

#### 8.1.1 连接指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `connections_active` | Gauge | 活跃连接数 |
| `connections_total` | Counter | 连接总数 |
| `connection_duration_seconds` | Histogram | 连接持续时间 |

#### 8.1.2 请求指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `requests_total` | Counter | 请求总数 |
| `request_duration_seconds` | Histogram | 请求延迟 |
| `request_size_bytes` | Histogram | 请求大小 |
| `response_size_bytes` | Histogram | 响应大小 |

#### 8.1.3 系统指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `go_goroutines` | Gauge | 协程数量 |
| `go_mem_alloc_bytes` | Gauge | 内存分配 |
| `go_gc_duration_seconds` | Histogram | GC 耗时 |
| `process_cpu_seconds_total` | Counter | CPU 使用 |

### 8.2 告警规则

```yaml
groups:
- name: ai-cdn-alerts
  rules:
  - alert: HighLatency
    expr: latency_p99 > 100ms
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "P99延迟过高"

  - alert: HighErrorRate
    expr: error_rate > 1%
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "错误率过高"

  - alert: ConnectionExhaustion
    expr: active_connections > 100000
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "连接数过高"

  - alert: NodeOffline
    expr: node_status == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "节点离线"
```

---

## 附录

### A. 技术栈

| 组件 | 版本 | 用途 |
|------|------|------|
| Go | 1.24.0 | 开发语言 |
| gin | v1.10.1 | HTTP 框架 |
| gRPC | v1.67.1 | RPC 框架 |
| MongoDB | latest | 主数据库 |
| Redis | latest | 缓存/队列 |
| Prometheus | latest | 监控 |
| Vue3 | latest | 前端框架 |
| gost | v3 | 隧道转发 |

### B. 参考文档

- [gost 官方文档](https://v2.gost.run/)
- [gRPC Go 教程](https://grpc.io/docs/languages/go/)
- [MongoDB Go Driver](https://pkg.go.dev/go.mongodb.org/mongo-driver)
- [Prometheus 客户端](https://pkg.go.dev/github.com/prometheus/client_golang)

### C. 文档整合说明

> **说明**: 本文档是系统架构的权威版本。
> 
> 以下内容已从 [`plans/ai-cdn-architecture.md`](../plans/ARCHIVE/ai-cdn-architecture.md) 整合到本文档：
> - 隧道转发层设计（QUIC/WebSocket优化）
> - CDN节点架构设计（边缘节点/核心节点）
> - 零缓存策略设计
> - 高并发处理机制
> - SSE流式响应优化
> 
> 相关设计文档已归档到 [`plans/ARCHIVE/`](../plans/ARCHIVE/) 目录。

---

*文档版本: v2.0*
*最后更新: 2026-01-13*
*整合自: plans/ai-cdn-architecture.md*

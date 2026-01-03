# AI CDN Tunnel - 主控-被控架构设计

## 1. 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│                        Master 主控节点                        │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │
│  │  Web API  │  │ 配置中心   │  │ 节点管理  │  │ 监控中心  │  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘  │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐                │
│  │ 指令分发  │  │ 日志收集  │  │ 告警中心  │                │
│  └───────────┘  └───────────┘  └───────────┘                │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │    gRPC/HTTP2     │
                    └─────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Agent 香港-1  │    │ Agent 香港-2  │    │ Agent 大陆-1  │
│ (边缘节点)     │    │ (边缘节点)     │    │ (核心节点)     │
└───────────────┘    └───────────────┘    └───────────────┘
```

## 2. 核心组件

### 2.1 Master 主控节点功能

| 模块 | 功能 | 端口 |
|------|------|------|
| Web API | 管理界面REST API | 8080 |
| gRPC Server | Agent通信服务 | 50051 |
| Config Center | 配置版本管理 | 内置 |
| Node Manager | 节点注册发现 | 内置 |
| Monitor | 指标聚合 | 9090 |
| Alert | 告警触发 | 内置 |

### 2.2 Agent 被控节点功能

| 模块 | 功能 |
|------|------|
| gRPC Client | 与Master通信 |
| Config Loader | 配置加载应用 |
| Heartbeater | 心跳上报 |
| Status Reporter | 状态上报 |
| Command Executor | 指令执行 |

## 3. 通信协议

### 3.1 gRPC 服务定义

```protobuf
syntax = "proto3";

package agent;

service AgentService {
    // 节点注册
    rpc Register(RegisterRequest) returns (RegisterResponse);
    
    // 心跳
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
    
    // 配置下发
    rpc PushConfig(PushConfigRequest) returns (PushConfigResponse);
    
    // 指令执行
    rpc ExecuteCommand(CommandRequest) returns (CommandResponse);
    
    // 状态上报
    rpc ReportStatus(StatusRequest) returns (StatusResponse);
    
    // 日志上报
    rpc UploadLogs(LogRequest) returns (LogResponse);
}

// 节点注册
message RegisterRequest {
    string node_id = 1;
    string node_name = 2;
    string node_type = 3;  // edge, core
    string region = 4;
    string ip = 5;
    map<string, string> metadata = 6;
}

message RegisterResponse {
    bool success = 1;
    string message = 2;
    string master_version = 3;
}

// 心跳
message HeartbeatRequest {
    string node_id = 1;
    int64 timestamp = 2;
    string status = 3;  // online, offline, degraded
}

message HeartbeatResponse {
    bool success = 1;
    string command = 2;  // 等待执行的命令
    bool config_updated = 3;
    string config_version = 4;
}

// 配置下发
message PushConfigRequest {
    string config_version = 1;
    string config_data = 2;  // Base64编码的配置
    string checksum = 3;
}

message PushConfigResponse {
    bool success = 1;
    bool need_restart = 2;
    string message = 3;
}

// 指令
message CommandRequest {
    string node_id = 1;
    string command = 2;  // reload, restart, stop
    map<string, string> params = 3;
}

message CommandResponse {
    bool success = 1;
    string output = 2;
    string error = 3;
}

// 状态
message StatusRequest {
    string node_id = 1;
    StatusData status = 2;
}

message StatusData {
    int64 uptime = 1;
    int32 connections = 2;
    int32 cpu_percent = 3;
    int64 memory_bytes = 4;
    int64 network_in = 5;
    int64 network_out = 6;
}

message StatusResponse {
    bool success = 1;
}
```

## 4. 数据模型

### 4.1 节点信息

```go
type Node struct {
    ID          string            `json:"id" bson:"_id"`
    Name        string            `json:"name" bson:"name"`
    Type        string            `json:"type" bson:"type"`  // edge, core
    Region      string            `json:"region" bson:"region"`
    IP          string            `json:"ip" bson:"ip"`
    Port        int               `json:"port" bson:"port"`
    Status      string            `json:"status" bson:"status"`  // online, offline, degraded
    Tags        []string          `json:"tags" bson:"tags"`
    Metadata    map[string]string `json:"metadata" bson:"metadata"`
    Version     string            `json:"version" bson:"version"`
    CreatedAt   time.Time         `json:"created_at" bson:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at" bson:"updated_at"`
    LastBeatAt  time.Time         `json:"last_beat_at" bson:"last_beat_at"`
}
```

### 4.2 配置版本

```go
type ConfigVersion struct {
    ID          string    `json:"id" bson:"_id"`
    Version     string    `json:"version" bson:"version"`
    Description string    `json:"description" bson:"description"`
    ConfigData  string    `json:"config_data" bson:"config_data"`  // Base64
    Checksum    string    `json:"checksum" bson:"checksum"`
    NodeType    string    `json:"node_type" bson:"node_type"`  // edge, core, all
    Regions     []string  `json:"regions" bson:"regions"`
    Status      string    `json:"status" bson:"status"`  // draft, published, archived
    CreatedAt   time.Time `json:"created_at" bson:"created_at"`
    PublishedAt time.Time `json:"published_at" bson:"published_at"`
}
```

### 4.3 告警规则

```go
type AlertRule struct {
    ID          string    `json:"id" bson:"_id"`
    Name        string    `json:"name" bson:"name"`
    Expression  string    `json:"expression" bson:"expression"`  // Prometheus查询
    Duration    int       `json:"duration" bson:"duration"`  // 秒
    Severity    string    `json:"severity" bson:"severity"`  // critical, warning, info
    Labels      map[string]string `json:"labels" bson:"labels"`
    Annotations map[string]string `json:"annotations" bson:"annotations"`
    Enabled     bool      `json:"enabled" bson:"enabled"`
}
```

## 5. API接口设计

### 5.1 节点管理

```yaml
# 节点列表
GET /api/v1/nodes
Response:
  - nodes: [Node]
  - total: 100

# 节点详情
GET /api/v1/nodes/{id}
Response:
  - Node

# 更新节点
PUT /api/v1/nodes/{id}
Request:
  - Node (部分字段)
Response:
  - Node

# 删除节点
DELETE /api/v1/nodes/{id}

# 节点标签
PUT /api/v1/nodes/{id}/tags

# 手动下线
POST /api/v1/nodes/{id}/offline

# 手动上线
POST /api/v1/nodes/{id}/online
```

### 5.2 配置管理

```yaml
# 配置列表
GET /api/v1/configs
Response:
  - configs: [ConfigVersion]
  - total: 10

# 配置详情
GET /api/v1/configs/{version}

# 创建配置
POST /api/v1/configs
Request:
  - version: "v1.0.0"
  - description: "初始配置"
  - config_data: "base64..."
  - node_type: "edge"
  - regions: ["hk", "cn"]

# 发布配置
POST /api/v1/configs/{version}/publish

# 回滚配置
POST /api/v1/configs/{version}/rollback

# 对比配置
GET /api/v1/configs/{v1}/diff/{v2}
```

### 5.3 指令分发

```yaml
# 执行指令
POST /api/v1/commands
Request:
  - command: "reload"  # reload, restart, stop
  - target_type: "node"  # node, region, type, all
  - target_ids: ["node-1", "node-2"]
  - params: {}

Response:
  - task_id: "task-123"
  - status: "pending"

# 指令状态
GET /api/v1/commands/{task_id}

# 指令历史
GET /api/v1/commands?node_id=xxx
```

### 5.4 监控数据

```yaml
# 节点指标
GET /api/v1/metrics/nodes/{id}

# 聚合指标
GET /api/v1/metrics/aggregate?region=hk

# 告警列表
GET /api/v1/alerts?status=firing

# 告警详情
GET /api/v1/alerts/{id}

# 静默告警
POST /api/v1/alerts/{id}/silence
```

## 6. 配置下发流程

```
1. 管理员在Master创建新配置
   ↓
2. Master生成配置版本，保存到数据库
   ↓
3. Master通过gRPC推送到目标Agent
   ↓
4. Agent接收配置，校验checksum
   ↓
5. Agent应用配置（热加载或重启）
   ↓
6. Agent上报应用结果
   ↓
7. Master更新配置状态
```

## 7. 心跳上报流程

```
Agent (每10s)                    Master
    │                              │
    │─ HeartbeatRequest ──────────>│
    │   node_id, status            │
    │                              │
    │<─ HeartbeatResponse ─────────│
    │   command, config_updated    │
    │                              │
```

## 8. 部署架构

### 8.1 Master部署

```yaml
# docker-compose.yml
version: '3.8'
services:
  master:
    image: ai-cdn-master:latest
    ports:
      - "8080:8080"  # Web API
      - "50051:50051"  # gRPC
      - "9090:9090"  # Metrics
    volumes:
      - ./data:/data
      - ./configs:/configs
    environment:
      - DATABASE_URL=mongodb://mongo:27017/ai-cdn
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=your-secret
    depends_on:
      - mongo
      - redis
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G

  mongo:
    image: mongo:6
    volumes:
      - mongo_data:/data/db

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  mongo_data:
  redis_data:
```

### 8.2 Agent部署

```bash
# 启动Agent
docker run -d \
  --name ai-cdn-agent \
  --network host \
  -v /etc/ai-cdn:/etc/ai-cdn \
  -v /var/log/ai-cdn:/var/log/ai-cdn \
  -e MASTER_ADDR=master.ai-cdn.local:50051 \
  -e NODE_ID=$(hostname) \
  -e NODE_TYPE=edge \
  -e REGION=hk \
  ai-cdn-agent:latest
```

## 9. 安全机制

### 9.1 认证

- **Agent认证**: 双向TLS + Token
- **API认证**: JWT Bearer Token
- **Admin认证**: 双因素认证

### 9.2 授权

- RBAC角色: Admin, Operator, Viewer
- 细粒度权限控制

### 9.3 加密

- 传输加密: TLS 1.3
- 配置加密: AES-256

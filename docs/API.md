# AI CDN Tunnel - API 接口文档

## 目录

- [1. 概述](#1-概述)
- [2. 认证](#2-认证)
- [3. 节点管理](#3-节点管理)
- [4. 配置管理](#4-配置管理)
- [5. 指令管理](#5-指令管理)
- [6. 监控数据](#6-监控数据)
- [7. 告警管理](#7-告警管理)
- [8. 部署脚本](#8-部署脚本)
- [9. 错误码](#9-错误码)

---

## 1. 概述

### 1.1 Base URL

| 环境 | URL |
|------|-----|
| 生产环境 | `http://master-ip:8080` |
| 本地开发 | `http://localhost:8080` |

### 1.2 内容类型

所有请求和响应均使用 JSON 格式：

```
Content-Type: application/json
```

### 1.3 通用响应格式

```json
{
    "code": 200,
    "message": "success",
    "data": {}
}
```

### 1.4 分页参数

列表接口支持分页：

| 参数 | 类型 | 说明 |
|------|------|------|
| `page` | int | 页码，默认 1 |
| `page_size` | int | 每页数量，默认 20 |

---

## 2. 认证

### 2.1 获取 Token

> **注意**: 当前版本 JWT 中间件为空实现，认证功能待完善

```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "username": "admin",
    "password": "admin123"
}
```

**响应** (待实现)

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIs...",
        "expires_at": "2024-01-01T00:00:00Z"
    }
}
```

### 2.2 使用 Token

在请求头中携带 Token：

```http
GET /api/v1/nodes
Authorization: Bearer <token>
```

---

## 3. 节点管理

### 3.1 获取节点列表

```http
GET /api/v1/nodes
```

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `status` | string | 过滤状态 (online/offline/degraded) |
| `region` | string | 过滤区域 |
| `type` | string | 过滤类型 (edge/core) |

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "nodes": [
            {
                "id": "hk-node-1",
                "name": "hk-node-1",
                "type": "edge",
                "region": "hk",
                "addr": "192.168.1.10",
                "port": 443,
                "status": "online",
                "tags": ["production", "quic"],
                "version": "v1.0.0",
                "connections": 15234,
                "uptime": 86400,
                "created_at": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-02T00:00:00Z"
            }
        ],
        "total": 10,
        "page": 1,
        "page_size": 20
    }
}
```

### 3.2 获取单个节点

```http
GET /api/v1/nodes/{id}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "node": {
            "id": "hk-node-1",
            "name": "hk-node-1",
            "type": "edge",
            "region": "hk",
            "addr": "192.168.1.10",
            "port": 443,
            "status": "online",
            "tags": ["production", "quic"],
            "metadata": {
                "hostname": "hk-edge-01",
                "os": "linux",
                "arch": "amd64"
            },
            "version": "v1.0.0",
            "connections": 15234,
            "cpu_usage": 45.5,
            "memory_usage": 62.3,
            "uptime": 86400,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z",
            "last_seen": "2024-01-02T00:00:00Z"
        }
    }
}
```

### 3.3 更新节点

```http
PUT /api/v1/nodes/{id}
Content-Type: application/json

{
    "name": "hk-node-1-renamed",
    "tags": ["production", "quic", "backup"],
    "metadata": {
        "environment": "production"
    }
}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "updated"
    }
}
```

### 3.4 删除节点

```http
DELETE /api/v1/nodes/{id}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "deleted"
    }
}
```

### 3.5 更新节点标签

```http
POST /api/v1/nodes/{id}/tags
Content-Type: application/json

{
    "tags": ["production", "quic", "priority"]
}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "tags_updated",
        "tags": ["production", "quic", "priority"]
    }
}
```

### 3.6 节点上线

```http
POST /api/v1/nodes/{id}/online
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "online"
    }
}
```

### 3.7 节点下线POST /api/v

```http
1/nodes/{id}/offline
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "offline"
    }
}
```

### 3.8 快速安装

```http
POST /api/v1/nodes/quick-install
Content-Type: application/json

{
    "master_addr": "master.ai-cdn.local:50051",
    "node_type": "edge",
    "region": "hk",
    "node_name": "quick-hk-1",
    "os": "linux",
    "arch": "amd64"
}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "install_script": "#!/bin/bash\n...",
        "node_id": "generated-node-id"
    }
}
```

---

## 4. 配置管理

### 4.1 获取配置列表

```http
GET /api/v1/configs
```

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `status` | string | 过滤状态 (draft/published/deprecated) |
| `node_type` | string | 过滤节点类型 |
| `region` | string | 过滤区域 |

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "configs": [
            {
                "version_id": 1,
                "version": "v1.0.0",
                "config_type": "gost",
                "description": "初始配置",
                "node_type": "edge",
                "regions": ["hk"],
                "status": "published",
                "created_at": "2024-01-01T00:00:00Z",
                "created_by": "admin",
                "published_at": "2024-01-01T00:00:00Z"
            }
        ],
        "total": 5
    }
}
```

### 4.2 获取配置详情

```http
GET /api/v1/configs/{version}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "config": {
            "version_id": 1,
            "version": "v1.0.0",
            "config_type": "gost",
            "checksum": "abc123...",
            "description": "初始配置",
            "config_data": "base64编码的配置内容",
            "node_type": "edge",
            "regions": ["hk"],
            "status": "published",
            "created_at": "2024-01-01T00:00:00Z",
            "created_by": "admin"
        }
    }
}
```

### 4.3 创建配置

```http
POST /api/v1/configs
Content-Type: application/json

{
    "version": "v1.1.0",
    "config_type": "gost",
    "description": "更新限流配置",
    "config_data": "base64编码的gost配置",
    "node_type": "edge",
    "regions": ["hk"]
}
```

**响应**

```json
{
    "code": 201,
    "message": "success",
    "data": {
        "status": "created",
        "version_id": 2
    }
}
```

### 4.4 发布配置

```http
POST /api/v1/configs/{version}/publish
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "published",
        "published_at": "2024-01-02T00:00:00Z"
    }
}
```

### 4.5 回滚配置

```http
POST /api/v1/configs/{version}/rollback
Content-Type: application/json

{
    "reason": "配置有问题，需要回滚"
}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "status": "rolled_back",
        "rollback_to": "v1.0.0"
    }
}
```

### 4.6 获取配置历史

```http
GET /api/v1/configs/history
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "history": [
            {
                "version_id": 2,
                "config_type": "gost",
                "action": "publish",
                "from_version": 1,
                "to_version": 2,
                "description": "发布v1.1.0",
                "created_at": "2024-01-02T00:00:00Z",
                "created_by": "admin"
            },
            {
                "version_id": 1,
                "config_type": "gost",
                "action": "create",
                "description": "初始配置",
                "created_at": "2024-01-01T00:00:00Z",
                "created_by": "admin"
            }
        ]
    }
}
```

---

## 5. 指令管理

### 5.1 执行指令

```http
POST /api/v1/commands
Content-Type: application/json

{
    "command": "reload",
    "target_type": "region",
    "target_ids": ["hk"],
    "params": {
        "timeout": 60
    }
}
```

**指令类型**

| 指令 | 说明 |
|------|------|
| `reload` | 重载配置 |
| `restart` | 重启服务 |
| `stop` | 停止服务 |
| `status` | 查询状态 |
| `logs` | 获取日志 |

**目标类型**

| 目标类型 | 说明 |
|----------|------|
| `node` | 单个节点 |
| `region` | 整个区域 |
| `type` | 指定类型的所有节点 |
| `all` | 所有节点 |

**响应**

```json
{
    "code": 202,
    "message": "success",
    "data": {
        "task_id": "task-abc123",
        "status": "queued"
    }
}
```

### 5.2 查询指令状态

```http
GET /api/v1/commands/{task_id}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "task": {
            "task_id": "task-abc123",
            "command": "reload",
            "target_type": "region",
            "target_ids": ["hk"],
            "status": "completed",
            "progress": 100,
            "created_at": "2024-01-02T00:00:00Z",
            "completed_at": "2024-01-02T00:00:10Z",
            "results": {
                "hk-node-1": {
                    "success": true,
                    "output": "Config reloaded successfully"
                }
            }
        }
    }
}
```

### 5.3 任务状态值

| 状态 | 说明 |
|------|------|
| `queued` | 排队中 |
| `running` | 执行中 |
| `completed` | 已完成 |
| `failed` | 失败 |
| `cancelled` | 已取消 |

---

## 6. 监控数据

### 6.1 获取节点指标

```http
GET /api/v1/metrics/nodes/{id}
```

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `start` | string | 开始时间 (RFC3339) |
| `end` | string | 结束时间 (RFC3339) |
| `step` | string | 步长 (15s/1m/5m) |

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "metrics": {
            "connections": {
                "current": 15234,
                "max": 20000,
                "min": 5000,
                "avg": 12500
            },
            "requests": {
                "total": 1000000,
                "per_second": 500,
                "errors": 10
            },
            "latency": {
                "p50": 25,
                "p95": 50,
                "p99": 100
            },
            "traffic": {
                "in_bytes": 1024000000,
                "out_bytes": 5120000000
            },
            "system": {
                "cpu_usage": 45.5,
                "memory_usage": 62.3,
                "goroutines": 150
            }
        },
        "timestamps": [
            "2024-01-02T00:00:00Z",
            "2024-01-02T00:01:00Z"
        ]
    }
}
```

### 6.2 获取聚合指标

```http
GET /api/v1/metrics/aggregate
```

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `region` | string | 区域过滤 |
| `type` | string | 类型过滤 |

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "metrics": {
            "total_nodes": 10,
            "online_nodes": 9,
            "total_connections": 152340,
            "total_requests": 10000000,
            "avg_latency": 35,
            "error_rate": 0.01
        },
        "by_region": {
            "hk": {
                "nodes": 5,
                "connections": 80000,
                "requests": 5000000
            },
            "cn": {
                "nodes": 5,
                "connections": 72340,
                "requests": 5000000
            }
        },
        "by_type": {
            "edge": {
                "nodes": 8,
                "connections": 130000
            },
            "core": {
                "nodes": 2,
                "connections": 22340
            }
        }
    }
}
```

### 6.3 Prometheus 指标端点

Master 节点暴露 Prometheus 格式指标：

```http
GET /metrics
```

主要指标：

| 指标 | 类型 | 说明 |
|------|------|------|
| `ai_cdn_nodes_total` | Gauge | 节点总数 |
| `ai_cdn_nodes_online` | Gauge | 在线节点数 |
| `ai_cdn_connections_active` | Gauge | 活跃连接数 |
| `ai_cdn_requests_total` | Counter | 请求总数 |
| `ai_cdn_request_duration_seconds` | Histogram | 请求延迟 |
| `ai_cdn_config_version` | Gauge | 当前配置版本 |

---

## 7. 告警管理

### 7.1 获取告警列表

```http
GET /api/v1/alerts
```

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `status` | string | 过滤状态 (firing/pending/resolved) |
| `severity` | string | 过滤级别 (critical/warning) |

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "alerts": [
            {
                "id": "alert-001",
                "name": "HighLatency",
                "severity": "warning",
                "status": "firing",
                "description": "P99延迟超过100ms",
                "labels": {
                    "node_id": "hk-node-1",
                    "region": "hk"
                },
                "value": 150,
                "threshold": 100,
                "starts_at": "2024-01-02T00:00:00Z",
                "ends_at": null
            }
        ],
        "total": 5
    }
}
```

### 7.2 获取告警详情

```http
GET /api/v1/alerts/{id}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "alert": {
            "id": "alert-001",
            "name": "HighLatency",
            "severity": "warning",
            "status": "firing",
            "description": "P99延迟超过100ms",
            "labels": {
                "node_id": "hk-node-1",
                "region": "hk"
            },
            "annotations": {
                "summary": "节点 hk-node-1 延迟过高",
                "runbook_url": "https://wiki.example.com/high-latency"
            },
            "value": 150,
            "threshold": 100,
            "starts_at": "2024-01-02T00:00:00Z",
            "ends_at": null
        }
    }
}
```

### 7.3 静默告警

```http
POST /api/v1/alerts/{id}/silence
Content-Type: application/json

{
    "duration": "1h",
    "reason": "计划内维护",
    "created_by": "admin"
}
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "silence_id": "silence-001",
        "expires_at": "2024-01-02T01:00:00Z"
    }
}
```

---

## 8. 部署脚本

### 8.1 获取部署脚本

```http
GET /api/v1/nodes/deploy-script
```

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `node_type` | string | 节点类型 (edge/core) |
| `region` | string | 区域 |
| `master_addr` | string | Master 地址 |
| `os` | string | 操作系统 |
| `arch` | string | 架构 |

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "script_id": "script-edge-hk",
        "content": "#!/bin/bash\n...",
        "filename": "deploy-agent-edge-hk.sh",
        "checksum": "sha256:abc123..."
    }
}
```

### 8.2 下载部署脚本

```http
GET /api/v1/nodes/deploy-script/{scriptID}/download
```

**响应**

返回脚本文件下载。

### 8.3 获取部署脚本列表

```http
GET /api/v1/nodes/deploy-script
```

**响应**

```json
{
    "code": 200,
    "message": "success",
    "data": {
        "scripts": [
            {
                "script_id": "script-edge-hk",
                "node_type": "edge",
                "region": "hk",
                "description": "香港边缘节点部署脚本",
                "created_at": "2024-01-01T00:00:00Z"
            }
        ]
    }
}
```

---

## 9. 错误码

### 9.1 通用错误码

| 错误码 | 说明 |
|--------|------|
| 200 | 成功 |
| 201 | 创建成功 |
| 400 | 请求参数错误 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 资源不存在 |
| 409 | 资源冲突 |
| 500 | 服务器内部错误 |

### 9.2 业务错误码

| 错误码 | 说明 |
|--------|------|
| 10001 | 节点不存在 |
| 10002 | 节点已离线 |
| 10003 | 节点注册失败 |
| 10004 | 节点心跳超时 |
| 20001 | 配置不存在 |
| 20002 | 配置版本冲突 |
| 20003 | 配置发布失败 |
| 20004 | 配置回滚失败 |
| 30001 | 任务不存在 |
| 30002 | 任务执行超时 |
| 30003 | 任务取消失败 |
| 40001 | 告警不存在 |
| 40002 | 告警静默失败 |
| 50001 | 数据库错误 |
| 50002 | 缓存错误 |
| 50003 | gRPC 连接错误 |

### 9.3 错误响应格式

```json
{
    "code": 40001,
    "message": "节点不存在",
    "details": {
        "node_id": "hk-node-999"
    }
}
```

---

## 附录

### A. OpenAPI 规范

完整的 OpenAPI 3.0 规范可在以下位置获取：

```
http://master-ip:8080/openapi.json
```

### B. SDK

| 语言 | 仓库 |
|------|------|
| Go | `go get github.com/ai-cdn-tunnel/sdk-go` |
| Python | `pip install ai-cdn-tunnel-sdk` |
| Node.js | `npm install ai-cdn-tunnel-sdk` |

# AI CDN Tunnel - 主控-被控架构部署指南

## 目录

- [架构概览](#架构概览)
- [组件说明](#组件说明)
- [快速开始](#快速开始)
- [部署Master主控节点](#部署master主控节点)
- [部署Agent被控节点](#部署agent被控节点)
- [配置管理](#配置管理)
- [API接口](#api接口)
- [运维操作](#运维操作)
- [故障排查](#故障排查)

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                     Master 主控节点                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Web API │  │ gRPC服务 │  │ 配置中心 │  │ 监控中心 │    │
│  │  :8080   │  │ :50051   │  │  MongoDB │  │ Prometheus│   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │ 节点管理 │  │ 告警中心 │  │ Redis缓存│                 │
│  └──────────┘  └──────────┘  └──────────┘                 │
└─────────────────────────────────────────────────────────────┘
                              │ gRPC/HTTP2
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Agent 香港-1  │    │ Agent 香港-2  │    │ Agent 大陆-1  │
│ (边缘节点)     │    │ (边缘节点)     │    │ (核心节点)     │
│ ┌───────────┐ │    │ ┌───────────┐ │    │ ┌───────────┐ │
│ │  gost     │ │    │ │  gost     │ │    │ │  gost     │ │
│ │  :443     │ │    │ │  :443     │ │    │ │  :8443    │ │
│ └───────────┘ │    │ └───────────┘ │    │ └───────────┘ │
└───────────────┘    └───────────────┘    └───────────────┘
```

## 组件说明

### Master 主控节点

| 组件 | 功能 | 端口 |
|------|------|------|
| Web API | 管理界面REST API | 8080 |
| gRPC Server | Agent通信服务 | 50051 |
| MongoDB | 数据持久化 | 27017 |
| Redis | 缓存和队列 | 6379 |
| Prometheus | 指标存储 | 9090 |
| Grafana | 监控面板 | 3000 |

### Agent 被控节点

| 组件 | 功能 |
|------|------|
| Agent客户端 | 与Master通信 |
| gost服务 | 实际代理服务 |
| 状态收集器 | 采集本地指标 |
| 配置更新器 | 应用Master下发的配置 |

## 快速开始

### 1. 部署Master（只需一次）

```bash
# 在主控服务器上执行
chmod +x scripts/deploy-master.sh
sudo ./scripts/deploy-master.sh
```

### 2. 部署Agent（每台被控服务器）

```bash
# 在被控服务器上执行
chmod +x scripts/deploy-agent.sh

# 部署边缘节点 (香港)
sudo ./scripts/deploy-agent.sh master.ai-cdn.local:50051 edge hk

# 部署核心节点 (大陆)
sudo ./scripts/deploy-agent.sh master.ai-cdn.local:50051 core cn
```

### 3. 验证部署

```bash
# 检查Master服务
curl http://localhost:8080/api/v1/nodes

# 应该看到已注册的节点列表
```

## 部署Master主控节点

### 环境要求

- CPU: 4核+
- 内存: 8GB+
- 磁盘: 100GB+
- Docker: 20.10+

### 部署步骤

```bash
# 1. 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn

# 2. 进入脚本目录
cd scripts

# 3. 运行部署脚本
chmod +x deploy-master.sh
sudo ./deploy-master.sh

# 4. 修改配置
# 编辑 /etc/ai-cdn/master/.env
# 修改 JWT_SECRET 和 ADMIN_PASSWORD

# 5. 重启服务
cd /etc/ai-cdn/master
docker-compose restart master
```

### 访问地址

| 服务 | 地址 | 默认账号 |
|------|------|----------|
| Web API | http://MasterIP:8080 | admin/* |
| Grafana | http://MasterIP:3000 | admin/admin123 |
| Prometheus | http://MasterIP:9091 | - |

## 部署Agent被控节点

### 环境要求

- CPU: 4核+
- 内存: 4GB+
- 磁盘: 10GB+
- 系统: Linux (amd64/arm64)

### 部署步骤

```bash
# 1. 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn

# 2. 进入脚本目录
cd scripts

# 3. 运行部署脚本
chmod +x deploy-agent.sh

# 部署边缘节点 (香港)
sudo ./deploy-agent.sh <Master地址> edge hk <节点名>

# 示例
sudo ./deploy-agent.sh 192.168.1.100:50051 edge hk hk-node-1

# 部署核心节点 (大陆)
sudo ./deploy-agent.sh 192.168.1.100:50051 core cn cn-node-1
```

### 参数说明

```bash
./deploy-agent.sh <Master地址> <节点类型> <地区> <节点名称>

参数说明:
  Master地址   Master节点的gRPC地址 (如: 192.168.1.100:50051)
  节点类型     edge (边缘节点) 或 core (核心节点)
  地区         节点所在地区 (如: hk, cn, us, sg)
  节点名称     自定义节点名称 (可选，自动生成)
```

### 手动启动Agent

```bash
# 如果需要手动启动
/usr/local/bin/ai-cdn-agent \
  -config /etc/ai-cdn/agent/agent.yml \
  -master 192.168.1.100:50051 \
  -type edge \
  -region hk
```

## 配置管理

### Master端配置

```yaml
# /etc/ai-cdn/master/master.yml

# 服务端口
http:
  addr: :8080

grpc:
  addr: :50051

# 数据库
database:
  type: mongodb
  uri: mongodb://localhost:27017/ai-cdn

# JWT认证
jwt:
  secret: your-secret-key
  expiration: 24h
```

### Agent端配置

```yaml
# /etc/ai-cdn/agent/agent.yml

# Master连接
master:
  addr: 192.168.1.100:50051
  token: your-node-token

# 节点信息
node:
  type: edge
  region: hk

# gost配置
gost:
  config_path: /etc/ai-cdn/agent/gost.yml
```

### gost服务配置

```yaml
# /etc/ai-cdn/agent/gost.yml

services:
  - name: quic-edge
    addr: :443
    handler:
      type: http3
      dialer:
        type: http3
        host: ${CORE_NODE_IP}
        port: 8443
    listener:
      type: quic
      config:
        max-incoming-streams: 10000
```

## API接口

### 节点管理

```bash
# 获取所有节点
GET /api/v1/nodes

# 获取单个节点
GET /api/v1/nodes/{id}

# 更新节点
PUT /api/v1/nodes/{id}

# 删除节点
DELETE /api/v1/nodes/{id}

# 设置节点标签
POST /api/v1/nodes/{id}/tags

# 手动上线
POST /api/v1/nodes/{id}/online

# 手动下线
POST /api/v1/nodes/{id}/offline
```

### 配置管理

```bash
# 获取所有配置版本
GET /api/v1/configs

# 获取配置详情
GET /api/v1/configs/{version}

# 创建新配置
POST /api/v1/configs
{
  "version": "v1.0.1",
  "description": "更新限流配置",
  "config_data": "base64编码的配置内容",
  "node_type": "edge",
  "regions": ["hk"]
}

# 发布配置
POST /api/v1/configs/{version}/publish

# 回滚配置
POST /api/v1/configs/{version}/rollback
```

### 指令管理

```bash
# 执行指令
POST /api/v1/commands
{
  "command": "reload",  // reload, restart, stop
  "target_type": "region",  // node, region, type, all
  "target_ids": ["hk"],
  "params": {}
}

# 查看指令状态
GET /api/v1/commands/{task_id}
```

### 监控数据

```bash
# 节点指标
GET /api/v1/metrics/nodes/{id}

# 聚合指标
GET /api/v1/metrics/aggregate?region=hk

# 告警列表
GET /api/v1/alerts

# 静默告警
POST /api/v1/alerts/{id}/silence
```

## 运维操作

### 查看节点状态

```bash
# 在Master上执行
curl http://localhost:8080/api/v1/nodes | jq

# 输出示例:
{
  "nodes": [
    {
      "id": "hk-node-1",
      "name": "hk-node-1",
      "type": "edge",
      "region": "hk",
      "status": "online",
      "connections": 15234,
      "uptime": 86400
    }
  ]
}
```

### 下发新配置

```bash
# 1. 创建新配置
curl -X POST http://localhost:8080/api/v1/configs \
  -H "Content-Type: application/json" \
  -d '{
    "version": "v1.0.2",
    "description": "更新TLS配置",
    "config_data": "base64...",
    "node_type": "edge",
    "regions": ["hk"]
  }'

# 2. 发布配置
curl -X POST http://localhost:8080/api/v1/configs/v1.0.2/publish

# 3. Agent会自动接收并应用配置
```

### 重启节点服务

```bash
# 重启单个节点
curl -X POST http://localhost:8080/api/v1/commands \
  -H "Content-Type: application/json" \
  -d '{
    "command": "restart",
    "target_type": "node",
    "target_ids": ["hk-node-1"]
  }'

# 重启整个地区
curl -X POST http://localhost:8080/api/v1/commands \
  -H "Content-Type: application/json" \
  -d '{
    "command": "restart",
    "target_type": "region",
    "target_ids": ["hk"]
  }'
```

### 查看告警

```bash
# 获取活跃告警
curl http://localhost:8080/api/v1/alerts?status=firing

# 获取告警详情
curl http://localhost:8080/api/v1/alerts/{alert_id}
```

## 故障排查

### Master无法连接Agent

```bash
# 检查Agent日志
journalctl -u ai-cdn-agent -f

# 检查网络连通性
nc -zv master.ai-cdn.local 50051

# 检查Agent配置
cat /etc/ai-cdn/agent/agent.yml
```

### 节点状态异常

```bash
# 检查Agent心跳
curl http://AgentIP:9090/metrics | grep agent

# 检查gost服务
systemctl status gost

# 查看gost日志
journalctl -u gost -f
```

### 配置不生效

```bash
# 检查Master配置版本
curl http://localhost:8080/api/v1/configs

# 检查Agent配置版本
curl http://AgentIP:8080/api/v1/nodes/AgentID | jq .config_version

# 手动触发重新加载
curl -X POST http://localhost:8080/api/v1/commands \
  -d '{"command": "reload", "target_type": "node", "target_ids": ["AgentID"]}'
```

## 性能监控

### Grafana面板

访问 http://MasterIP:3000 ，使用 admin/admin123 登录。

### 关键指标

| 指标 | 说明 | 告警阈值 |
|------|------|----------|
| connections_active | 活跃连接数 | >80,000 |
| request_duration_p99 | P99延迟 | >100ms |
| error_rate | 错误率 | >1% |
| cpu_usage | CPU使用率 | >80% |
| memory_usage | 内存使用率 | >80% |

# AI CDN Tunnel - 智能CDN隧道转发系统

基于 gost v3 的高并发AI对话CDN解决方案，支持主控-被控架构统一管理。

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [架构设计](#架构设计)
- [快速开始](#快速开始)
- [部署指南](#部署指南)
- [配置说明](#配置说明)
- [性能优化](#性能优化)
- [API接口](#api接口)
- [运维管理](#运维管理)
- [常见问题](#常见问题)

## 项目简介

AI CDN Tunnel 是一个专为AI大模型对话系统设计的CDN隧道转发系统，具备：

- **高并发**: 支持10万+并发连接，50万+QPS
- **低延迟**: P99延迟 <100ms，端到端优化
- **零缓存**: 实时转发，无缓存层
- **多协议**: HTTP/1.1、HTTP/2、WebSocket、SSE、QUIC
- **主控管理**: Master统一管理多个Agent节点
- **完整CDN功能**: 负载均衡、健康检查、故障转移、安全防护
- **智能防护**: 连接保护、限流、CC防护、IP黑白名单

## 核心特性

| 特性 | 说明 |
|------|------|
| **隧道转发** | QUIC/WebSocket/TCP/TLS多协议 |
| **零缓存** | 实时转发到LLM源站 |
| **主控-被控** | Master统一管理Agent |
| **配置中心** | 版本管理、热下发 |
| **监控告警** | Prometheus集成 |
| **可视化** | Vue3管理后台 |

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     Master 主控节点                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Web API  │  │ gRPC服务 │  │ 配置中心 │  │ 监控中心 │    │
│  │ :8080    │  │ :50051   │  │ MongoDB  │  │ Prometheus│   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│  纯管理节点，不处理流量                                      │
└─────────────────────────────────────────────────────────────┘
                               │ gRPC（配置、心跳、状态上报）
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
 ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
 │ Agent 香港-1  │    │ Agent 香港-2  │    │ Agent 大陆-1  │
 │ (完整CDN节点） │    │ (完整CDN节点） │    │ (完整CDN节点） │
 │               │    │               │    │               │
 │ CDN功能：     │    │ CDN功能：     │    │ CDN功能：     │
 │ • TLS终止     │    │ • TLS终止     │    │ • TLS终止     │
 │ • 转发引擎     │    │ • 转发引擎     │    │ • 转发引擎     │
 │ • 负载均衡     │    │ • 负载均衡     │    │ • 负载均衡     │
 │ • 健康检查     │    │ • 健康检查     │    │ • 健康检查     │
 │ • 故障转移     │    │ • 故障转移     │    │ • 故障转移     │
 │ • 安全防护     │    │ • 安全防护     │    │ • 安全防护     │
 │ • 流量分发     │    │ • 流量分发     │    │ • 流量分发     │
 │               │    │               │    │               │
 │ 服务：        │    │ 服务：        │    │ 服务：        │
 │ • HTTP  :8080 │    │ • HTTP  :8080 │    │ • HTTP  :8080 │
 │ • HTTPS :8443 │    │ • HTTPS :8443 │    │ • HTTPS :8443 │
 │ • Metrics:9090│    │ • Metrics:9090│    │ • Metrics:9090│
 └───────────────┘    └───────────────┘    └───────────────┘
                               │
                               │ 负载均衡转发
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
 ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
 │ LLM源站-1     │    │ LLM源站-2     │    │ LLM源站-3     │
 │ :8000         │    │ :8000         │    │ :8000         │
 │ (健康：✅)     │    │ (健康：✅)     │    │ (健康：✅)     │
 └───────────────┘    └───────────────┘    └───────────────┘
```

### Master主控节点

- **职责：** 纯管理节点，不处理流量
- **功能：**
  - 节点注册与管理
  - 配置中心（版本管理、热下发）
  - 监控数据收集
  - 命令下发（reload、restart等）
  - HTTP API（:8080）和gRPC服务（:50051）

### Agent CDN节点

- **职责：** 完整CDN功能，处理实际流量
- **功能：**
  - **转发引擎** - HTTP/1.1、HTTP/2、WebSocket、SSE转发
  - **TLS终止** - TLS 1.3、证书管理
  - **负载均衡** - 多种策略（轮询、加权、最少连接、IP Hash）
  - **健康检查** - TCP/HTTP多层检查
  - **故障转移** - 自动故障切换与回切
  - **安全防护** - 连接保护、限流、CC防护、IP黑白名单
  - **流量分发** - 路由规则、流量分类
  - **监控指标** - Prometheus指标导出

## 快速开始

### 环境要求

| 组件 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 4核 | 16核 |
| 内存 | 4GB | 32GB |
| 磁盘 | 20GB | 100GB |
| 网络 | 100Mbps | 1Gbps |

### 1. 部署Master主控

```bash
# 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn

# 部署Master
chmod +x scripts/deploy-master.sh
sudo ./scripts/deploy-master.sh
```

### 2. 部署Agent被控

```bash
# 在被控服务器上
chmod +x scripts/deploy-agent.sh

# 部署边缘节点 (香港)
sudo ./deploy-agent.sh <Master地址>:50051 edge hk hk-node-1

# 部署核心节点 (大陆)
sudo ./deploy-agent.sh <Master地址>:50051 core cn cn-node-1
```

### 3. 访问管理后台

```bash
# 打开浏览器
http://<MasterIP>:3000

# 默认账号: admin/admin123
```

## 部署指南

### Master节点完整部署（推荐）

新脚本支持一键部署 Master + 前端 + MongoDB，无需 Docker：

```bash
# 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn

# 部署完整Master（包含前后端和数据库）
chmod +x scripts/deploy-master-full.sh
sudo ./scripts/deploy-master-full.sh

# 自定义参数部署
sudo ./scripts/deploy-master-full.sh \
    --http-port 8080 \
    --web-port 80 \
    --mongo-port 27017 \
    --mongo-user admin \
    --mongo-pass your-password

# 跳过 MongoDB 安装（使用外部数据库）
sudo ./scripts/deploy-master-full.sh --skip-mongo

# 跳过前端构建（已有构建产物）
sudo ./scripts/deploy-master-full.sh --skip-web
```

**部署完成后：**
- Web 管理界面: `http://<服务器IP>:80`
- API 接口: `http://<服务器IP>:8080`
- gRPC 接口: `<服务器IP>:50051`

### Master节点部署（仅后端）

```bash
# 进入部署目录
cd scripts

# 运行部署脚本
./deploy-master.sh

# 配置说明
# - Web API: http://localhost:8080
# - gRPC: localhost:50051
# - Prometheus: http://localhost:9091
# - Grafana: http://localhost:3000
```

### Agent节点部署

```bash
# 基本部署
./deploy-agent.sh master.ai-cdn.local:50051 edge hk

# 指定节点名
./deploy-agent.sh master.ai-cdn.local:50051 edge hk hk-node-1

# 部署核心节点
./deploy-agent.sh master.ai-cdn.local:50051 core cn cn-node-1
```

**Agent配置文件：** `/etc/ai-cdn/agent.yml`

配置示例见 `config/agent.yml.example`，包含：
- **节点配置** - ID、名称、类型、区域
- **Master连接** - 地址、TLS、超时
- **CDN服务** - HTTP/HTTPS、TLS证书
- **上游配置** - 源站地址、端口、权重
- **负载均衡** - 策略、会话粘性
- **健康检查** - 间隔、超时、阈值
- **故障转移** - 策略、重试、回切
- **安全防护** - 连接保护、限流、CC防护
- **路由规则** - 匹配规则、动作
- **监控配置** - Prometheus指标

### Docker部署

```bash
# Master
docker-compose -f config/master/docker-compose.yml up -d

# Agent
docker run -d --network host \
  -v /etc/ai-cdn:/etc/ai-cdn \
  ai-cdn-agent:latest \
  --master master.ai-cdn.local:50051 \
  --type edge --region hk
```

## 配置说明

### Master配置

```yaml
# config/master.yml
http:
  addr: :8080

grpc:
  addr: :50051

database:
  type: mongodb
  uri: mongodb://localhost:27017/ai-cdn

jwt:
  secret: your-jwt-secret
  expiration: 24h
```

### Agent配置

```yaml
# config/agent.yml
node:
  type: edge
  region: hk

master:
  addr: master.ai-cdn.local:50051
  token: your-node-token

gost:
  config_path: /etc/ai-cdn/gost.yml
```

### gost服务配置

```yaml
# config/gost-edge-hk.yml
services:
  - name: quic-edge
    addr: :443
    handler:
      type: http3
      dialer:
        type: http3
        host: ${CORE_NODE}
        port: 8443
    listener:
      type: quic
      config:
        max-incoming-streams: 10000
        congestion-control: bbr
```

## 性能优化

### 一键优化

```bash
chmod +x scripts/optimize.sh
sudo ./optimize.sh

# 重启服务使配置生效
sudo systemctl daemon-reload
sudo systemctl restart gost
```

### 手动优化

```bash
# 应用内核参数
sudo cp config/performance/sysctl.conf /etc/sysctl.conf
sudo sysctl -p

# 应用文件描述符限制
cat config/performance/limits.conf >> /etc/security/limits.conf

# 启用BBR
sudo modprobe tcp_bbr
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
```

### 性能指标

| 场景 | 连接数 | QPS | P99延迟 |
|------|--------|-----|---------|
| 基础配置 | 50,000 | 25,000 | 80ms |
| 优化后 | 100,000 | 50,000 | 45ms |

## API接口

### 节点管理

```bash
# 获取所有节点
GET /api/v1/nodes

# 获取单个节点
GET /api/v1/nodes/{id}

# 更新节点
PUT /api/v1/nodes/{id}

# 重启节点
POST /api/v1/nodes/{id}/restart

# 重载配置
POST /api/v1/nodes/{id}/reload
```

### 配置管理

```bash
# 获取配置列表
GET /api/v1/configs

# 创建配置
POST /api/v1/configs
{
  "version": "v1.0.1",
  "description": "更新配置",
  "config_data": "base64...",
  "node_type": "edge",
  "regions": ["hk"]
}

# 发布配置
POST /api/v1/configs/{version}/publish

# 回滚配置
POST /api/v1/configs/{version}/rollback
```

### 指令分发

```bash
# 执行指令
POST /api/v1/commands
{
  "command": "reload",
  "target_type": "region",
  "target_ids": ["hk"]
}

# 查看执行状态
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

## 运维管理

### 服务管理

```bash
# 查看状态
./scripts/manage.sh status

# 查看日志
./scripts/manage.sh logs

# 重启服务
./scripts/manage.sh restart

# 监控模式
./scripts/manage.sh monitor
```

### 负载均衡

```bash
# 检查节点健康
./scripts/load-balance.sh health

# 监控节点
./scripts/load-balance.sh monitor

# 生成Nginx配置
./scripts/load-balance.sh nginx
```

### 压测

```bash
# 性能压测
./scripts/benchmark.sh localhost 443 30s 1000

# 手动压测
hey -n 50000 -c 1000 -d 30s http://localhost:443
```

## 常见问题

### Q1: 连接数上不去?

```bash
# 检查文件描述符限制
ulimit -n

# 检查系统限制
sysctl net.core.somaxconn

# 检查进程限制
cat /proc/$(pgrep gost)/limits
```

### Q2: 延迟过高?

1. 检查网络拓扑
2. 启用BBR
3. 优化TLS配置
4. 增加连接池大小

### Q3: 内存使用过高?

```yaml
# 减少缓冲大小
listener:
  config:
    read-buffer-size: 32768
```

### Q4: 如何滚动更新?

```bash
# 备份配置
./scripts/manage.sh backup

# 加载新配置
./scripts/manage.sh reload

# 检查状态
./scripts/manage.sh status
```

## 文档链接

| 目录 | 说明 | 链接 |
|------|------|------|
| `docs/` | 技术文档目录 | [查看文档](docs/README.md) |
| `plans/` | 架构设计计划 | [查看计划](plans/README.md) |

### 核心文档

- [架构设计](docs/ARCHITECTURE.md) - 系统架构设计
- [部署指南](docs/DEPLOYMENT.md) - 部署步骤和配置
- [开发指南](docs/DEVELOPMENT.md) - 开发环境设置
- [安全指南](docs/SECURITY.md) - 安全配置
- [运维手册](docs/RUNBOOK.md) - 日常运维操作
- [术语表](docs/GLOSSARY.md) - 术语定义

## 项目结构

```
go-cdn/
├── cmd/                      # 命令行入口
│   ├── master/main.go       # Master主控节点
│   └── agent/main.go        # Agent被控节点
├── master/                   # Master模块
│   ├── config/              # 配置管理
│   ├── db/                  # 数据库操作
│   ├── health/              # 健康检查
│   ├── ha/                  # 高可用
│   └── node/                # 节点管理
├── agent/                    # Agent模块
│   ├── config/              # 配置
│   ├── heartbeat/           # 心跳
│   └── status/              # 状态上报
├── pkg/                      # 公共包 (30+模块)
│   ├── security/            # 安全防护
│   ├── http3/               # HTTP3服务
│   ├── monitor/             # 监控
│   └── ...
├── web-admin/               # Vue3管理后台
├── docs/                    # 技术文档
│   ├── README.md            # 文档索引
│   ├── ARCHITECTURE.md      # 架构设计
│   ├── DEPLOYMENT.md        # 部署指南
│   ├── DEVELOPMENT.md       # 开发指南
│   ├── SECURITY.md          # 安全指南
│   ├── RUNBOOK.md           # 运维手册
│   └── GLOSSARY.md          # 术语表
├── plans/                   # 设计计划
│   ├── README.md            # 计划索引
│   ├── master-agent-architecture.md  # 架构决策
│   └── ARCHIVE/             # 归档文档
└── scripts/                 # 部署脚本
```

## 许可证

MIT License

# AI CDN Tunnel - 部署指南

## 目录

- [1. 环境要求](#1-环境要求)
- [2. 部署架构](#2-部署架构)
- [3. 准备工作](#3-准备工作)
- [4. 部署 Master](#4-部署-master)
- [5. 部署 Agent](#5-部署-agent)
- [6. Docker 部署](#6-docker-部署)
- [7. 高可用部署](#7-高可用部署)
- [8. 验证部署](#8-验证部署)
- [9. 运维管理](#9-运维管理)

---

## 1. 环境要求

### 1.1 硬件要求

#### Master 节点

| 配置 | 最低 | 推荐 |
|------|------|------|
| CPU | 4 核 | 16 核 |
| 内存 | 8 GB | 32 GB |
| 磁盘 | 50 GB | 200 GB SSD |
| 网络 | 100 Mbps | 1 Gbps |

#### Agent 节点

| 配置 | 最低 | 推荐 |
|------|------|------|
| CPU | 4 核 | 8 核 |
| 内存 | 4 GB | 16 GB |
| 磁盘 | 20 GB | 50 GB SSD |
| 网络 | 100 Mbps | 1 Gbps |

### 1.2 软件要求

| 软件 | 版本要求 | 说明 |
|------|----------|------|
| Linux | Ubuntu 20.04+ / CentOS 8+ | 操作系统 |
| Go | 1.24.0 | 开发环境（仅构建时需要） |
| Docker | 20.10+ | 容器运行时 |
| Docker Compose | 2.0+ | 容器编排 |
| MongoDB | 5.0+ | 数据库 |
| Redis | 6.0+ | 缓存 |

### 1.3 网络要求

| 端口 | 协议 | 服务 | 说明 |
|------|------|------|------|
| 80 | TCP | HTTP | Web 管理界面 |
| 443 | TCP | QUIC | 边缘节点 HTTPS/QUIC |
| 8080 | TCP | HTTP | Master API |
| 50051 | TCP | gRPC | Master gRPC |
| 9090 | TCP | HTTP | Prometheus |
| 3000 | TCP | HTTP | Grafana |

---

## 2. 部署架构

### 2.1 最小部署（开发/测试）

```
┌─────────────────────────────────────┐
│           开发/测试环境              │
│  ┌──────────┐  ┌──────────┐        │
│  │  Master  │  │ Agent    │        │
│  │ :8080/   │  │ :443     │        │
│  │ :50051   │  │          │        │
│  └──────────┘  └──────────┘        │
│       │                │            │
│  ┌──────────┐         │            │
│  │ MongoDB  │         │            │
│  │ :27017   │         │            │
│  └──────────┘         │            │
└─────────────────────────────────────┘
```

### 2.2 生产部署

```
                         ┌─────────────────┐
                         │   负载均衡器     │
                         │   (Nginx/LVS)   │
                         └────────┬────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
         ▼                        ▼                        ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│  Master #1    │       │  Master #2    │       │  Master #3    │
│   (Leader)    │◄─────►│   (Follower)  │◄─────►│   (Follower)  │
│  ┌─────────┐  │       │  ┌─────────┐  │       │  ┌─────────┐  │
│  │ MongoDB │  │       │  │ MongoDB │  │       │  │ MongoDB │  │
│  │(Replica │  │       │  │(Replica │  │       │  │(Replica │  │
│  │  Set)   │  │       │  │  Set)   │  │       │  │  Set)   │  │
│  └─────────┘  │       │  └─────────┘  │       │  └─────────┘  │
└───────────────┘       └───────────────┘       └───────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
      ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
      │Agent HK-1 Edge│   │Agent HK-2 Edge│   │Agent CN-1 Core│
      │   :443/8080   │   │   :443/8080   │   │   :8443/8444  │
      └───────────────┘   └───────────────┘   └───────────────┘
```

---

## 3. 准备工作

### 3.1 系统准备

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装必要工具
sudo apt install -y curl wget git unzip apt-transport-https ca-certificates

# 禁用防火墙（或者配置放行端口）
sudo ufw disable
# 或放行必要端口
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 50051/tcp
sudo ufw allow 9090/tcp
sudo ufw allow 3000/tcp
sudo ufw enable
```

### 3.2 安装 Docker

```bash
# 安装 Docker
curl -fsSL https://get.docker.com | sh

# 安装 Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 启动 Docker
sudo systemctl enable docker
sudo systemctl start docker

# 添加当前用户到 docker 组
sudo usermod -aG docker $USER
```

### 3.3 克隆项目

```bash
# 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn
```

### 3.4 构建项目

```bash
# 构建所有组件
make build

# 或分别构建
make build-master
make build-agent
make build-cdn
```

---

## 4. 部署 Master

### 4.1 快速部署（单节点）

```bash
# 运行部署脚本
chmod +x scripts/deploy-master.sh
sudo ./scripts/deploy-master.sh
```

### 4.2 完整部署（推荐）

```bash
# 运行完整部署脚本
chmod +x scripts/deploy-master-full.sh
sudo ./scripts/deploy-master-full.sh
```

### 4.3 自定义参数部署

```bash
# 指定端口部署
sudo ./scripts/deploy-master-full.sh \
    --http-port 8080 \
    --web-port 80 \
    --mongo-port 27017 \
    --mongo-user admin \
    --mongo-pass your-secure-password

# 跳过 MongoDB 安装（使用外部数据库）
sudo ./scripts/deploy-master-full.sh --skip-mongo

# 跳过前端构建（已有构建产物）
sudo ./scripts/deploy-master-full.sh --skip-web
```

### 4.4 Docker Compose 部署

```yaml
# config/master/docker-compose.yml
version: '3.8'

services:
  master:
    image: ai-cdn-master:latest
    container_name: ai-cdn-master
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "50051:50051"
      - "9090:9090"
    volumes:
      - ./config/master.yml:/etc/ai-cdn/master.yml:ro
      - ./certs:/etc/ai-cdn/certs:ro
      - master-data:/data
    environment:
      - MONGO_URI=mongodb://mongo:27017/ai-cdn
      - REDIS_ADDR=redis:6379
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - mongo
      - redis
    networks:
      - ai-cdn-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mongo:
    image: mongo:7
    container_name: ai-cdn-mongo
    restart: unless-stopped
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
      - ./config/mongo/mongod.conf:/etc/mongod.conf:ro
    networks:
      - ai-cdn-network
    command: mongod --config /etc/mongod.conf

  redis:
    image: redis:7-alpine
    container_name: ai-cdn-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - ai-cdn-network
    command: redis-server --appendonly yes

  prometheus:
    image: prom/prometheus:v2.48
    container_name: ai-cdn-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
    networks:
      - ai-cdn-network

  grafana:
    image: grafana/grafana:10
    container_name: ai-cdn-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./config/grafana/provisioning:/etc/grafana/provisioning:ro
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    networks:
      - ai-cdn-network

volumes:
  master-data:
  mongo-data:
  redis-data:
  prometheus-data:
  grafana-data:

networks:
  ai-cdn-network:
    driver: bridge
```

```bash
# 启动服务
cd config/master
docker-compose up -d

# 查看状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 4.5 配置 Master

```yaml
# config/master.yml
# Master 主配置

# HTTP 服务配置
http:
  addr: :8080
  read_timeout: 30s
  write_timeout: 30s

# gRPC 服务配置
grpc:
  addr: :50051
  max_recv_msg_size: 4194304  # 4MB
  max_send_msg_size: 4194304

# 数据库配置
database:
  type: mongodb
  uri: mongodb://localhost:27017/ai-cdn
  pool_size: 100
  max_conn_idle: 5m

# Redis 配置
redis:
  addr: localhost:6379
  password: ""
  db: 0
  pool_size: 100

# JWT 认证
jwt:
  secret: "${JWT_SECRET}"
  expiration: 24h
  refresh_expiration: 168h

# 监控配置
monitor:
  enabled: true
  interval: 10s
  retention: 7d

# 告警配置
alerts:
  enabled: true
  rules_file: /etc/ai-cdn/rules/ai-cdn-alerts.yml

# 日志配置
logging:
  level: info
  format: json
  output: file
```

---

## 5. 部署 Agent

### 5.1 快速部署

```bash
# 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn/scripts

# 部署边缘节点（香港）
chmod +x deploy-agent.sh
sudo ./deploy-agent.sh <Master地址>:50051 edge hk <节点名>

# 示例
sudo ./deploy-agent.sh 192.168.1.100:50051 edge hk hk-node-1

# 部署核心节点（大陆）
sudo ./deploy-agent.sh 192.168.1.100:50051 core cn cn-node-1
```

### 5.2 参数说明

```bash
./deploy-agent.sh <Master地址> <节点类型> <地区> <节点名称>

参数说明:
  Master地址   Master节点的gRPC地址 (如: 192.168.1.100:50051)
  节点类型     edge (边缘节点) 或 core (核心节点)
  地区         节点所在地区 (如: hk, cn, us, sg)
  节点名称     自定义节点名称 (可选，自动生成)
```

### 5.3 Docker 部署 Agent

```yaml
# config/agent/docker-compose.yml
version: '3.8'

services:
  agent:
    image: ai-cdn-agent:latest
    container_name: ai-cdn-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config/agent.yml:/etc/ai-cdn/agent.yml:ro
      - ./config/gost-edge-hk.yml:/etc/ai-cdn/gost.yml:ro
      - ./certs:/etc/ai-cdn/certs:ro
      - agent-data:/data
    environment:
      - MASTER_ADDR=${MASTER_ADDR}
      - NODE_TYPE=${NODE_TYPE}
      - REGION=${REGION}
      - NODE_NAME=${NODE_NAME}
      - TOKEN=${AGENT_TOKEN}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9090/metrics"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  agent-data:

# 环境变量文件 .env
# MASTER_ADDR=192.168.1.100:50051
# NODE_TYPE=edge
# REGION=hk
# NODE_NAME=hk-agent-1
# AGENT_TOKEN=your-agent-token
```

```bash
# 启动 Agent
cd config/agent
docker-compose up -d
```

### 5.4 配置 Agent

```yaml
# config/agent.yml
# Agent 配置

# Master 连接
master:
  addr: 192.168.1.100:50051
  token: "${AGENT_TOKEN}"
  dial_timeout: 10s
  max_retries: 3

# 节点信息
node:
  type: edge        # edge | core
  region: hk        # hk | cn | us | sg
  name: hk-agent-1  # 可选，自动生成

# gost 配置
gost:
  config_path: /etc/ai-cdn/gost.yml

# 心跳配置
heartbeat:
  interval: 10s
  timeout: 30s

# 状态上报
status:
  collect_interval: 10s
  report_interval: 10s

# 监控配置
monitor:
  enabled: true
  addr: :9090
```

### 5.5 边缘节点 gost 配置

```yaml
# config/gost-edge-hk.yml
# 边缘节点配置 - 香港

# 全局配置
global:
  log-level: info
  api-addr: :18080
  metrics-addr: :9090

# 服务定义
services:
  # QUIC 监听 - 主要协议
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
        max-idle-timeout: 300s
        max-incoming-streams: 10000
        alpn: [h3, h3-32, h3-31]
    # 限流
    limiter:
      name: rate-limiter
      config:
        global:
          rate: 50000/s
          burst: 100000

  # WebSocket 兼容
  - name: ws-edge
    addr: :8080
    handler:
      type: http
      dialer:
        type: http
        host: ${CORE_NODE_IP}
        port: 8080
    listener:
      type: ws
      config:
        read-buffer-size: 65536
        write-buffer-size: 65536

# TLS 配置
tls:
  cert-file: /etc/ai-cdn/certs/server.crt
  key-file: /etc/ai-cdn/certs/server.key
```

---

## 6. Docker 部署

### 6.1 构建镜像

```bash
# 构建 Master 镜像
make docker-build-master

# 构建 Agent 镜像
make docker-build-agent

# 构建 CDN 镜像
make docker-build-cdn

# 推送镜像到仓库
make docker-push
```

### 6.2 Docker Compose 完整部署

```yaml
# docker-compose.yml
version: '3.8'

services:
  master:
    image: ai-cdn/master:latest
    container_name: ai-cdn-master
    restart: unless-stopped
    ports:
      - "80:80"
      - "8080:8080"
      - "50051:50051"
      - "9090:9090"
      - "3000:3000"
    volumes:
      - ./config/master.yml:/etc/ai-cdn/master.yml:ro
      - ./certs:/etc/ai-cdn/certs:ro
      - master-data:/data
      - prometheus-data:/prometheus
      - grafana-data:/var/lib/grafana
    environment:
      - MONGO_URI=mongodb://mongo:27017/ai-cdn
      - REDIS_ADDR=redis:6379
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - mongo
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mongo:
    image: mongo:7
    restart: unless-stopped
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis-data:/data

  agent-hk:
    image: ai-cdn/agent:latest
    container_name: ai-cdn-agent-hk
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config/agent-edge-hk.yml:/etc/ai-cdn/agent.yml:ro
      - ./config/gost-edge-hk.yml:/etc/ai-cdn/gost.yml:ro
      - ./certs:/etc/ai-cdn/certs:ro
    environment:
      - MASTER_ADDR=${MASTER_ADDR}
      - NODE_TYPE=edge
      - REGION=hk
      - TOKEN=${AGENT_TOKEN}

volumes:
  master-data:
  mongo-data:
  redis-data:
  prometheus-data:
  grafana-data:
```

```bash
# 启动所有服务
docker-compose up -d

# 查看状态
docker-compose ps

# 查看日志
docker-compose logs -f master
docker-compose logs -f agent-hk
```

---

## 7. 高可用部署

### 7.1 Master 高可用

```yaml
# config/master-ha/docker-compose.yml
version: '3.8'

services:
  master-1:
    image: ai-cdn/master:latest
    container_name: ai-cdn-master-1
    restart: unless-stopped
    ports:
      - "8081:8080"
      - "50052:50051"
    volumes:
      - ./master-1/master.yml:/etc/ai-cdn/master.yml:ro
      - master-1-data:/data
    environment:
      - MONGO_URI=mongodb://mongo:27017/ai-cdn
      - REDIS_ADDR=redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - NODE_ID=master-1
    depends_on:
      - mongo
      - redis

  master-2:
    image: ai-cdn/master:latest
    container_name: ai-cdn-master-2
    restart: unless-stopped
    ports:
      - "8082:8080"
      - "50053:50051"
    volumes:
      - ./master-2/master.yml:/etc/ai-cdn/master.yml:ro
      - master-2-data:/data
    environment:
      - MONGO_URI=mongodb://mongo:27017/ai-cdn
      - REDIS_ADDR=redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - NODE_ID=master-2
    depends_on:
      - mongo
      - redis

  master-3:
    image: ai-cdn/master:latest
    container_name: ai-cdn-master-3
    restart: unless-stopped
    ports:
      - "8083:8080"
      - "50054:50051"
    volumes:
      - ./master-3/master.yml:/etc/ai-cdn/master.yml:ro
      - master-3-data:/data
    environment:
      - MONGO_URI=mongodb://mongo:27017/ai-cdn
      - REDIS_ADDR=redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - NODE_ID=master-3
    depends_on:
      - mongo
      - redis

  # MongoDB Replica Set
  mongo-1:
    image: mongo:7
    restart: unless-stopped
    ports:
      - "27017:27017"
    volumes:
      - mongo-1-data:/data/db
    command: mongod --replSet rs0 --bind_ip_all
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes

volumes:
  master-1-data:
  master-2-data:
  master-3-data:
  mongo-1-data:
  redis-data:
```

### 7.2 初始化 MongoDB Replica Set

```javascript
// 连接到任意 MongoDB 节点
// 初始化 Replica Set

rs.initiate({
  _id: "rs0",
  members: [
    { _id: 0, host: "mongo-1:27017" },
    // 添加更多成员
  ]
});
```

### 7.3 Nginx 负载均衡配置

```nginx
# /etc/nginx/conf.d/ai-cdn-master.conf
upstream ai_cdn_master {
    least_conn;
    server 192.168.1.100:8081 weight=1;
    server 192.168.1.100:8082 weight=1;
    server 192.168.1.100:8083 weight=1;
}

upstream ai_cdn_grpc {
    least_conn;
    server 192.168.1.100:50052 weight=1;
    server 192.168.1.100:50053 weight=1;
    server 192.168.1.100:50054 weight=1;
}

# HTTP API
server {
    listen 80;
    server_name api.ai-cdn.local;

    location / {
        proxy_pass http://ai_cdn_master;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## 8. 验证部署

### 8.1 检查 Master 服务

```bash
# 检查 HTTP API
curl http://localhost:8080/health

# 检查 gRPC
grpcurl -plaintext localhost:50051 list

# 检查 Prometheus
curl http://localhost:9090/api/v1/query?query=up

# 检查 Grafana
curl -u admin:admin123 http://localhost:3000/api/health
```

### 8.2 检查 Agent 服务

```bash
# 检查 Agent 进程
systemctl status ai-cdn-agent

# 检查 gost 服务
systemctl status gost

# 检查日志
journalctl -u ai-cdn-agent -f
journalctl -u gost -f

# 检查连接数
ss -s

# 检查端口监听
netstat -tlnp | grep -E '443|8080'
```

### 8.3 端到端测试

```bash
# 1. 检查节点注册
curl http://localhost:8080/api/v1/nodes

# 2. 检查节点状态
curl http://localhost:8080/api/v1/nodes/<node-id>

# 3. 测试配置下发
curl -X POST http://localhost:8080/api/v1/configs \
  -H "Content-Type: application/json" \
  -d '{"version":"v1.0.1","config_type":"test"}'

# 4. 测试指令执行
curl -X POST http://localhost:8080/api/v1/commands \
  -H "Content-Type: application/json" \
  -d '{"command":"status","target_type":"all"}'
```

### 8.4 性能测试

```bash
# 连接数测试
hey -n 10000 -c 100 -m GET http://localhost:8080/health

# API 性能测试
wrk -t10 -c100 -d30s http://localhost:8080/api/v1/nodes

# QUIC 性能测试
# 使用 h2load 或专门工具
```

---

## 9. 运维管理

### 9.1 服务管理

```bash
# Master 服务
sudo systemctl status ai-cdn-master
sudo systemctl restart ai-cdn-master
sudo systemctl stop ai-cdn-master

# Agent 服务
sudo systemctl status ai-cdn-agent
sudo systemctl restart ai-cdn-agent
sudo systemctl stop ai-cdn-agent

# gost 服务
sudo systemctl status gost
sudo systemctl restart gost
```

### 9.2 日志管理

```bash
# 查看 Master 日志
tail -f /var/log/ai-cdn/master.log

# 查看 Agent 日志
tail -f /var/log/ai-cdn/agent.log

# 查看 gost 日志
journalctl -u gost -f

# 日志轮转
# /etc/logrotate.d/ai-cdn
/var/log/ai-cdn/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
```

### 9.3 备份恢复

```bash
# MongoDB 备份
mongodump --uri="mongodb://localhost:27017/ai-cdn" \
  --out=/backup/ai-cdn-$(date +%Y%m%d)

# MongoDB 恢复
mongorestore --uri="mongodb://localhost:27017/ai-cdn" \
  /backup/ai-cdn-20240101

# Redis 备份
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb /backup/redis-$(date +%Y%m%d).rdb

# 配置备份
tar czf /backup/config-$(date +%Y%m%d).tar.gz /etc/ai-cdn/
```

### 9.4 升级更新

```bash
# 1. 备份数据
./scripts/manage.sh backup

# 2. 下载新版本
cd /opt
wget https://github.com/tyqy12/go-cdn/releases/download/v1.x.x/go-cdn-v1.x.x-linux-amd64.tar.gz
tar xzf go-cdn-v1.x.x-linux-amd64.tar.gz

# 3. 停止服务
sudo systemctl stop ai-cdn-master
sudo systemctl stop ai-cdn-agent

# 4. 更新二进制
sudo cp go-cdn-master /usr/local/bin/
sudo cp go-cdn-agent /usr/local/bin/

# 5. 重启服务
sudo systemctl start ai-cdn-master
sudo systemctl start ai-cdn-agent

# 6. 验证
./scripts/manage.sh status
```

### 9.5 监控检查

```bash
# 检查节点状态
./scripts/manage.sh status

# 检查负载均衡
./scripts/load-balance.sh health

# 生成报告
./scripts/manage.sh report

# 性能压测
./scripts/benchmark.sh localhost 443 30s 1000
```

---

## 附录

### A. 常用命令速查

| 操作 | 命令 |
|------|------|
| 启动 Master | `sudo systemctl start ai-cdn-master` |
| 停止 Master | `sudo systemctl stop ai-cdn-master` |
| 重启 Master | `sudo systemctl restart ai-cdn-master` |
| 查看状态 | `sudo systemctl status ai-cdn-master` |
| 查看日志 | `journalctl -u ai-cdn-master -f` |
| 检查健康 | `curl http://localhost:8080/health` |

### B. 目录结构

```
/etc/ai-cdn/
├── master/
│   ├── master.yml
│   └── certs/
├── agent/
│   ├── agent.yml
│   ├── gost.yml
│   └── certs/
├── logs/
│   ├── master.log
│   └── agent.log
└── rules/
    └── ai-cdn-alerts.yml

/var/log/ai-cdn/
├── master.log
├── agent.log
└── audit.log
```

### C. 故障排查

| 问题 | 解决方案 |
|------|----------|
| Master 无法启动 | 检查 MongoDB 连接，检查端口占用 |
| Agent 无法连接 Master | 检查网络，验证 Token |
| gRPC 超时 | 调整 keepalive 参数 |
| 内存使用过高 | 检查 goroutine 泄漏，优化配置 |
| 磁盘空间不足 | 清理日志，扩容磁盘 |

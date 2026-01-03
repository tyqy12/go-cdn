# AI CDN Tunnel - 部署指南

基于 gost v3 的高并发 AI 对话 CDN 系统

## 目录

- [架构概览](#架构概览)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [部署步骤](#部署步骤)
- [多节点部署](#多节点部署)
- [监控运维](#监控运维)
- [性能调优](#性能调优)
- [常见问题](#常见问题)

## 架构概览

```
客户端 → CDN边缘节点(香港) → CDN核心节点(大陆) → LLM源站
         ↓
    QUIC/WebSocket/HTTP
         ↓
    TLS卸载 + 零缓存 + 限流
```

## 快速开始

### 1. 克隆项目

```bash
git clone https://your-repo/ai-cdn-tunnel.git
cd ai-cdn-tunnel
```

### 2. 配置环境

```bash
# 复制环境配置
cp config/env.example .env

# 编辑配置
vim .env

# 主要配置项:
# NODE_TYPE=edge           # edge:边缘节点, core:核心节点
# REGION=hk                # 地区代码
# LLM_SOURCE_HOST=xxx      # LLM服务地址
# API_KEYS=sk-xxx          # API密钥
```

### 3. 一键部署

```bash
# 部署边缘节点 (香港)
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh --node-type edge --region hk

# 部署核心节点 (大陆)
sudo ./scripts/deploy.sh --node-type core --region cn
```

## 配置说明

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `NODE_TYPE` | edge | 节点类型: edge/core |
| `LISTEN_QUIC` | :443 | QUIC监听端口 |
| `LISTEN_WS` | :8080 | WebSocket端口 |
| `LISTEN_HTTP` | :80 | HTTP端口 |
| `CORE_NODE_HOST` | - | 核心节点地址 |
| `LLM_SOURCE_HOST` | - | LLM源站地址 |
| `LLM_SOURCE_PORT` | 8000 | LLM源站端口 |
| `API_KEYS` | - | API密钥列表 |
| `RATE_LIMIT_GLOBAL` | 50000 | 全局限流(QPS) |
| `MAX_CONNECTIONS` | 100000 | 最大连接数 |

### 配置文件

#### 边缘节点 (gost-edge-hk.yml)
- 监听客户端连接
- TLS卸载
- 协议转换
- 基础限流

#### 核心节点 (gost-core-cn.yml)
- 转发到LLM源站
- 认证授权
- 流量控制

## 部署步骤

### 单节点部署

```bash
# 1. 安装依赖
sudo apt-get update
sudo apt-get install -y curl wget openssl

# 2. 运行部署脚本
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh --node-type edge --region hk

# 3. 检查状态
./scripts/manage.sh status

# 4. 查看日志
./scripts/manage.sh logs
```

### 多节点部署

```bash
# 香港边缘节点 1
ssh hk-node-1
sudo ./scripts/deploy.sh --node-type edge --region hk --config-dir /etc/gost-hk1

# 香港边缘节点 2
ssh hk-node-2
sudo ./scripts/deploy.sh --node-type edge --region hk --config-dir /etc/gost-hk2

# 大陆核心节点
ssh cn-node-1
sudo ./scripts/deploy.sh --node-type core --region cn --config-dir /etc/gost-cn
```

### Kubernetes 部署

```bash
# 部署边缘节点
kubectl apply -f k8s/edge/

# 部署核心节点
kubectl apply -f k8s/core/

# 检查状态
kubectl get pods -l app=gost
```

## 监控运维

### 监控指标

| 指标 | 说明 |
|------|------|
| `gost_connections_active` | 活跃连接数 |
| `gost_requests_total` | 总请求数 |
| `gost_request_duration_seconds` | 请求延迟 |
| `gost_sse_connections_active` | SSE连接数 |
| `gost_upstream_latency_seconds` | 上游延迟 |

### 查看监控

```bash
# 实时监控
./scripts/manage.sh monitor

# Prometheus指标
curl http://localhost:9090/metrics

# Grafana (如已安装)
# 访问 http://localhost:3000
```

### 告警配置

告警规则位于 `config/rules/ai-cdn-alerts.yml`：

- 高连接数: >80,000
- 高延迟P99: >100ms
- 错误率: >1%
- 资源使用: CPU/Memory >80%

### 日志管理

```bash
# 查看日志
journalctl -u gost -f

# 日志文件
tail -f /var/log/gost/gost.log

# 日志级别调整
# 修改 .env 中的 LOG_LEVEL=debug
```

## 性能调优

### 系统参数

```bash
# TCP优化
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.ipv4.tcp_congestion_control=bbr

# 文件描述符
ulimit -n 1048576
```

### gost配置优化

```yaml
# 调整并发参数
services:
  - name: quic-edge
    handler:
      type: http3
    listener:
      type: quic
      config:
        max-incoming-streams: 10000  # 增加并发流
```

### 资源分配

```bash
# GOMAXPROCS
export GOMAXPROCS=16

# GC调优
export GOGC=50

# 内存限制
# 在systemd服务中设置 MemoryMax=8G
```

## 常见问题

### Q1: 连接数上不去？

检查系统限制:
```bash
# 查看当前限制
ulimit -n

# 临时提升
ulimit -n 1048576

# 永久修改
echo "* soft nofile 1048576" >> /etc/security/limits.conf
```

### Q2: 延迟过高？

1. 检查网络拓扑
2. 优化TLS配置
3. 启用BBR拥塞控制
4. 增加连接池大小

### Q3: 内存使用过高？

```yaml
# 减少缓冲大小
listener:
  type: quic
  config:
    read-buffer-size: 32768  # 从65536减少
```

### Q4: 如何滚动更新？

```bash
# 1. 备份配置
./scripts/manage.sh backup

# 2. 加载新配置
./scripts/manage.sh reload

# 3. 检查状态
./scripts/manage.sh status
```

## 性能基准

| 配置 | 并发连接 | QPS | P99延迟 |
|------|----------|-----|---------|
| 8核16GB | 50,000 | 20,000 | 50ms |
| 16核32GB | 100,000 | 50,000 | 40ms |
| 32核64GB | 200,000 | 100,000 | 35ms |

## 许可证

MIT License

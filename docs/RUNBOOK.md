# AI CDN Tunnel - 运维手册

> 本手册面向运维人员，包含日常运维操作、故障排查和服务管理。

## 目录

- [1. 服务管理](#1-服务管理)
- [2. 日志管理](#2-日志管理)
- [3. 备份恢复](#3-备份恢复)
- [4. 升级更新](#4-升级更新)
- [5. 监控检查](#5-监控检查)
- [6. 故障排查](#6-故障排查)
- [7. 常用命令速查](#7-常用命令速查)

---

## 1. 服务管理

### 1.1 Master 服务

```bash
# 查看状态
sudo systemctl status ai-cdn-master

# 启动服务
sudo systemctl start ai-cdn-master

# 停止服务
sudo systemctl stop ai-cdn-master

# 重启服务
sudo systemctl restart ai-cdn-master

# 查看实时日志
journalctl -u ai-cdn-master -f
```

### 1.2 Agent 服务

```bash
# 查看状态
sudo systemctl status ai-cdn-agent

# 启动服务
sudo systemctl start ai-cdn-agent

# 停止服务
sudo systemctl stop ai-cdn-agent

# 重启服务
sudo systemctl restart ai-cdn-agent

# 查看实时日志
journalctl -u ai-cdn-agent -f
```

### 1.3 gost 服务

```bash
# 查看状态
sudo systemctl status gost

# 启动服务
sudo systemctl start gost

# 停止服务
sudo systemctl stop gost

# 重启服务
sudo systemctl restart gost

# 查看实时日志
journalctl -u gost -f
```

---

## 2. 日志管理

### 2.1 日志位置

| 服务 | 日志路径 |
|------|----------|
| Master | `/var/log/ai-cdn/master.log` |
| Agent | `/var/log/ai-cdn/agent.log` |
| gost | `journalctl -u gost` |

### 2.2 查看日志

```bash
# 查看 Master 日志
tail -f /var/log/ai-cdn/master.log

# 查看 Agent 日志
tail -f /var/log/ai-cdn/agent.log

# 查看 gost 日志
journalctl -u gost -f
```

### 2.3 日志轮转配置

```bash
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

---

## 3. 备份恢复

### 3.1 MongoDB 备份

```bash
# 备份
mongodump --uri="mongodb://localhost:27017/ai-cdn" \
  --out=/backup/ai-cdn-$(date +%Y%m%d)

# 恢复
mongorestore --uri="mongodb://localhost:27017/ai-cdn" \
  /backup/ai-cdn-20240101
```

### 3.2 Redis 备份

```bash
# 触发备份
redis-cli BGSAVE

# 备份文件
cp /var/lib/redis/dump.rdb /backup/redis-$(date +%Y%m%d).rdb
```

### 3.3 配置备份

```bash
# 备份配置
tar czf /backup/config-$(date +%Y%m%d).tar.gz /etc/ai-cdn/
```

---

## 4. 升级更新

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

---

## 5. 监控检查

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

### 5.1 健康检查

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

### 5.2 Agent 检查

```bash
# 检查 Agent 进程
systemctl status ai-cdn-agent

# 检查 gost 服务
systemctl status gost

# 检查连接数
ss -s

# 检查端口监听
netstat -tlnp | grep -E '443|8080'
```

---

## 6. 故障排查

### 6.1 常见问题

| 问题 | 解决方案 |
|------|----------|
| Master 无法启动 | 检查 MongoDB 连接，检查端口占用 |
| Agent 无法连接 Master | 检查网络，验证 Token |
| gRPC 超时 | 调整 keepalive 参数 |
| 内存使用过高 | 检查 goroutine 泄漏，优化配置 |
| 磁盘空间不足 | 清理日志，扩容磁盘 |

### 6.2 诊断命令

```bash
# 检查端口占用
netstat -tlnp | grep -E '8080|50051|443'

# 检查进程状态
ps aux | grep ai-cdn

# 检查系统资源
top -bn1 | head -20

# 检查内存使用
free -h

# 检查磁盘空间
df -h
```

### 6.3 网络诊断

```bash
# 测试 Master 连通性
telnet localhost 50051

# 测试 Agent 连通性
telnet <master-ip> 50051

# 检查 DNS 解析
nslookup master.example.com

# 检查路由
traceroute master.example.com
```

---

## 7. 常用命令速查

| 操作 | 命令 |
|------|------|
| 启动 Master | `sudo systemctl start ai-cdn-master` |
| 停止 Master | `sudo systemctl stop ai-cdn-master` |
| 重启 Master | `sudo systemctl restart ai-cdn-master` |
| 查看状态 | `sudo systemctl status ai-cdn-master` |
| 查看日志 | `journalctl -u ai-cdn-master -f` |
| 检查健康 | `curl http://localhost:8080/health` |

---

## 附录 A: 目录结构

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

---

## 附录 B: 端口说明

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

*最后更新: 2026-01-13*

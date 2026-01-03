# AI CDN Tunnel - 性能调优指南

## 目录

- [性能目标](#性能目标)
- [系统优化](#系统优化)
- [Go运行时优化](#go运行时优化)
- [gost性能配置](#gost性能配置)
- [网络优化](#网络优化)
- [数据库优化](#数据库优化)
- [前端性能优化](#前端性能优化)
- [监控与压测](#监控与压测)

## 性能目标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 并发连接数 | 100,000+ | 单节点 |
| QPS | 50,000+ | 全节点 |
| P99延迟 | < 100ms | 端到端 |
| 可用性 | 99.9% | SLA |
| 内存使用 | < 8GB | 单节点 |

## 系统优化

### 1. 应用内核参数

```bash
# 备份当前配置
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak

# 应用优化配置
sudo cp config/performance/sysctl.conf /etc/sysctl.conf
sudo sysctl -p

# 验证配置
sysctl net.core.somaxconn
sysctl net.ipv4.tcp_congestion_control
```

### 2. 应用文件描述符限制

```bash
# 备份当前配置
sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak

# 应用限制配置
sudo cp config/performance/limits.conf /etc/security/limits.conf

# 验证
ulimit -n
```

### 3. 禁用透明大页(可选)

```bash
# 检查当前状态
cat /sys/kernel/mm/transparent_hugepage/enabled

# 禁用(临时)
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

# 永久禁用 - 添加到/etc/rc.local
```

### 4. CPU性能模式

```bash
# 查看当前模式
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 设置为性能模式
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo "performance" | sudo tee $cpu
done
```

## Go运行时优化

### 1. 环境变量配置

在 systemd 服务中配置:

```ini
[Service]
Environment=GOMAXPROCS=16
Environment=GOGC=50
Environment=GODEBUG=gctrace=0
```

### 2. 参数说明

| 参数 | 推荐值 | 说明 |
|------|--------|------|
| GOMAXPROCS | CPU核心数 | 控制并发线程数 |
| GOGC | 50-100 | GC触发阈值, 值越大GC越少 |
| GODEBUG | gctrace=0 | 生产环境关闭GC日志 |

### 3. 内存限制

```ini
[Service]
# 内存限制
MemoryMax=8G
MemoryHigh=6G
MemorySwapMax=0
```

## gost性能配置

### 1. 配置文件

使用优化配置:

```bash
# 复制优化配置
cp config/performance/gost-performance.yml /etc/gost/gost.yml

# 或使用环境变量覆盖
export GOST_MAX_CONNECTIONS=100000
export GOST_QUIC_STREAMS=10000
```

### 2. 关键配置

```yaml
# QUIC优化
listener:
  type: quic
  config:
    max-incoming-streams: 10000
    congestion-control: bbr
    enable-0rtt: true

# 连接池
handler:
  dialer:
    config:
      max-idle-conns: 10000
      max-idle-conns-per-host: 1000
```

### 3. systemd服务优化

```ini
[Service]
# CPU亲和性
CPUAffinity=0,1,2,3,4,5,6,7

# 优先级
Nice=-10
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=50

# 资源限制
LimitNOFILE=1048576
LimitNPROC=65536

# 内存
MemoryMax=8G
MemoryHigh=6G
```

## 网络优化

### 1. TCP优化

```bash
# 启用BBR
sudo modprobe tcp_bbr
sudo echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
sudo echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
sudo sysctl -p
```

### 2. 网络接口优化

```bash
# 禁用TCP Segmentation Offload (如果不需要)
ethtool -K eth0 tso off
ethtool -K eth0 gso off

# 启用自适应中断调节
ethtool -C eth0 adaptive-rx on adaptive-tx on
```

### 3. 连接跟踪优化

```bash
# 增加连接跟踪表大小
echo "net.netfilter.nf_conntrack_max=1048576" >> /etc/sysctl.conf
echo "net.netfilter.nf_conntrack_tcp_timeout_established=3600" >> /etc/sysctl.conf
sysctl -p
```

## 数据库优化

### 1. MongoDB优化

```yaml
# docker-compose.yml
mongo:
  command: mongod 
    --wiredTigerCacheSizeGB 2
    --wiredTigerJournalCompressor none
    --noIndexBuildRetry
    --disableTransparentHugePages
  deploy:
    resources:
      limits:
        memory: 4G
      reservations:
        memory: 2G
```

### 2. Redis优化

```yaml
# docker-compose.yml
redis:
  command: redis-server 
    --maxmemory 2gb
    --maxmemory-policy allkeys-lru
    --appendonly no
    --tcp-keepalive 300
```

### 3. 连接池配置

```go
// Master配置
database:
  pool_size: 100
  max_conn_idle: 5m

redis:
  pool_size: 100
  min_idle_conns: 10
```

## 前端性能优化

### 1. Vite构建优化

```javascript
// vite.config.js
export default defineConfig({
  build: {
    // 代码分割
    rollupOptions: {
      output: {
        manualChunks: {
          'element-plus': ['element-plus'],
          'echarts': ['echarts'],
          'vendor': ['vue', 'vue-router', 'pinia']
        }
      }
    },
    // 压缩
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    }
  },
  // 预构建
  optimizeDeps: {
    include: ['element-plus', 'echarts']
  }
})
```

### 2. 组件懒加载

```javascript
// router/index.js
const routes = [
  {
    path: '/',
    component: () => import('../views/Dashboard.vue')
    // 路由预读取
    // component: () => import(/* webpackPrefetch: true */ '../views/Dashboard.vue')
  }
]
```

### 3. 资源压缩

```javascript
// vite.config.js
import gzipPlugin from 'vite-plugin-gzip'

export default defineConfig({
  plugins: [
    gzipPlugin({
      customCompressFilename: /\.(js|css|html|svg)$/,
      algorithm: 'gzip',
      threshold: 10240
    })
  ]
})
```

## 监控与压测

### 1. 监控指标

```yaml
# 关键指标
- connections_active: 活跃连接数
- request_duration_seconds: 请求延迟
- requests_total: 请求总数
- go_gc_duration_seconds: GC耗时
- go_goroutines: 协程数
- process_resident_memory_bytes: 内存使用
```

### 2. 压测工具

```bash
# 使用hey进行压测
hey -n 100000 -c 1000 -m GET http://localhost:443

# 使用wrk进行压测
wrk -t10 -c1000 -d30s http://localhost:443

# QUIC压测
# 使用h2load或vegeta
```

### 3. 性能测试脚本

```bash
#!/bin/bash
# scripts/benchmark.sh

echo "=== 连接数测试 ==="
hey -n 10000 -c 100 -m GET http://localhost:8080/health

echo "=== 吞吐量测试 ==="
wrk -t10 -c500 -d30s http://localhost:8080/api/v1/nodes

echo "=== 并发测试 ==="
hey -n 50000 -c 2000 -m GET http://localhost:443
```

## 性能基线

### 单节点性能(8核16GB)

| 场景 | 连接数 | QPS | P99延迟 |
|------|--------|-----|---------|
| QUIC | 50,000 | 25,000 | 45ms |
| WebSocket | 80,000 | 40,000 | 55ms |
| HTTP | 100,000 | 50,000 | 35ms |

### 优化后性能(16核32GB)

| 场景 | 连接数 | QPS | P99延迟 |
|------|--------|-----|---------|
| QUIC | 100,000 | 50,000 | 40ms |
| WebSocket | 150,000 | 80,000 | 45ms |
| HTTP | 200,000 | 100,000 | 30ms |

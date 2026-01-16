# M0: 数据面形态架构决策文档

## 文档信息

| 项目 | 内容 |
|------|------|
| 文档版本 | v1.0 |
| 创建日期 | 2026-01-06 |
| 状态 | 已完成 |

---

## 1. 数据面形态决策

### 1.1 TLS终止策略

**决策：采用 **L7 代理模式（Edge终止TLS）**

| 选项 | 选择 | 理由 |
|------|------|------|
| L4 透传 | ❌ | 无法获取HTTP可见性，无法进行L7防护 |
| L7 代理 | ✅ | 可获取HTTP可见性，支持完整L7防护规则 |

**实施说明：**
```
┌───────────────────────────────────────────────────────────┐
│  Client  ──────(HTTPS)────>  Edge Node                  │
│                                     │                   │
│                                     ▼                   │
│                          ┌──────────────────────────────┐       │
│                          │  TLS Termination       │       │
│                          │  + HTTP Visibility     │       │
│                          └──────────────────────────────┘       │
│                                     │                   │
│                                     ▼                   │
│                          ┌──────────────────────────────┐       │
│                          │  L7 Security Layer       │       │
│                          │  - Rule Engine          │       │
│                          │  - Rate Limit           │       │
│                          │  - Challenge            │       │
│                          │  - Behavior Analysis      │       │
│                          └──────────────────────────────┘       │
│                                     │                   │
│                                     ▼                   │
│                          ┌──────────────────────────────┐       │
│                          │  Forward to Origin       │       │
│                          └──────────────────────────────┘       │
└───────────────────────────────────────────────────────────┘
```

---

## 2. 协议支持矩阵

| 协议 | 版本 | 支持 | 应用场景 | 说明 |
|------|------|------|----------|------|
| HTTP | 1.1, 1.2 | ✅ | 兼容旧系统 | 基础协议 |
| HTTP/2 | 2.0 | ✅ | 高性能 | 多路复用 |
| WebSocket | - | ✅ | 实时通信 | 双向通信 |
| SSE | - | ✅ | 服务端推送 | 流式响应 |
| QUIC/HTTP3 | v1 | ⚠️ | M2增强 | 低延迟传输 |
| TCP | - | ✅ | L4透传 | 无状态服务 |

**配置示例：**
```yaml
data_plane:
  tls_termination_mode: "edge"
  supported_protocols:
    - "http1.1"
    - "http2"
    - "websocket"
    - "sse"
  forward_mode: "l7_proxy"
```

---

## 3. API vs Browser 路径边界

### 3.1 挑战验证路径白名单

**原则：** API和LLM对话路径**禁止**使用JS/Captcha挑战，仅Web页面路径启用挑战。

| 业务类型 | 路径模式 | 可用挑战 | 禁用场景 | 原因 |
|----------|----------|----------|----------|------|
| Web 页面 | `/*.html`, `/*.htm`, `/static/*` | ✅ JS Challenge, Captcha | - | 浏览器可执行JS |
| 静态资源 | `/assets/*`, `/images/*` | ✅ JS Challenge | - | 浏览器可执行JS |
| API 端点 | `/api/*` | ❌ **仅限流** | SDK调用、机器对机器 | 客户端无法执行JS |
| LLM 对话 | `/v1/chat/*`, `/v1/completions/*` | ❌ **禁止所有挑战** | 客户端无法执行JS | 实时性要求高 |
| 登录认证 | `/api/login`, `/api/auth/*` | ❌ 限流+行为分析 | Captcha影响体验 | 敏感操作 |

**配置示例：**
```yaml
challenge_paths:
  enabled_paths:
    - "/*.html"
    - "/static/*"
    - "/assets/*"
  
  excluded_paths:
    - "/api/*"
    - "/v1/chat/*"
    - "/v1/completions/*"
    - "/api/health"
    - "/api/public"
  
  default_action: "allow"
```

### 3.2 路径防护策略

| 路径类型 | 防护策略 | 原因 |
|----------|----------|------|
| `/*.html` | 挑战验证+限流 | 浏览器可执行JS |
| `/api/v1/chat/*` | 限流+行为分析 | 禁止挑战，保证可用性 |
| `/api/login` | 限流+行为分析+暴力破解防护 | 敏感操作，禁止Captcha |
| `/api/payment/*` | 限流+行为分析+风控 | 金融操作 |
| `/api/admin/*` | IP白名单+限流 | 管理路径 |
| `/api/health` | 无限流 | 健康检查 |

---

## 4. 高防牵引与清洗数据面闭环

### 4.1 数据面拓扑

**两条数据面：正常转发 vs 触发清洗**

#### A. 正常路径（未牵引）
```
Client ──(DNS/Anycast)──> Edge(L7终止+分类) ──> Origin(私网入口)
```

#### B. 清洗路径（牵引后）
```
Client ──(BGP牵引/高防IP)──> Scrubbing Center(上游清洗)
                                    │
                                    ├─ 过滤恶意/限速/丢弃
                                    │
                                    └─(GRE/IPIP 回注)──> Edge 或 Origin 私网入口
```

### 4.2 牵引方式选型

| 方案 | 优点 | 缺点 | 推荐场景 |
|------|------|------|----------|
| **BGP牵引** | 响应快、可精确控制 | 需要ASN配置 | ✅ 推荐，生产环境 |
| DNS切换 | 易用、配置简单 | 切换慢、粒度粗 | 备用方案 |
| Anycast | 低时延、智能路由 | 配置复杂 | 增强方案 |

**决策：采用 **BGP牵引**为主，**DNS切换**为备**

### 4.3 回注方案

| 方案 | 优点 | 缺点 | 推荐 |
|------|------|------|------|
| **GRE** | 成熟、兼容性好 | MTU问题 | ✅ 推荐 |
| IPIP | 简单、开销小 | 防火墙可能拦截 | 备选 |
| VXLAN | 云原生、可扩展 | 配置复杂 | 可选 |
| WireGuard | 现代、安全 | 需额外配置 | 可选 |
| 专线 | 稳定、高带宽 | 成本高 | 企业级 |

**决策：采用 **GRE回注**（带MTU优化）**

### 4.4 回注配置参数

**GRE隧道配置：**
```yaml
reinjection:
  enabled: true
  mode: "gre"
  
  gre:
    local_ip: "10.0.1.1"
    local_port: 4789
    remote_ip: "10.0.2.1"
    remote_port: 4789
    key: 1234567890
    
    inner_local_ip: "192.168.100.2"
    inner_remote_ip: "192.168.100.1"
    inner_mask: "255.255.255.0"
    
    keepalive_interval: 10s
    keepalive_count: 3
  
  topology:
    scrubbing_center_ip: "203.0.113.1"
    target: "edge"
    injection_cidr: "192.168.100.0/24"
    origin_cidr: "192.168.200.0/24"
    edge_cidr: "192.168.100.0/24"
    routes:
      - destination: "192.168.200.0/24"
        gateway: "192.168.100.1"
        interface: "gre0"
        metric: 100
  
  mtu:
    physical_mtu: 1500
    tunnel_mtu: 1436
    enable_mss_clamp: true
    mss_value: 1436
    auto_discovery: true
```

---

## 5. 源站保护策略

### 5.1 保护原则

> **强制要求：** 源站必须只能通过Edge或回注网段访问，对公网不可达。

### 5.2 保护实施方案

#### 方案A：私有网络 + ACL（推荐）
```
Origin(192.168.200.10)
    ↑
    | (仅允许192.168.100.0/24)
    |
Router(192.168.100.1)
    ↑
    | (来自清洗中心)
    |
Scrubbing Center(203.0.113.1)
    ↑
    | (GRE回注)
    |
Edge(192.168.100.2) → Client访问
```

#### 方案B：VPC安全组（云环境）
```
VPC: vpc-origin (192.168.200.0/24)
  Security Group: sg-origin-allow
    Inbound Rules:
      - Source: 192.168.100.0/24, Port: All, Action: Allow
      - Source: 0.0.0.0/0, Port: All, Action: Deny
```

### 5.3 源站保护配置

```yaml
origin_protection:
  enabled: true
  mode: "whitelist"  # 白名单模式
  
  allow_only_from:
    - id: "edge-nodes"
      cidr: "192.168.100.0/24"
      name: "边缘节点网段"
      type: "edge"
    
    - id: "reinjection"
      cidr: "203.0.113.0/24"
      name: "回注网段"
      type: "reinjection"
    
    - id: "admin-vpn"
      cidr: "10.10.10.0/24"
      name: "管理员VPN"
      type: "vpn"
  
  hide_origin:
    enabled: true
    origin_unreachable: false
    edge_only: true
    reinjection_only: false
    disable_public_dns: true
  
  port_restrictions:
    allowed_ports: [443, 8080, 8443]
    blocked_ports: [22, 3306, 5432]
    default_policy: "deny"
  
  private_network:
    vpc:
      provider: "aws"
      vpc_id: "vpc-xxx"
      subnet_id: "subnet-xxx"
      security_group_id: "sg-xxx"
```

---

## 6. 牵引触发/回切策略

### 6.1 触发信号（多维度交叉验证）

| 信号类型 | 阈值 | 触发动作 | 说明 |
|----------|------|----------|------|
| 入方向带宽 | >2 Gbps | 评估牵引 | 持续30秒 |
| PPS | >50,000 | 立即牵引 | SYN洪水特征 |
| SYN/ACK比例 | <1:10 | 评估牵引 | SYN洪水 |
| 连接建立速率 | >10,000/s | 评估牵引 | 连接洪泛 |
| 5xx率 | >50% | 评估牵引 | 应用层问题 |
| 错误率 | >80% | 评估牵引 | 服务异常 |

**触发策略（避免误触发）：**
- 单信号评估30秒
- 多信号同时命中才触发牵引
- 支持人工手动覆盖
- 冷却时间5分钟

### 6.2 回切策略（稳定+抖动保护）

**稳定窗口：** 连续5分钟检测到流量正常

**抖动保护：**
- 回切后保持稳定10分钟
- 期间不再触发牵引
- 即使再次触发也延迟30秒执行

**最小牵引时间：** 至少牵引5分钟，避免频繁切换

**配置示例：**
```yaml
steering:
  trigger:
    auto_steer: true
    cooldown: "5m"
    conditions:
      - type: "bandwidth"
        threshold: 2000.0
        duration: "30s"
        action: "steer"
        priority: 1
      
      - type: "pps"
        threshold: 50000
        action: "steer"
        priority: 2
      
      - type: "syn_ratio"
        threshold: 0.1
        action: "steer"
        priority: 2
  
  fallback:
    strategy: "auto"
    stable_window: "5m"
    jitter_protection: "10m"
    min_steering_time: "5m"
    auto_fallback: true
    
    conditions:
      - type: "bandwidth"
        threshold: 1000.0
        duration: "5m"
        priority: 1
```

---

## 7. 配置文件位置

### 7.1 主配置文件
```bash
/etc/ai-cdn/config.yml          # 主配置（包含所有M0配置）
/etc/ai-cdn/steering.yml        # 牵引配置
/etc/ai-cdn/reinjection.yml      # 回注配置
/etc/ai-cdn/origin_protection.yml # 源站保护配置
/etc/ai-cdn/failover.yml          # 故障切换配置
```

### 7.2 示例配置文件

**完整配置示例：**
```yaml
# /etc/ai-cdn/config.yml
service:
  mode: "edge"
  node_id: "edge-hk-1"
  node_name: "香港边缘节点1"
  region: "hk"

data_plane:
  tls_termination_mode: "edge"
  supported_protocols:
    - "http1.1"
    - "http2"
    - "websocket"
    - "sse"
  forward_mode: "l7_proxy"
  
  challenge_paths:
    enabled_paths:
      - "/*.html"
      - "/static/*"
    excluded_paths:
      - "/api/*"
      - "/v1/chat/*"
      - "/v1/completions/*"
    default_action: "allow"

steering:
  enabled: true
  mode: "bgp"  # 或 "dns", "anycast"
  
  bgp:
    local_asn: 65000
    neighbor_asn: 65001
    neighbor_ip: "203.0.113.1"
    prefixes:
      - "203.0.113.0/24"
    steering_prefixes:
      - "203.0.113.0/24"
    policy: "prepend"
  
  trigger:
    auto_steer: true
    cooldown: "5m"
    conditions:
      - type: "bandwidth"
        threshold: 2000.0
        duration: "30s"
        action: "steer"
        priority: 1

  fallback:
    strategy: "auto"
    stable_window: "5m"
    jitter_protection: "10m"
    min_steering_time: "5m"
    auto_fallback: true

reinjection:
  enabled: true
  mode: "gre"
  
  gre:
    local_ip: "10.0.1.1"
    local_port: 4789
    remote_ip: "10.0.2.1"
    remote_port: 4789
    key: 1234567890
    inner_local_ip: "192.168.100.2"
    inner_remote_ip: "192.168.100.1"
    inner_mask: "255.255.255.0"
    keepalive_interval: 10s
    keepalive_count: 3
  
  topology:
    scrubbing_center_ip: "203.0.113.1"
    target: "edge"
    injection_cidr: "192.168.100.0/24"
    origin_cidr: "192.168.200.0/24"
    edge_cidr: "192.168.100.0/24"
  
  mtu:
    physical_mtu: 1500
    tunnel_mtu: 1436
    enable_mss_clamp: true
    mss_value: 1436
    auto_discovery: true

origin_protection:
  enabled: true
  mode: "whitelist"
  
  allow_only_from:
    - id: "edge-nodes"
      cidr: "192.168.100.0/24"
      name: "边缘节点网段"
      type: "edge"
    
    - id: "reinjection"
      cidr: "203.0.113.0/24"
      name: "回注网段"
      type: "reinjection"
  
  hide_origin:
    enabled: true
    edge_only: true
    reinjection_only: false
    disable_public_dns: true

failover:
  enabled: true
  
  detection:
    interval: "10s"
    timeout: "5s"
    failure_threshold: 3
    success_threshold: 5
    types:
      - "http"
      - "tcp"
      - "icmp"
  
  switch:
    mode: "auto"
    switch_delay: "30s"
    max_switches: 10
    forbid_switch_window: true
    window_start: "02:00"
    window_end: "06:00"
  
  rollback:
    enabled: true
    stable_window: "5m"
    jitter_protection: "10m"
    min_failure_time: "1m"
    rollback_delay: "30s"
    manual_rollback: false

  health_check:
    check_url: "http://localhost:8080/api/health"
    method: "GET"
    expected_status_code: 200
    interval: "5s"
    timeout: "3s"
    concurrency: 5
    healthy_threshold: 3
    unhealthy_threshold: 2

monitoring:
  prometheus:
    enabled: true
    addr: "0.0.0.0"
    port: 9090
    path: "/metrics"
    interval: "15s"
  
  alert:
    enabled: true
    webhook: "http://alertmanager:9093/api/v1/alerts"
    threshold:
      bandwidth_mbps: 1000.0
      qps: 10000
      error_rate: 0.5
      response_time_ms: 5000
```

---

## 8. 网络拓扑图

### 8.1 物理拓扑

```
                    ┌─────────────────────────────────────────────────┐
                    │            公网 (Internet)               │
                    └───────────────┬─────────────────────────┘
                                  │
                    ┌─────────────▼─────────────────────────┐
                    │         DNS/BGP/Anycast          │
                    │    (203.0.113.0/24)            │
                    └─────────────┬─────────────────────────┘
                                  │
                  ┌─────────────────┴─────────────────────────┐
                  │                                         │
        ┌─────────────────▼────────────────┐    │    ┌───────────────────▼──────────────┐
        │         Edge 集群            │    │    │  清洗中心(上游)    │
        │  ┌────────────────────────┐   │    │  ┌──────────────────────────┐    │
        │  │ Edge-HK-1 (192.168.100.2) │  │    │  │ 203.0.113.1          │    │
        │  │ Edge-HK-2 (192.168.100.3) │  │    │  │  - GRE回注到Edge │    │
        │  │ Edge-HK-3 (192.168.100.4) │  │    │  │ - 清洗+限速        │    │
        │  └────────────────────────┘   │    │  └──────────────────────────┘    │
        │                             │    │                                 │
        └─────────────────────────────┘    └─────────────────────────────────┘
                     │
                     │ GRE隧道 (192.168.100.0/24)
                     │
        ┌─────────────────────────────▼──────────────────────┐
        │              路由器                               │
        │              (192.168.100.1)                    │
        └───────────────────────────────────────────────────┘
                     │
        ┌─────────────────────────────▼──────────────────────┐
        │              Origin 源站                           │
        │        (192.168.200.10)                         │
        │                                                 │
        │  ┌───────────────────────────────────────────────┐   │
        │  │  仅允许: 192.168.100.0/24 (Edge)           │   │
        │  │            203.0.113.0/24 (回注)          │   │
        │  │  阻止: 0.0.0.0/0                    │   │
        │  └───────────────────────────────────────────────┘   │
        └───────────────────────────────────────────────────┘
```

### 8.2 清洗路径拓扑

```
              ┌─────────────────────────────────┐
              │        公网 (攻击流量)         │
              └─────────────┬───────────────────┘
                            │ BGP牵引
                            ▼
              ┌─────────────────────────────────┐
              │       清洗中心               │
              │      (203.0.113.1)          │
              └─────────────┬───────────────────┘
                            │
                ┌──────────┴──────────────┐
                │                          │
         ┌──────▼─────┐   ┌─────────▼──────────┐
         │ 清洗+限速  │   │ GRE回注到Edge/Origin │
         │ - 丢弃恶意  │   │ (192.168.100.0/24)  │
         │ - 限速    │   └─────────────────────┘
         │ - 回注正常│
         └───────────┘
```

---

## 9. 关键参数说明

### 9.1 MTU配置

| 配置项 | 推荐值 | 说明 |
|--------|--------|------|
| 物理接口MTU | 1500 | 标准以太网MTU |
| GRE隧道MTU | 1436 | 1500 - 40(IP头+GRE头) |
| TCP MSS | 1436 | 隧道MTU - 40 |
| Path MTU Discovery | 启用 | 自动检测最小MTU |

**MSS Clamping重要性：**
- 防止TCP分片和重组问题
- 提高传输效率
- 减少延迟

### 9.2 冷却时间

| 场景 | 冷却时间 | 说明 |
|------|----------|------|
| 牵引触发 | 5分钟 | 避免频繁牵引 |
| 回切 | 10分钟 | 稳定后再允许触发 |
| 手动覆盖 | 永久 | 人工控制优先级最高 |

---

## 10. 验收检查清单

### M0.1 基础配置
- [x] TLS终止策略已文档化（L7代理模式）
- [x] 协议支持矩阵已定义
- [x] 挑战验证路径白名单已配置
- [ ] gost版本已锁定并测试兼容

### M0.2 高防牵引
- [ ] BGP牵引方式已选型并完成最小可用连通性验证
- [ ] 清洗路径与回注拓扑已文档化
- [ ] 牵引触发/回切策略已定义
- [ ] 牵引/回切演练用例已定义

### M0.3 源站保护
- [ ] 源站保护策略已落地
- [ ] 源站仅接受Edge/回注网段的入站
- [ ] 源站对公网不可达（安全组/ACL/防火墙白名单）

### M0.4 测试验证
- [ ] GRE/IPIP回注链路连通性已验证（含MTU/丢包/抖动测试）
- [ ] 牵引触发/回切功能已测试（含抖动保护与回切窗口）
- [ ] MTU调整生效已验证（抓包验证）

---

## 11. 下一步行动

### 11.1 立即执行（M0-1到M0-6）
1. 创建配置模块 `pkg/config/` ✅ 已完成
2. 实现牵引管理器 `pkg/defense/steering.go` ✅ 已完成
3. 实现回注管理器 `pkg/defense/reinjection.go`
4. 实现流量分发器 `pkg/distribute/traffic.go`
5. 实现源站保护策略 `pkg/security/origin_protection.go`
6. 实现故障切换控制器 `pkg/defense/failover.go`

### 11.2 文档和验证（M0-7到M0-9）
7. 创建架构决策文档 ✅ 本文档
8. 创建数据面拓扑图
9. 编写牵引/回切测试脚本
10. 更新部署文档 `README-DEPLOY.md`

### 11.3 集成测试
1. 部署测试环境
2. 配置GRE隧道
3. 测试牵引流程
4. 测试回切流程
5. 验证源站保护
6. 性能测试

---

## 12. 风险与缓解

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| 牵引误触发 | 全站波动 | 中 | 多维度验证+人工覆盖+冷却时间 |
| 回注MTU问题 | 丢包/延迟 | 中 | MSS Clamping+Path MTU Discovery |
| Anycast路由不对称 | 会话异常 | 低 | 会话无状态化+粘性策略 |
| L4连接洪泛压垮Edge | 连接耗尽 | 高 | 上游高防兜底+连接限制 |
| 源站被绕过 | 暴露源站 | 高 | 强制ACL+安全组+VPC |

---

## 13. 技术债务

| 项目 | 优先级 | 计划 |
|------|--------|------|
| ML检测 | 低 | v2实现 |
| 10Gbps清洗（应用层） | 低 | 需上游高防 |
| 多云部署 | 中 | v2增强 |
| 自动化运维 | 中 | v2增强 |

---

**文档版本：** v1.0
**最后更新：** 2026-01-06
**下次审核：** M0验收时

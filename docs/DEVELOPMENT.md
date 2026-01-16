# AI CDN Tunnel - 开发指南

## 目录

- [1. 开发环境](#1-开发环境)
- [2. 项目结构](#2-项目结构)
- [3. 快速开始](#3-快速开始)
- [4. 代码规范](#4-代码规范)
- [5. 开发流程](#5-开发流程)
- [6. 测试](#6-测试)
- [7. 调试技巧](#7-调试技巧)
- [8. 常见问题](#8-常见问题)

---

## 1. 开发环境

### 1.1 系统要求

| 组件 | 最低版本 | 推荐版本 |
|------|----------|----------|
| Go | 1.24.0 | 1.24.0 |
| Node.js | 16.x | 20.x |
| Git | 2.0+ | 最新 |
| MongoDB | 5.0 | 7.0 |
| Redis | 6.0 | 7.0 |

### 1.2 开发工具推荐

| 工具 | 用途 |
|------|------|
| VS Code / GoLand | Go IDE |
| Golangci-lint | 代码检查 |
| Delve | Go 调试器 |
| Postman / Insomnia | API 测试 |
| MongoDB Compass | MongoDB GUI |
| Redis Desktop Manager | Redis GUI |

### 1.3 环境变量配置

```bash
# .env.development
# Master 配置
export MASTER_HTTP_ADDR=":8080"
export MASTER_GRPC_ADDR=":50051"
export MONGO_URI="mongodb://localhost:27017/ai-cdn"
export REDIS_ADDR="localhost:6379"
export JWT_SECRET="your-dev-jwt-secret"

# Agent 配置
export AGENT_MASTER_ADDR="localhost:50051"
export AGENT_NODE_TYPE="edge"
export AGENT_REGION="hk"
export AGENT_NODE_NAME="dev-node"

# 监控配置
export PROMETHEUS_ADDR=":9090"
```

---

## 2. 项目结构

```
go-cdn/
├── cmd/                          # 入口点
│   ├── master/main.go           # Master 主程序
│   ├── agent/main.go            # Agent 主程序
│   ├── cdn/main.go              # CDN 独立服务
│   └── gost/main.go             # gost 命令
│
├── master/                       # Master 模块
│   ├── config/                  # 配置管理
│   │   └── config.go
│   ├── db/                      # 数据库操作
│   │   └── db.go
│   ├── handler/                 # HTTP 处理器
│   │   └── handler.go
│   ├── health/                  # 健康检查
│   │   ├── health_check.go
│   │   ├── failover.go
│   │   └── autoscale.go
│   ├── ha/                      # 高可用
│   │   ├── election.go
│   │   └── config_version.go
│   ├── monitor/                 # 监控
│   │   └── monitor.go
│   ├── node/                    # 节点管理
│   │   └── node.go
│   ├── scripts/                 # 部署脚本
│   │   └── deploy.go
│   └── templates/               # 配置模板
│       └── gost_configs.go
│
├── agent/                        # Agent 模块
│   ├── config/                  # 配置
│   │   └── config.go
│   ├── heartbeat/               # 心跳
│   │   └── heartbeat.go
│   ├── status/                  # 状态
│   │   └── status.go
│   └── updater/                 # 配置更新
│       └── updater.go
│
├── pkg/                          # 公共包
│   ├── accesscontrol/           # 访问控制
│   ├── batch/                   # 批量操作
│   ├── billing/                 # 计费
│   ├── cache/                   # 缓存
│   ├── defense/                 # 防御
│   ├── dns/                     # DNS
│   ├── e2e/                     # E2E 测试
│   ├── edge/                    # 边缘计算
│   ├── http3/                   # HTTP3
│   ├── iplib/                   # IP 库
│   ├── layer4/                  # L4 代理
│   ├── logs/                    # 日志
│   ├── media/                   # 媒体
│   ├── monitor/                 # 监控
│   ├── node/                    # 节点
│   ├── notification/            # 通知
│   ├── performance/             # 性能
│   ├── resource/                # 资源
│   ├── security/                # 安全
│   ├── stats/                   # 统计
│   ├── storage/                 # 存储
│   └── tlsutil/                 # TLS
│
├── proto/                        # Protocol Buffers
│   ├── agent/
│   │   └── agent.go
│   └── master/
│       └── master.go
│
├── config/                       # 配置文件
│   ├── master.yml
│   ├── agent.yml
│   ├── gost-edge-hk.yml
│   ├── gost-core-cn.yml
│   └── performance/
│       ├── gost-performance.yml
│       ├── sysctl.conf
│       └── limits.conf
│
├── scripts/                      # 部署脚本
│   ├── deploy-master.sh
│   ├── deploy-agent.sh
│   ├── manage.sh
│   ├── optimize.sh
│   ├── benchmark.sh
│   └── load-balance.sh
│
├── web-admin/                    # Vue3 前端
│   ├── src/
│   ├── public/
│   └── package.json
│
├── docs/                         # 文档
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── COMMUNICATION.md
│   └── PERFORMANCE.md
│
├── plans/                        # 设计文档
│   ├── ai-cdn-architecture.md
│   └── master-agent-architecture.md
│
├── test/                         # 测试文件
│   └── integration/
│
├── Makefile                      # 构建脚本
├── go.mod                        # Go 模块
├── go.sum                        # Go 依赖
├── Dockerfile                    # Docker 构建
├── docker-compose.yml           # Docker Compose
└── README.md                     # 项目说明
```

---

## 3. 快速开始

### 3.1 克隆项目

```bash
# 克隆项目
git clone https://github.com/tyqy12/go-cdn.git
cd go-cdn

# 切换到开发分支
git checkout -b develop
```

### 3.2 安装依赖

```bash
# 安装 Go 依赖
go mod download

# 安装前端依赖
cd web-admin
npm install
cd ..
```

### 3.3 启动 MongoDB 和 Redis

```bash
# 使用 Docker 启动
docker-compose up -d mongo redis

# 或使用本地服务
# 确保 MongoDB 在 localhost:27017
# 确保 Redis 在 localhost:6379
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

### 3.5 运行 Master

```bash
# 开发模式运行 Master
go run cmd/master/main.go \
    -config config/master.yml \
    -http :8080 \
    -grpc :50051
```

### 3.6 运行 Agent

```bash
# 开发模式运行 Agent
go run cmd/agent/main.go \
    -config config/agent.yml \
    -master localhost:50051 \
    -type edge \
    -region hk
```

### 3.7 运行前端

```bash
cd web-admin
npm run dev
```

---

## 4. 代码规范

### 4.1 Go 代码规范

遵循 [Effective Go](https://golang.org/doc/effective_go) 和社区规范：

#### 4.1.1 命名规范

```go
// 包名：简洁、小写
package monitor

// 变量：驼峰命名
var maxConnections = 10000

// 常量：全大写下划线分隔
const DEFAULT_TIMEOUT = 30 * time.Second

// 导出函数：首字母大写
func NewMonitor() *Monitor {}

// 私有函数：首字母小写
func newIdGenerator() string {}

// 接口：-er 后缀
type Reader interface {
    Read(p []byte) (n int, err error)
}

// 结构体：名词或名词短语
type NodeManager struct {
    nodes map[string]*Node
}
```

#### 4.1.2 错误处理

```go
// 好的做法
func GetNode(id string) (*Node, error) {
    node, exists := nodes[id]
    if !exists {
        return nil, fmt.Errorf("node not found: %s", id)
    }
    return node, nil
}

// 避免：不要忽略错误
func BadExample() {
    data, _ := os.ReadFile("file.txt") // 错误被忽略
}
```

#### 4.1.3 上下文使用

```go
// 好的做法：使用 context 传递超时和取消
func FetchData(ctx context.Context, url string) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }
    return http.DefaultClient.Do(req)
}
```

#### 4.1.4 并发安全

```go
// 使用读写锁
type Cache struct {
    mu    sync.RWMutex
    items map[string]string
}

func (c *Cache) Get(key string) string {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.items[key]
}

func (c *Cache) Set(key, value string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = value
}

// 或使用 sync.Map
var cache sync.Map
```

### 4.2 提交规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Type 类型**：

| 类型 | 说明 |
|------|------|
| feat | 新功能 |
| fix | Bug 修复 |
| docs | 文档更新 |
| style | 代码格式 |
| refactor | 重构 |
| test | 测试 |
| chore | 构建/工具 |

**示例**：

```
feat(master): 添加节点健康检查功能

实现节点心跳检测和自动下线机制

Closes #123
```

### 4.3 代码检查

```bash
# 运行 linter
golangci-lint run

# 格式化代码
gofmt -w .

# 检查未使用的导入
goimports -w .
```

---

## 5. 开发流程

### 5.1 分支策略

```
main          # 主分支，生产环境代码
develop       # 开发分支，集成测试
feature/*     # 功能分支
hotfix/*      # 紧急修复
release/*     # 发布分支
```

### 5.2 开发步骤

```bash
# 1. 创建功能分支
git checkout develop
git checkout -b feature/new-feature

# 2. 开发并测试
# ... 编写代码 ...

# 3. 提交更改
git add .
git commit -m "feat: 添加新功能"

# 4. 推送到远程
git push origin feature/new-feature

# 5. 创建 Pull Request
# 在 GitHub 上创建 PR 并请求审查
```

### 5.3 代码审查要点

提交 PR 前确保：

- [ ] 代码通过所有测试
- [ ] 通过 lint 检查
- [ ] 文档已更新
- [ ] 新增 API 有测试
- [ ] 无硬编码敏感信息

---

## 6. 测试

### 6.1 运行测试

```bash
# 运行所有测试
go test ./...

# 运行特定包测试
go test ./pkg/cache/...

# 运行测试并显示覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# 运行基准测试
go test -bench=. ./pkg/cache/...
```

### 6.2 单元测试示例

```go
// pkg/cache/advanced_cache_test.go
package cache

import (
    "testing"
    "time"
)

func TestAdvancedCache_Get(t *testing.T) {
    cache := NewAdvancedCache(&CacheConfig{
        Enabled: true,
        Global: &GlobalCacheConfig{
            DefaultTTL: 3600 * time.Second,
        },
    })

    // 测试获取不存在的缓存
    req := &CacheRequest{
        URL:    "/test",
        Method: "GET",
    }

    resp := cache.Get(req)
    if resp.Hit {
        t.Error("expected miss, got hit")
    }
}

func TestAdvancedCache_Set(t *testing.T) {
    cache := NewAdvancedCache(nil)

    req := &CacheRequest{
        URL:    "/test",
        Method: "GET",
    }

    key := cache.Set(req, []byte("test data"), nil, 200)
    if key == "" {
        t.Error("expected non-empty key")
    }
}
```

### 6.3 集成测试

```go
// test/integration/master_test.go
package integration

import (
    "context"
    "testing"
    "time"

    "github.com/ai-cdn-tunnel/master/db"
    "github.com/ai-cdn-tunnel/master/node"
)

func TestNodeManager(t *testing.T) {
    // 启动测试数据库
    mongo := db.NewMongoDB("mongodb://localhost:27017/ai-cdn-test")
    defer mongo.Close()

    mgr := node.NewManager(mongo)

    // 测试创建节点
    ctx := context.Background()
    testNode := &db.Node{
        ID:      "test-node-1",
        Name:    "Test Node",
        Type:    "edge",
        Region:  "hk",
        Status:  "online",
    }

    err := mgr.SaveNode(ctx, testNode)
    if err != nil {
        t.Fatalf("failed to save node: %v", err)
    }

    // 验证创建成功
    savedNode, err := mgr.GetNode(ctx, "test-node-1")
    if err != nil {
        t.Fatalf("failed to get node: %v", err)
    }

    if savedNode.Name != "Test Node" {
        t.Errorf("expected name 'Test Node', got '%s'", savedNode.Name)
    }
}
```

### 6.4 Mock 测试

```go
// 使用 mockery 生成 mock
//go:generate mockery --name=Store --output=test/mocks

type Store interface {
    GetNode(ctx context.Context, id string) (*Node, error)
    SaveNode(ctx context.Context, node *Node) error
}

func TestWithMock(t *testing.T) {
    mockStore := NewMockStore(ctrl)
    mockStore.EXPECT().GetNode(gomock.Any(), "test").
        Return(&Node{ID: "test"}, nil)

    mgr := NewManager(mockStore)
    node, err := mgr.GetNode(context.Background(), "test")

    if err != nil {
        t.Errorf("unexpected error: %v", err)
    }
    if node.ID != "test" {
        t.Errorf("expected id 'test', got '%s'", node.ID)
    }
}
```

---

## 7. 调试技巧

### 7.1 使用 Delve 调试

```bash
# 安装 Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 调试 Master
dlv debug cmd/master/main.go -- --config config/master.yml

# 调试 Agent
dlv debug cmd/agent/main.go -- --master localhost:50051 --type edge
```

### 7.2 日志调试

```go
// 使用日志包
import "github.com/ai-cdn-tunnel/pkg/logs"

func MyFunction() {
    logs.Debug("Debug message")
    logs.Info("Info message")
    logs.Warn("Warning message")
    logs.Error("Error message", logs.Err(err))

    // 带字段的日志
    logs.WithField("node_id", "test").Info("Node info")
    logs.WithFields(logs.Fields{
        "region": "hk",
        "type":   "edge",
    }).Info("Node details")
}
```

### 7.3 pprof 性能分析

```go
// 在代码中添加
import (
    "net/http"
    _ "net/http/pprof"
)

func init() {
    go func() {
        http.ListenAndServe(":6060", nil)
    }()
}
```

```bash
# 查看性能分析
go tool pprof http://localhost:6060/debug/pprof/heap

# 生成火焰图
go tool pprof -http=:8081 http://localhost:6060/debug/pprof/profile
```

### 7.4 远程调试

```yaml
# launch.json (VS Code)
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Remote Debug Master",
            "type": "go",
            "request": "attach",
            "mode": "remote",
            "remotePath": "/path/to/go-cdn",
            "host": "192.168.1.100",
            "port": 2345,
            "env": {},
            "args": ["-config", "config/master.yml"]
        }
    ]
}
```

---

## 8. 常见问题

### Q1: 编译失败，依赖缺失

```bash
# 清理并重新下载依赖
go clean -modcache
go mod download
go mod tidy
```

### Q2: MongoDB 连接失败

```bash
# 检查 MongoDB 服务
docker ps | grep mongo

# 检查连接字符串
mongosh "mongodb://localhost:27017"
```

### Q3: gRPC 连接被拒绝

```bash
# 检查端口是否监听
netstat -tlnp | grep 50051

# 检查防火墙
sudo ufw status
```

### Q4: 测试超时

```bash
# 增加测试超时时间
go test -timeout 5m ./...
```

### Q5: 前端构建失败

```bash
# 清理 node_modules 并重新安装
cd web-admin
rm -rf node_modules package-lock.json
npm install
```

---

## 附录

### A. Makefile 常用命令

```makefile
# 查看所有可用命令
make help

# 构建
make build           # 构建所有
make build-master    # 构建 Master
make build-agent     # 构建 Agent
make build-cdn       # 构建 CDN

# 测试
make test            # 运行测试
make test-coverage   # 运行测试并生成覆盖率

# 代码检查
make lint            # 运行 linter
make fmt             # 格式化代码

# 清理
make clean           # 清理构建产物
make clean-test      # 清理测试覆盖率

# Docker
make docker-build    # 构建 Docker 镜像
make docker-push     # 推送镜像

# 发布
make release         # 创建发布版本
```

### B. Git Hooks

```bash
# 安装 pre-commit hooks
make install-hooks

# 钩子会在以下操作前执行
# - commit: 运行 lint 和测试
# - push: 运行完整的测试套件
```

### C. 开发工具配置

**VS Code settings.json**:
```json
{
    "go.useLanguageServer": true,
    "go.lintOnSave": "package",
    "go.formatTool": "goimports",
    "editor.formatOnSave": true,
    "[go]": {
        "editor.insertSpaces": false,
        "editor.tabSize": 4
    }
}
```

**Golangci-lint .golangci.yml**:
```yaml
run:
  timeout: 5m
  issues-exit-code: 1
  tests: true

linters:
  enable-all: true
  disable:
    - gochecknoglobals
    - gochecknoinits

linters-settings:
  goimports:
    local-prefixes: github.com/ai-cdn-tunnel
```

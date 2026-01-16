# 文档整理计划

> 创建日期: 2026-01-13
> 状态: 待用户确认

## 1. 当前文档结构分析

### 1.1 文档分布

| 目录 | 文件数 | 说明 |
|------|--------|------|
| `plans/` | 5 | 设计计划文档 |
| `docs/` | 10+ | 技术文档 (含多个里程碑文档) |

### 1.2 当前文档清单

#### plans/ 目录

| 文件名 | 行数 | 内容 |
|--------|------|------|
| [`ai-cdn-architecture.md`](plans/ai-cdn-architecture.md) | 739 | AI大模型对话系统 CDN 架构设计 |
| [`DEVELOPMENT_PLAN.md`](plans/DEVELOPMENT_PLAN.md) | 879 | 开发计划 (状态: 全部完成) |
| [`high-performance-architecture.md`](plans/high-performance-architecture.md) | 259 | 高性能 CDN 架构 (10Gb+PB级) |
| [`master-agent-architecture.md`](plans/master-agent-architecture.md) | 428 | 主控-被控架构设计 |
| [`one-click-deploy-design.md`](plans/one-click-deploy-design.md) | 852 | 一键部署节点功能设计 |

#### docs/ 目录

| 文件名 | 行数 | 内容 |
|--------|------|------|
| [`README.md`](docs/README.md) | 24 | 文档目录索引 |
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 637 | 系统架构设计文档 |
| [`API.md`](docs/API.md) | - | REST API 接口文档 |
| [`DEPLOYMENT.md`](docs/DEPLOYMENT.md) | 1047 | 部署指南 |
| [`DEVELOPMENT.md`](docs/DEVELOPMENT.md) | 798 | 开发指南 |
| [`SECURITY.md`](docs/SECURITY.md) | 1020 | 安全指南 |
| [`COMMUNICATION.md`](docs/COMMUNICATION.md) | - | Master-Agent 通信优化 |
| [`PERFORMANCE.md`](docs/PERFORMANCE.md) | - | 性能调优指南 |
| [`IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | 1516 | 实施计划 (M0-M3里程碑) |

### 1.3 存在问题

1. **内容重复**: `plans/ai-cdn-architecture.md` 与 `docs/ARCHITECTURE.md` 架构内容重复
2. **状态过期**: `plans/DEVELOPMENT_PLAN.md` 标记为"全部完成"，但仍在 plans/ 中
3. **粒度混乱**: `docs/IMPLEMENTATION_PLAN.md` 过于详细 (1500+行)，与 `docs/DEPLOYMENT.md` 职责不清
4. **目录混乱**: `docs/` 目录既有用户文档也有开发计划
5. **索引缺失**: 缺少统一的文档导航入口

---

## 2. 整理目标

### 2.1 目录结构重整

```
docs/
├── README.md              # 文档入口 (更新)
├── ARCHITECTURE.md        # 系统架构 (保留，整合 plans/ai-cdn-architecture.md)
├── API.md                 # API 接口 (保留)
├── DEPLOYMENT.md          # 部署指南 (保留)
├── DEVELOPMENT.md         # 开发指南 (保留)
├── SECURITY.md            # 安全指南 (保留)
├── PERFORMANCE.md         # 性能调优 (保留)
├── COMMUNICATION.md       # 通信协议 (保留)
├── RUNBOOK.md             # 运维手册 (新增，整合运维内容)
└── GLOSSARY.md            # 术语表 (新增)

plans/
├── README.md              # 计划索引 (更新，标记已完成计划)
├── master-agent-architecture.md  # 保留 (架构决策记录)
└── ARCHIVE/               # 归档目录
    ├── ai-cdn-architecture.md    # 移入归档
    ├── DEVELOPMENT_PLAN.md       # 移入归档
    ├── high-performance-architecture.md # 移入归档
    ├── one-click-deploy-design.md      # 移入归档
    └── IMPLEMENTATION_PLAN.md          # 移入归档
```

### 2.2 文档分类

| 分类 | 目标读者 | 文档 |
|------|----------|------|
| **用户文档** | 运维人员 | DEPLOYMENT.md, RUNBOOK.md, GLOSSARY.md |
| **开发文档** | 开发者 | DEVELOPMENT.md, ARCHITECTURE.md, API.md |
| **架构文档** | 架构师 | ARCHITECTURE.md, COMMUNICATION.md |
| **运维文档** | 运维工程师 | PERFORMANCE.md, RUNBOOK.md |
| **安全文档** | 安全工程师 | SECURITY.md |

---

## 3. 详细整理计划

### 3.1 第一阶段: 创建文档索引 [ ]

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.1.1 | `docs/README.md` | 更新为完整文档索引 |
| 3.1.2 | `plans/README.md` | 创建计划目录索引，标记已完成计划 |

### 3.2 第二阶段: 整合架构文档 [ ]

| 任务 | 说明 |
|------|------|
| 3.2.1 | 将 `plans/ai-cdn-architecture.md` 核心内容整合到 `docs/ARCHITECTURE.md` |
| 3.2.2 | 删除 `plans/ai-cdn-architecture.md` |

### 3.3 第三阶段: 归档过期计划 [ ]

| 任务 | 说明 |
|------|------|
| 3.3.1 | 创建 `plans/ARCHIVE/` 目录 |
| 3.3.2 | 移动以下文件到 ARCHIVE/: |
| | - `plans/DEVELOPMENT_PLAN.md` (已完成) |
| | - `plans/high-performance-architecture.md` (未来规划) |
| | - `plans/one-click-deploy-design.md` (已完成设计) |
| | - `docs/IMPLEMENTATION_PLAN.md` (过细粒度) |

### 3.4 第四阶段: 新增运维文档 [ ]

| 任务 | 文件 | 说明 |
|------|------|------|
| 3.4.1 | `docs/RUNBOOK.md` | 从 DEPLOYMENT.md 提取运维内容 |
| 3.4.2 | `docs/GLOSSARY.md` | 统一术语表 |

### 3.5 第五阶段: 更新文档交叉引用 [ ]

| 任务 | 说明 |
|------|------|
| 3.5.1 | 更新 `README.md` 主文档中的文档链接 |
| 3.5.2 | 更新 `docs/README.md` 索引 |

---

## 4. 预期成果

### 4.1 整理后结构

```
docs/                          # 技术文档目录
├── README.md                  # 文档入口导航
├── ARCHITECTURE.md            # 系统架构 (已整合)
├── API.md                     # API 接口
├── DEPLOYMENT.md              # 部署指南
├── DEVELOPMENT.md             # 开发指南
├── SECURITY.md                # 安全指南
├── PERFORMANCE.md             # 性能调优
├── COMMUNICATION.md           # 通信协议
├── RUNBOOK.md                 # 运维手册 (新增)
└── GLOSSARY.md                # 术语表 (新增)

plans/                         # 设计计划目录
├── README.md                  # 计划索引
├── master-agent-architecture.md # 保留 (架构决策)
└── ARCHIVE/                   # 归档
    ├── ai-cdn-architecture.md
    ├── DEVELOPMENT_PLAN.md
    ├── high-performance-architecture.md
    ├── one-click-deploy-design.md
    └── IMPLEMENTATION_PLAN.md
```

### 4.2 文档职责划分

| 文档 | 职责 |
|------|------|
| `README.md` | 项目主入口，链接到所有文档 |
| `docs/README.md` | 技术文档导航 |
| `docs/ARCHITECTURE.md` | 系统架构设计 (权威版本) |
| `docs/DEPLOYMENT.md` | 部署步骤 (面向用户) |
| `docs/DEVELOPMENT.md` | 开发环境设置 (面向开发者) |
| `docs/SECURITY.md` | 安全配置指南 |
| `docs/RUNBOOK.md` | 日常运维操作 |
| `plans/README.md` | 设计计划索引 |

---

## 5. 执行顺序

```
Step 1: 创建 docs/README.md (文档索引)
Step 2: 创建 plans/README.md (计划索引)
Step 3: 整合 ARCHITECTURE.md (合并 plans/ai-cdn-architecture.md)
Step 4: 创建 plans/ARCHIVE/ 并移动归档文件
Step 5: 创建 docs/RUNBOOK.md (运维手册)
Step 6: 创建 docs/GLOSSARY.md (术语表)
Step 7: 更新交叉引用
Step 8: 验证文档链接
```

---

## 6. 风险与注意事项

| 风险 | 缓解措施 |
|------|----------|
| 文档链接失效 | 执行前备份，执行后验证 |
| 归档文件丢失 | 创建 ARCHIVE 目录并明确标记 |
| 文档内容不一致 | 整合时检查并同步更新 |

---

> **下一步**: 请确认此整理计划是否满足您的需求。
> 
> 如需调整，请告知具体修改方向。

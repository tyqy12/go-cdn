# AI CDN Tunnel - 文档目录

> 本目录包含项目技术文档，面向运维人员、开发者和架构师。

## 快速导航

| 文档 | 说明 | 目标读者 |
|------|------|----------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | 系统架构设计 | 架构师、开发者 |
| [API.md](./API.md) | REST API 接口文档 | 开发者、集成方 |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | 部署指南 | 运维人员 |
| [DEVELOPMENT.md](./DEVELOPMENT.md) | 开发指南 | 开发者 |
| [SECURITY.md](./SECURITY.md) | 安全指南 | 安全工程师、运维 |
| [PERFORMANCE.md](./PERFORMANCE.md) | 性能调优指南 | 运维人员、开发者 |
| [COMMUNICATION.md](./COMMUNICATION.md) | Master-Agent 通信协议 | 开发者 |
| [RUNBOOK.md](./RUNBOOK.md) | 运维操作手册 | 运维人员 |
| [GLOSSARY.md](./GLOSSARY.md) | 术语表 | 全体成员 |

---

## 文档分类

### 🚀 入门指南

| 文档 | 描述 |
|------|------|
| [DEPLOYMENT.md](./DEPLOYMENT.md) | 从零开始部署系统 |
| [DEVELOPMENT.md](./DEVELOPMENT.md) | 设置开发环境 |

### 📐 架构设计

| 文档 | 描述 |
|------|------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | 系统整体架构、组件设计 |
| [COMMUNICATION.md](./COMMUNICATION.md) | Master-Agent 通信协议 |

### 🔧 开发参考

| 文档 | 描述 |
|------|------|
| [API.md](./API.md) | REST API 接口定义 |
| [DEVELOPMENT.md](./DEVELOPMENT.md) | 代码规范、开发流程 |

### 🛡️ 安全与性能

| 文档 | 描述 |
|------|------|
| [SECURITY.md](./SECURITY.md) | 安全配置、认证授权 |
| [PERFORMANCE.md](./PERFORMANCE.md) | 性能优化、调优参数 |

### 📋 运维支持

| 文档 | 描述 |
|------|------|
| [RUNBOOK.md](./RUNBOOK.md) | 日常运维操作、故障处理 |
| [GLOSSARY.md](./GLOSSARY.md) | 术语定义 |

---

## 相关文档

| 位置 | 描述 |
|------|------|
| [README.md](../README.md) | 项目主文档 |
| [README-MASTER-AGENT.md](../README-MASTER-AGENT.md) | 主被控架构说明 |
| [plans/](../plans/) | 架构设计计划 (含归档) |
| [web-admin/](../web-admin/) | Vue3 管理前端 |

---

## 归档文档

> 以下历史文档已移至 [`plans/ARCHIVE/`](../plans/ARCHIVE/) 目录：

- M0/M1 里程碑文档
- 实现计划 (IMPLEMENTATION_PLAN.md)
- 开发计划 (DEVELOPMENT_PLAN.md)
- 高性能架构设计 (high-performance-architecture.md)
- 一键部署设计 (one-click-deploy-design.md)

---

## 版本信息

| 项目 | 版本 |
|------|------|
| Go | 1.24.0 |
| Vue3 | Latest |
| gost | v3.x |

---

## 贡献指南

1. **更新文档**: 在对应目录修改 `.md` 文件
2. **新增文档**: 遵循命名规范 (大写字母开头)
3. **更新索引**: 新增文档后更新本 `README.md`
4. **代码示例**: 使用 ```go, ```yaml, ```bash 等代码块

## 文档规范

- 使用中文标题和中文标点
- 标题使用中文，代码使用英文
- 表格使用 Markdown 格式
- 链接使用相对路径
- 代码示例需可运行

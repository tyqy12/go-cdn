# AI CDN Tunnel - 管理后台

基于 Vue 3 + Element Plus + Tailwind CSS 的可视化管理系统

## 技术栈

- **Vue 3** - 前端框架
- **Pinia** - 状态管理
- **Vue Router** - 路由管理
- **Element Plus** - UI组件库
- **Tailwind CSS** - 原子化CSS
- **ECharts** - 图表库
- **Vite** - 构建工具

## 项目结构

```
web-admin/
├── src/
│   ├── main.js           # 应用入口
│   ├── App.vue           # 根组件
│   ├── router/           # 路由配置
│   │   └── index.js
│   ├── views/            # 页面组件
│   │   ├── Dashboard.vue # 仪表盘
│   │   ├── Nodes.vue     # 节点管理
│   │   ├── Configs.vue   # 配置管理
│   │   ├── Commands.vue  # 指令分发
│   │   ├── Alerts.vue    # 告警中心
│   │   └── Monitor.vue   # 监控面板
│   ├── stores/           # Pinia状态管理
│   │   └── index.js
│   ├── api/              # API接口封装
│   │   └── index.js
│   └── style.css         # 全局样式
├── index.html
├── package.json
├── vite.config.js
├── tailwind.config.js
└── postcss.config.js
```

## 安装运行

```bash
# 进入目录
cd web-admin

# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build
```

## 功能特性

### 仪表盘
- 总节点数统计
- 在线节点统计
- 活跃连接数
- 活跃告警数
- 节点分布饼图

### 节点管理
- 节点列表展示
- 多维度筛选（类型/地区/状态）
- 节点详情查看
- 重启/重载操作

### 配置管理
- 配置版本列表
- 新建配置
- 发布配置
- 回滚配置

### 指令分发
- 批量指令执行（reload/restart/stop）
- 按地区/类型/节点选择目标
- 执行历史记录

### 告警中心
- 活跃告警列表
- 告警静默
- 告警详情

### 监控面板
- 连接数趋势图
- QPS趋势图
- 延迟分布图
- 错误率统计
- 流量统计

## API代理

开发环境通过 Vite 代理将 `/api` 请求转发到后端服务：

```javascript
// vite.config.js
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
})
```

## 截图预览

[待添加]

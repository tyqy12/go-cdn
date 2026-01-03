import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue'),
    meta: { title: '仪表盘' }
  },
  {
    path: '/nodes',
    name: 'Nodes',
    component: () => import('../views/Nodes.vue'),
    meta: { title: '节点管理' }
  },
  {
    path: '/configs',
    name: 'Configs',
    component: () => import('../views/Configs.vue'),
    meta: { title: '配置管理' }
  },
  {
    path: '/commands',
    name: 'Commands',
    component: () => import('../views/Commands.vue'),
    meta: { title: '指令分发' }
  },
  {
    path: '/alerts',
    name: 'Alerts',
    component: () => import('../views/Alerts.vue'),
    meta: { title: '告警中心' }
  },
  {
    path: '/monitor',
    name: 'Monitor',
    component: () => import('../views/Monitor.vue'),
    meta: { title: '监控面板' }
  },
  // ============ 安全防护 ============
  {
    path: '/security/shield',
    name: 'Shield',
    component: () => import('../views/security/Shield.vue'),
    meta: { title: '5秒盾配置', parent: '安全防护' }
  },
  {
    path: '/security/cc-protection',
    name: 'CCProtection',
    component: () => import('../views/security/CCProtection.vue'),
    meta: { title: 'CC防护配置', parent: '安全防护' }
  },
  {
    path: '/security/url-auth',
    name: 'URLAuth',
    component: () => import('../views/security/URLAuth.vue'),
    meta: { title: 'URL鉴权配置', parent: '安全防护' }
  },
  {
    path: '/security/active-defense',
    name: 'ActiveDefense',
    component: () => import('../views/security/ActiveDefense.vue'),
    meta: { title: '主动防御配置', parent: '安全防护' }
  },
  // ============ 节点管理 ============
  {
    path: '/nodes/l2',
    name: 'L2Nodes',
    component: () => import('../views/nodes/L2Nodes.vue'),
    meta: { title: 'L2节点管理', parent: '节点管理' }
  },
  // ============ DNS调度 ============
  {
    path: '/dns/scheduler',
    name: 'DNSScheduler',
    component: () => import('../views/dns/DNSScheduler.vue'),
    meta: { title: 'DNS智能调度', parent: 'DNS管理' }
  },
  {
    path: '/dns/smart',
    name: 'SmartDNS',
    component: () => import('../views/dns/SmartDNS.vue'),
    meta: { title: '智能DNS配置', parent: 'DNS管理' }
  },
  // ============ 日志与监控 ============
  {
    path: '/logs/access',
    name: 'AccessLogs',
    component: () => import('../views/logs/AccessLogs.vue'),
    meta: { title: '访问日志', parent: '日志管理' }
  },
  {
    path: '/logs/analyzer',
    name: 'LogAnalyzer',
    component: () => import('../views/logs/LogAnalyzer.vue'),
    meta: { title: '日志分析配置', parent: '日志管理' }
  },
  {
    path: '/monitor/region',
    name: 'RegionMonitor',
    component: () => import('../views/monitor/RegionMonitor.vue'),
    meta: { title: '区域监控', parent: '监控管理' }
  },
  // ============ 存储与媒体 ============
  {
    path: '/storage/object',
    name: 'ObjectStorage',
    component: () => import('../views/storage/ObjectStorage.vue'),
    meta: { title: '对象存储配置', parent: '存储管理' }
  },
  {
    path: '/media/hls',
    name: 'HLSEncryption',
    component: () => import('../views/media/HLSEncryption.vue'),
    meta: { title: 'HLS加密配置', parent: '媒体服务' }
  },
  // ============ 边缘计算 ============
  {
    path: '/edge/computing',
    name: 'EdgeComputing',
    component: () => import('../views/edge/EdgeComputing.vue'),
    meta: { title: '边缘运算配置', parent: '边缘计算' }
  },
  // ============ 运维管理 ============
  {
    path: '/ops/batch',
    name: 'BatchOperations',
    component: () => import('../views/ops/BatchOperations.vue'),
    meta: { title: '批量操作', parent: '运维管理' }
  },
  {
    path: '/ops/notification',
    name: 'Notification',
    component: () => import('../views/ops/Notification.vue'),
    meta: { title: '消息通知配置', parent: '运维管理' }
  },
  {
    path: '/ops/performance',
    name: 'Performance',
    component: () => import('../views/ops/Performance.vue'),
    meta: { title: '性能优化配置', parent: '运维管理' }
  },
  // ============ 计费管理 ============
  {
    path: '/billing/plans',
    name: 'BillingPlans',
    component: () => import('../views/billing/Plans.vue'),
    meta: { title: '套餐管理', parent: '计费管理' }
  },
  {
    path: '/billing/packages',
    name: 'TrafficPackages',
    component: () => import('../views/billing/Packages.vue'),
    meta: { title: '流量包管理', parent: '计费管理' }
  },
  {
    path: '/billing/bills',
    name: 'Bills',
    component: () => import('../views/billing/Bills.vue'),
    meta: { title: '账单管理', parent: '计费管理' }
  },
  // ============ 高防管理 ============
  {
    path: '/defense/high-defense',
    name: 'HighDefense',
    component: () => import('../views/defense/HighDefense.vue'),
    meta: { title: '高防IP管理', parent: '高防管理' }
  },
  // ============ IP库 ============
  {
    path: '/system/ip-library',
    name: 'IPLibrary',
    component: () => import('../views/system/IPLibrary.vue'),
    meta: { title: 'IP库配置', parent: '系统管理' }
  },
  {
    path: '/system/http3',
    name: 'HTTP3Config',
    component: () => import('../views/system/HTTP3Config.vue'),
    meta: { title: 'HTTP/3配置', parent: '系统管理' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router

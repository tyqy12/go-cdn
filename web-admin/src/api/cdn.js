import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000
})

// ==================== 节点管理 ====================
export const nodeApi = {
  list: (params) => api.get('/nodes', { params }),
  get: (id) => api.get(`/nodes/${id}`),
  create: (data) => api.post('/nodes', data),
  update: (id, data) => api.put(`/nodes/${id}`, data),
  delete: (id) => api.delete(`/nodes/${id}`),
  restart: (id) => api.post(`/nodes/${id}/restart`),
  status: (id) => api.get(`/nodes/${id}/status`)
}

// ==================== 域名管理 ====================
export const domainApi = {
  list: () => api.get('/domains'),
  create: (data) => api.post('/domains', data),
  update: (id, data) => api.put(`/domains/${id}`, data),
  delete: (id) => api.delete(`/domains/${id}`),
  configs: (id) => api.get(`/domains/${id}/configs`),
  ssl: (id) => api.post(`/domains/${id}/ssl`)
}

// ==================== 安全防护 ====================
export const shieldApi = {
  getConfig: () => api.get('/security/shield/config'),
  updateConfig: (data) => api.put('/security/shield/config', data),
  whitelist: () => api.get('/security/shield/whitelist'),
  addWhitelist: (data) => api.post('/security/shield/whitelist', data),
  delWhitelist: (id) => api.delete(`/security/shield/whitelist/${id}`)
}

export const ccProtectionApi = {
  getConfig: () => api.get('/security/cc/config'),
  updateConfig: (data) => api.put('/security/cc/config', data),
  stats: () => api.get('/security/cc/stats'),
  rules: () => api.get('/security/cc/rules'),
  addRule: (data) => api.post('/security/cc/rules', data),
  delRule: (id) => api.delete(`/security/cc/rules/${id}`)
}

export const urlAuthApi = {
  getConfig: () => api.get('/security/auth/config'),
  updateConfig: (data) => api.put('/security/auth/config', data),
  keys: () => api.get('/security/auth/keys'),
  addKey: (data) => api.post('/security/auth/keys', data),
  delKey: (id) => api.delete(`/security/auth/keys/${id}`)
}

// ==================== IP库 ====================
export const ipLibraryApi = {
  info: (ip) => api.get(`/iplib/${ip}`),
  stats: () => api.get('/iplib/stats'),
  update: (data) => api.put('/iplib/update', data),
  query: (params) => api.get('/iplib/query', { params })
}

// ==================== HTTP/3 ====================
export const http3Api = {
  getConfig: () => api.get('/http3/config'),
  updateConfig: (data) => api.put('/http3/config', data),
  stats: () => api.get('/http3/stats')
}

// ==================== 性能优化 ====================
export const performanceApi = {
  getConfig: () => api.get('/performance/config'),
  updateConfig: (data) => api.put('/performance/config', data),
  stats: () => api.get('/performance/stats')
}

// ==================== 统计看板 ====================
export const dashboardApi = {
  overview: () => api.get('/stats/overview'),
  traffic: (params) => api.get('/stats/traffic', { params }),
  requests: (params) => api.get('/stats/requests', { params }),
  latency: (params) => api.get('/stats/latency', { params }),
  topUrls: () => api.get('/stats/top/urls'),
  topIPs: () => api.get('/stats/top/ips')
}

// ==================== 监控 ====================
export const monitorApi = {
  nodes: () => api.get('/monitor/nodes'),
  domains: () => api.get('/monitor/domains'),
  alerts: () => api.get('/monitor/alerts'),
  check: (id) => api.post(`/monitor/check/${id}`),
  history: (params) => api.get('/monitor/history', { params })
}

// ==================== 区域监控 ====================
export const regionMonitorApi = {
  listTerminals: () => api.get('/monitor/region/terminals'),
  createTerminal: (data) => api.post('/monitor/region/terminals', data),
  updateTerminal: (id, data) => api.put(`/monitor/region/terminals/${id}`, data),
  deleteTerminal: (id) => api.delete(`/monitor/region/terminals/${id}`),
  enableTerminal: (id) => api.post(`/monitor/region/terminals/${id}/enable`),
  disableTerminal: (id) => api.post(`/monitor/region/terminals/${id}/disable`),
  listTasks: () => api.get('/monitor/region/tasks'),
  createTask: (data) => api.post('/monitor/region/tasks', data),
  updateTask: (id, data) => api.put(`/monitor/region/tasks/${id}`, data),
  deleteTask: (id) => api.delete(`/monitor/region/tasks/${id}`),
  enableTask: (id) => api.post(`/monitor/region/tasks/${id}/enable`),
  disableTask: (id) => api.post(`/monitor/region/tasks/${id}/disable`),
  getResults: (params) => api.get('/monitor/region/results', { params })
}

// ==================== L2节点 ====================
export const l2NodeApi = {
  list: () => api.get('/l2/nodes'),
  create: (data) => api.post('/l2/nodes', data),
  update: (id, data) => api.put(`/l2/nodes/${id}`, data),
  delete: (id) => api.delete(`/l2/nodes/${id}`),
  sync: (id) => api.post(`/l2/nodes/${id}/sync`)
}

// ==================== DNS智能调度 ====================
export const dnsSchedulerApi = {
  list: () => api.get('/dns/scheduler/rules'),
  create: (data) => api.post('/dns/scheduler/rules', data),
  update: (id, data) => api.put(`/dns/scheduler/rules/${id}`, data),
  delete: (id) => api.delete(`/dns/scheduler/rules/${id}`)
}

// ==================== 智能DNS ====================
export const smartDnsApi = {
  getConfig: () => api.get('/dns/smart/config'),
  updateConfig: (data) => api.put('/dns/smart/config', data),
  pools: () => api.get('/dns/smart/pools'),
  createPool: (data) => api.post('/dns/smart/pools', data),
  updatePool: (id, data) => api.put(`/dns/smart/pools/${id}`, data),
  deletePool: (id) => api.delete(`/dns/smart/pools/${id}`)
}

// ==================== 访问日志 ====================
export const accessLogApi = {
  list: (params) => api.get('/logs/access', { params }),
  export: (params) => api.get('/logs/export', { params }),
  stats: () => api.get('/logs/stats'),
  search: (params) => api.post('/logs/search', params)
}

// ==================== 批量操作 ====================
export const batchApi = {
  execute: (data) => api.post('/batch/execute', data),
  status: (id) => api.get(`/batch/status/${id}`),
  history: () => api.get('/batch/history')
}

// ==================== 对象存储 ====================
export const objectStorageApi = {
  list: () => api.get('/storage'),
  create: (data) => api.post('/storage', data),
  update: (id, data) => api.put(`/storage/${id}`, data),
  delete: (id) => api.delete(`/storage/${id}`),
  test: (id) => api.post(`/storage/${id}/test`)
}

// ==================== 消息通知 ====================
export const notificationApi = {
  list: () => api.get('/notifications'),
  create: (data) => api.post('/notifications', data),
  update: (id, data) => api.put(`/notifications/${id}`, data),
  delete: (id) => api.delete(`/notifications/${id}`),
  test: (id) => api.post(`/notifications/${id}/test`)
}

// ==================== 边缘计算 ====================
export const edgeComputingApi = {
  list: () => api.get('/edge/functions'),
  get: (id) => api.get(`/edge/functions/${id}`),
  create: (data) => api.post('/edge/functions', data),
  update: (id, data) => api.put(`/edge/functions/${id}`, data),
  delete: (id) => api.delete(`/edge/functions/${id}`),
  deploy: (id) => api.post(`/edge/functions/${id}/deploy`),
  undeploy: (id) => api.post(`/edge/functions/${id}/undeploy`),
  logs: (id) => api.get(`/edge/functions/${id}/logs`)
}

// ==================== HLS加密 ====================
export const hlsEncryptionApi = {
  getConfig: () => api.get('/media/hls/config'),
  updateConfig: (data) => api.put('/media/hls/config', data),
  getKeys: () => api.get('/media/hls/keys'),
  createKey: (data) => api.post('/media/hls/keys', data),
  deleteKey: (id) => api.delete(`/media/hls/keys/${id}`)
}

// ==================== 计费管理 ====================
export const billingApi = {
  overview: () => api.get('/billing/overview'),
  plans: () => api.get('/billing/plans'),
  packages: () => api.get('/billing/packages'),
  bills: (params) => api.get('/billing/bills', { params }),
  usage: () => api.get('/billing/usage')
}

// ==================== 高防IP ====================
export const highDefenseApi = {
  list: () => api.get('/defense/ips'),
  get: (id) => api.get(`/defense/ips/${id}`),
  purchase: (data) => api.post('/defense/ips/purchase', data),
  enable: (id) => api.post(`/defense/ips/${id}/enable`),
  disable: (id) => api.post(`/defense/ips/${id}/disable`),
  rules: (id) => api.get(`/defense/ips/${id}/rules`),
  updateRules: (id, data) => api.put(`/defense/ips/${id}/rules`, data)
}

// ==================== 套餐管理 ====================
export const plansApi = {
  list: () => api.get('/plans'),
  create: (data) => api.post('/plans', data),
  update: (id, data) => api.put(`/plans/${id}`, data),
  delete: (id) => api.delete(`/plans/${id}`),
  subscribe: (id) => api.post(`/plans/${id}/subscribe`)
}

// ==================== 流量包 ====================
export const packagesApi = {
  list: () => api.get('/packages'),
  create: (data) => api.post('/packages', data),
  purchase: (id) => api.post(`/packages/${id}/purchase`),
  usage: (id) => api.get(`/packages/${id}/usage`)
}

// ==================== 节点部署 ====================
export const deployApi = {
  generateScript: (data) => api.post('/nodes/deploy-script', data),
  getScript: (scriptId) => api.get(`/nodes/deploy-script/${scriptId}`),
  downloadScript: (scriptId) => api.get(`/nodes/deploy-script/${scriptId}/download`, {
    responseType: 'blob'
  }),
  quickInstall: (data) => api.post('/nodes/quick-install', data)
}

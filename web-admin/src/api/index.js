import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000
})

// 节点管理
export const nodeApi = {
  list: (params) => api.get('/nodes', { params }),
  get: (id) => api.get(`/nodes/${id}`),
  update: (id, data) => api.put(`/nodes/${id}`, data),
  delete: (id) => api.delete(`/nodes/${id}`),
  updateTags: (id, tags) => api.post(`/nodes/${id}/tags`, { tags }),
  online: (id) => api.post(`/nodes/${id}/online`),
  offline: (id) => api.post(`/nodes/${id}/offline`),
  restart: (id) => api.post(`/nodes/${id}/restart`),
  reload: (id) => api.post(`/nodes/${id}/reload`)
}

// 配置管理
export const configApi = {
  list: (params) => api.get('/configs', { params }),
  get: (version) => api.get(`/configs/${version}`),
  create: (data) => api.post('/configs', data),
  publish: (version) => api.post(`/configs/${version}/publish`),
  rollback: (version) => api.post(`/configs/${version}/rollback`),
  diff: (v1, v2) => api.get(`/configs/${v1}/diff/${v2}`)
}

// 指令管理
export const commandApi = {
  execute: (data) => api.post('/commands', data),
  status: (taskId) => api.get(`/commands/${taskId}`),
  history: (params) => api.get('/commands', { params })
}

// 监控数据
export const metricsApi = {
  node: (id) => api.get(`/metrics/nodes/${id}`),
  aggregate: (params) => api.get('/metrics/aggregate', { params }),
  prometheus: (query) => api.get('/metrics/prometheus', { params: { query } })
}

// 告警管理
export const alertApi = {
  list: (params) => api.get('/alerts', { params }),
  get: (id) => api.get(`/alerts/${id}`),
  silence: (id) => api.post(`/alerts/${id}/silence`)
}

export default api

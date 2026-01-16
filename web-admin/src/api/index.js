import axios from 'axios'
import { ElMessage } from 'element-plus'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000
})

// 请求拦截器 - 添加 JWT Token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// 响应拦截器 - 统一错误处理
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status, data } = error.response
      switch (status) {
        case 401:
          // 未授权，清除 token 并跳转登录
          localStorage.removeItem('token')
          window.location.href = '/login'
          break
        case 403:
          ElMessage.error(data.message || '没有权限访问')
          break
        case 404:
          ElMessage.error('请求的资源不存在')
          break
        case 500:
          ElMessage.error('服务器错误，请稍后重试')
          break
      }
    }
    return Promise.reject(error)
  }
)

// ==================== 节点管理 ====================
export const nodeApi = {
  // 列出所有节点
  list: (params) => api.get('/nodes', { params }),

  // 获取单个节点 (可选)
  get: (id) => api.get(`/nodes/${id}`),

  // 更新节点 (可选)
  update: (id, data) => api.put(`/nodes/${id}`, data),

  // 删除节点 (可选)
  delete: (id) => api.delete(`/nodes/${id}`),

  // 更新标签 (可选)
  updateTags: (id, tags) => api.post(`/nodes/${id}/tags`, { tags }),

  // 上线节点 (可选)
  online: (id) => api.post(`/nodes/${id}/online`),

  // 下线节点 (可选)
  offline: (id) => api.post(`/nodes/${id}/offline`),

  // 重启服务
  restart: (id) => api.post(`/nodes/${id}/restart`),

  // 重载配置
  reload: (id) => api.post(`/nodes/${id}/reload`)
}

// ==================== 节点部署 ====================
export const deployApi = {
  // 生成部署脚本
  generateScript: (data) => api.post('/nodes/deploy-script', data),

  // 获取脚本内容
  getScript: (scriptId) => api.get(`/nodes/deploy-script/${scriptId}`),

  // 下载脚本
  downloadScript: (scriptId) => api.get(`/nodes/deploy-script/${scriptId}/download`, {
    responseType: 'blob'
  }),

  // 快速安装命令
  quickInstall: (data) => api.post('/nodes/quick-install', data)
}

// ==================== 配置管理 ====================
export const configApi = {
  // 列出配置 (可选)
  list: (params) => api.get('/configs', { params }),

  // 获取配置 (可选)
  get: (version) => api.get(`/configs/${version}`),

  // 创建配置 (可选)
  create: (data) => api.post('/configs', data),

  // 发布配置 (可选)
  publish: (version) => api.post(`/configs/${version}/publish`),

  // 回滚配置 (可选)
  rollback: (version) => api.post(`/configs/${version}/rollback`)
}

// ==================== 指令管理 ====================
export const commandApi = {
  // 执行指令
  execute: (data) => api.post('/commands', data),

  // 获取任务状态
  status: (taskId) => api.get(`/commands/${taskId}`),

  // 获取执行历史
  history: (params) => api.get('/commands', { params })
}

// ==================== 监控数据 ====================
export const metricsApi = {
  // 获取节点监控数据
  node: (id) => api.get(`/metrics/nodes/${id}`),

  // 获取聚合监控数据
  aggregate: (params) => api.get('/metrics/aggregate', { params })
}

// ==================== 告警管理 ====================
export const alertApi = {
  // 列出告警
  list: (params) => api.get('/alerts', { params }),

  // 获取告警详情
  get: (id) => api.get(`/alerts/${id}`),

  // 静默告警
  silence: (id) => api.post(`/alerts/${id}/silence`)
}

// ==================== 健康检查 ====================
export const healthApi = {
  check: () => api.get('/health')
}

export default api

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { nodeApi, configApi, alertApi, commandApi, deployApi } from '../api'

export const useNodeStore = defineStore('nodes', () => {
  const nodes = ref([])
  const loading = ref(false)
  const filter = ref({ type: '', region: '', status: '' })

  const onlineNodes = computed(() => nodes.value.filter(n => n.status === 'online'))
  const totalConnections = computed(() =>
    nodes.value.reduce((sum, n) => sum + (n.connections || n.ActiveConnections || 0), 0)
  )
  const regions = computed(() => {
    const r = new Set(nodes.value.map(n => n.region))
    return Array.from(r).filter(Boolean)
  })

  const filteredNodes = computed(() => {
    return nodes.value.filter(n => {
      if (filter.value.type && n.type !== filter.value.type) return false
      if (filter.value.region && n.region !== filter.value.region) return false
      if (filter.value.status && n.status !== filter.value.status) return false
      return true
    })
  })

  async function fetchNodes() {
    loading.value = true
    try {
      const res = await nodeApi.list()
      // 后端直接返回节点数组
      nodes.value = Array.isArray(res.data) ? res.data : (res.data.nodes || [])
    } catch (error) {
      console.error('获取节点列表失败:', error)
      nodes.value = []
    } finally {
      loading.value = false
    }
  }

  async function executeCommand(id, command) {
    const method = nodeApi[command]
    if (method) {
      await method(id)
      await fetchNodes()
    }
  }

  return {
    nodes,
    loading,
    filter,
    onlineNodes,
    totalConnections,
    regions,
    filteredNodes,
    fetchNodes,
    executeCommand
  }
})

export const useConfigStore = defineStore('configs', () => {
  const configs = ref([])
  const loading = ref(false)

  async function fetchConfigs() {
    loading.value = true
    try {
      const res = await configApi.list()
      configs.value = Array.isArray(res.data) ? res.data : (res.data.configs || [])
    } catch (error) {
      console.error('获取配置列表失败:', error)
      configs.value = []
    } finally {
      loading.value = false
    }
  }

  async function publish(version) {
    await configApi.publish(version)
    await fetchConfigs()
  }

  async function rollback(version) {
    await configApi.rollback(version)
    await fetchConfigs()
  }

  return { configs, loading, fetchConfigs, publish, rollback }
})

export const useAlertStore = defineStore('alerts', () => {
  const alerts = ref([])
  const loading = ref(false)

  const firingAlerts = computed(() =>
    alerts.value.filter(a => a.status === 'firing' || a.Status === 'firing')
  )

  async function fetchAlerts() {
    loading.value = true
    try {
      const res = await alertApi.list()
      // 后端返回 {alerts: [...]} 或直接数组
      alerts.value = Array.isArray(res.data) ? res.data : (res.data.alerts || [])
    } catch (error) {
      console.error('获取告警列表失败:', error)
      alerts.value = []
    } finally {
      loading.value = false
    }
  }

  async function silence(id) {
    await alertApi.silence(id)
    await fetchAlerts()
  }

  return { alerts, loading, firingAlerts, fetchAlerts, silence }
})

export const useCommandStore = defineStore('commands', () => {
  const history = ref([])
  const loading = ref(false)
  const currentTaskId = ref(null)
  const currentTaskStatus = ref(null)

  async function fetchHistory() {
    loading.value = true
    try {
      const res = await commandApi.history()
      history.value = Array.isArray(res.data) ? res.data : (res.data.commands || [])
    } catch (error) {
      console.error('获取指令历史失败:', error)
      history.value = []
    } finally {
      loading.value = false
    }
  }

  async function execute(data) {
    try {
      const res = await commandApi.execute(data)
      // 后端返回 {task_id: "xxx"}
      currentTaskId.value = res.data.task_id || res.data.TaskID
      currentTaskStatus.value = 'pending'
      await fetchHistory()
      return currentTaskId.value
    } catch (error) {
      console.error('执行指令失败:', error)
      throw error
    }
  }

  async function getTaskStatus(taskId) {
    try {
      const res = await commandApi.status(taskId)
      currentTaskStatus.value = res.data.status || res.data.Status
      return res.data
    } catch (error) {
      console.error('获取任务状态失败:', error)
      throw error
    }
  }

  return {
    history,
    loading,
    currentTaskId,
    currentTaskStatus,
    fetchHistory,
    execute,
    getTaskStatus
  }
})

export const useDeployStore = defineStore('deploy', () => {
  const loading = ref(false)
  const currentScript = ref('')
  const currentScriptId = ref('')

  async function generateScript(data) {
    loading.value = true
    try {
      const res = await deployApi.generateScript(data)
      currentScriptId.value = res.data.script_id || res.data.ScriptID
      // 获取脚本内容
      const scriptRes = await deployApi.getScript(currentScriptId.value)
      currentScript.value = typeof scriptRes.data === 'string'
        ? scriptRes.data
        : (scriptRes.data.script || scriptRes.data.content || '')
      return currentScriptId.value
    } catch (error) {
      console.error('生成部署脚本失败:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  async function downloadScript() {
    if (!currentScriptId.value) return
    try {
      const response = await deployApi.downloadScript(currentScriptId.value)
      const blob = new Blob([currentScript.value], { type: 'text/plain' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `deploy-${currentScriptId.value}.sh`
      link.click()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('下载脚本失败:', error)
      throw error
    }
  }

  return {
    loading,
    currentScript,
    currentScriptId,
    generateScript,
    downloadScript
  }
})

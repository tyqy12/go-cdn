import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { nodeApi, configApi, alertApi, commandApi } from '../api'

export const useNodeStore = defineStore('nodes', () => {
  const nodes = ref([])
  const loading = ref(false)
  const filter = ref({ type: '', region: '', status: '' })

  const onlineNodes = computed(() => nodes.value.filter(n => n.status === 'online'))
  const totalConnections = computed(() => 
    nodes.value.reduce((sum, n) => sum + (n.connections || 0), 0)
  )
  const regions = computed(() => {
    const r = new Set(nodes.value.map(n => n.region))
    return Array.from(r)
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
      nodes.value = res.data.nodes || []
    } finally {
      loading.value = false
    }
  }

  async function executeCommand(id, command) {
    await nodeApi[command](id)
    await fetchNodes()
  }

  return { nodes, loading, filter, onlineNodes, totalConnections, regions, filteredNodes, fetchNodes, executeCommand }
})

export const useConfigStore = defineStore('configs', () => {
  const configs = ref([])
  const loading = ref(false)

  async function fetchConfigs() {
    loading.value = true
    try {
      const res = await configApi.list()
      configs.value = res.data.configs || []
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

  const firingAlerts = computed(() => alerts.value.filter(a => a.status === 'firing'))

  async function fetchAlerts() {
    loading.value = true
    try {
      const res = await alertApi.list()
      alerts.value = res.data.alerts || []
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

  async function fetchHistory() {
    loading.value = true
    try {
      const res = await commandApi.history()
      history.value = res.data.commands || []
    } finally {
      loading.value = false
    }
  }

  async function execute(data) {
    await commandApi.execute(data)
    await fetchHistory()
  }

  return { history, loading, fetchHistory, execute }
})

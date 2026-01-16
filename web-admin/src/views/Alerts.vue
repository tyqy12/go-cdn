<template>
  <div class="space-y-6">
    <el-card>
      <template #header>
        <div class="flex gap-2">
          <el-button :type="filter === 'firing' ? 'danger' : ''" @click="filter = 'firing'">
            活跃告警 ({{ alertStore.firingAlerts.length }})
          </el-button>
          <el-button :type="filter === 'all' ? 'info' : ''" @click="filter = 'all'">
            全部 ({{ alertStore.alerts.length }})
          </el-button>
          <el-button @click="alertStore.fetchAlerts()" :loading="alertStore.loading">
            <el-icon><Refresh /></el-icon>刷新
          </el-button>
        </div>
      </template>
      <div class="space-y-4">
        <el-card v-for="alert in displayAlerts" :key="alert.id || alert.AlertID" :class="{ 'border-red-500': alert.severity === 'critical' || alert.Severity === 'critical' }">
          <div class="flex items-start justify-between">
            <div>
              <div class="flex items-center gap-2">
                <h3 class="font-bold text-lg">{{ alert.name || alert.Message || alert.message }}</h3>
                <el-tag :type="getSeverityType(alert.severity || alert.Severity)" size="small">
                  {{ alert.severity || alert.Severity || 'unknown' }}
                </el-tag>
              </div>
              <p class="text-gray-500 mt-1">{{ alert.description || alert.Message || '' }}</p>
              <div class="flex gap-4 mt-2 text-sm text-gray-400">
                <span v-if="alert.node || alert.NodeID"><el-icon><Location /></el-icon> {{ alert.node || alert.NodeID }}</span>
                <span><el-icon><Clock /></el-icon> {{ formatTime(alert.starts_at || alert.StartedAt || alert.CreatedAt) }}</span>
              </div>
            </div>
            <el-button @click="handleSilence(alert.id || alert.AlertID)" :disabled="alert.silenced || alert.Silenced">静默</el-button>
          </div>
        </el-card>
        <el-empty v-if="displayAlerts.length === 0" description="暂无告警" />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Location, Clock, Refresh } from '@element-plus/icons-vue'
import { useAlertStore } from '../stores'

const alertStore = useAlertStore()
const filter = ref('firing')

const displayAlerts = computed(() => {
  return filter.value === 'firing' ? alertStore.firingAlerts : alertStore.alerts
})

const getSeverityType = (severity) => {
  switch (severity) {
    case 'critical': return 'danger'
    case 'warning': return 'warning'
    case 'info': return 'info'
    default: return 'info'
  }
}

const handleSilence = async (id) => {
  try {
    await alertStore.silence(id)
    ElMessage.success('告警已静默')
  } catch {
    ElMessage.error('静默告警失败')
  }
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN')
}

onMounted(() => alertStore.fetchAlerts())
</script>

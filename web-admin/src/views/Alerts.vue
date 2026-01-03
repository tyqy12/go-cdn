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
        </div>
      </template>
      <div class="space-y-4">
        <el-card v-for="alert in displayAlerts" :key="alert.id" :class="{ 'border-red-500': alert.severity === 'critical' }">
          <div class="flex items-start justify-between">
            <div>
              <div class="flex items-center gap-2">
                <h3 class="font-bold text-lg">{{ alert.name }}</h3>
                <el-tag :type="alert.severity === 'critical' ? 'danger' : 'warning'" size="small">
                  {{ alert.severity }}
                </el-tag>
              </div>
              <p class="text-gray-500 mt-1">{{ alert.description }}</p>
              <div class="flex gap-4 mt-2 text-sm text-gray-400">
                <span><el-icon><Location /></el-icon> {{ alert.node }}</span>
                <span><el-icon><Clock /></el-icon> {{ formatTime(alert.starts_at) }}</span>
              </div>
            </div>
            <el-button @click="handleSilence(alert.id)">静默</el-button>
          </div>
        </el-card>
        <el-empty v-if="displayAlerts.length === 0" description="暂无告警" />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Location, Clock } from '@element-plus/icons-vue'
import { useAlertStore } from '../stores'

const alertStore = useAlertStore()
const filter = ref('firing')

const displayAlerts = computed(() => {
  return filter.value === 'firing' ? alertStore.firingAlerts : alertStore.alerts
})

const handleSilence = async (id) => {
  await alertStore.silence(id)
}

const formatTime = (time) => time ? new Date(time).toLocaleString('zh-CN') : '-'

onMounted(() => alertStore.fetchAlerts())
</script>

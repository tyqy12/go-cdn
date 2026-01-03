<template>
  <el-config-provider :locale="locale">
    <div class="flex h-screen bg-gray-100">
      <!-- 侧边栏 -->
      <aside class="w-64 bg-gray-900 text-white flex flex-col">
        <div class="p-6 border-b border-gray-700">
          <h1 class="text-xl font-bold flex items-center gap-2">
            <el-icon class="text-blue-400"><Cloudy /></el-icon>
            AI CDN Manager
          </h1>
          <p class="text-gray-400 text-sm mt-1">智能CDN管理系统</p>
        </div>
        
        <nav class="flex-1 p-4 overflow-auto">
          <el-menu
            :default-active="activeMenu"
            class="border-none bg-transparent"
            text-color="#9ca3af"
            active-text-color="#fff"
          >
            <!-- 基础功能 -->
            <el-menu-item index="Dashboard" @click="router.push('/')">
              <el-icon><DataAnalysis /></el-icon>
              <span>仪表盘</span>
            </el-menu-item>
            <el-menu-item index="Nodes" @click="router.push('/nodes')">
              <el-icon><Grid /></el-icon>
              <span>节点管理</span>
            </el-menu-item>
            <el-menu-item index="Monitor" @click="router.push('/monitor')">
              <el-icon><TrendCharts /></el-icon>
              <span>监控面板</span>
            </el-menu-item>
            <el-menu-item index="Alerts" @click="router.push('/alerts')">
              <el-icon><Bell /></el-icon>
              <span>告警中心</span>
            </el-menu-item>
            <el-menu-item index="Configs" @click="router.push('/configs')">
              <el-icon><Files /></el-icon>
              <span>配置管理</span>
            </el-menu-item>
            
            <!-- 安全防护 -->
            <el-sub-menu index="security">
              <template #title>
                <el-icon><Lock /></el-icon>
                <span>安全防护</span>
              </template>
              <el-menu-item index="Shield" @click="router.push('/security/shield')">5秒盾</el-menu-item>
              <el-menu-item index="CCProtection" @click="router.push('/security/cc-protection')">CC防护</el-menu-item>
              <el-menu-item index="URLAuth" @click="router.push('/security/url-auth')">URL鉴权</el-menu-item>
              <el-menu-item index="ActiveDefense" @click="router.push('/security/active-defense')">主动防御</el-menu-item>
            </el-sub-menu>
            
            <!-- 节点管理 -->
            <el-sub-menu index="nodes">
              <template #title>
                <el-icon><Connection /></el-icon>
                <span>节点管理</span>
              </template>
              <el-menu-item index="L2Nodes" @click="router.push('/nodes/l2')">L2节点</el-menu-item>
            </el-sub-menu>
            
            <!-- DNS管理 -->
            <el-sub-menu index="dns">
              <template #title>
                <el-icon><Position /></el-icon>
                <span>DNS管理</span>
              </template>
              <el-menu-item index="DNSScheduler" @click="router.push('/dns/scheduler')">DNS智能调度</el-menu-item>
              <el-menu-item index="SmartDNS" @click="router.push('/dns/smart')">智能DNS</el-menu-item>
            </el-sub-menu>
            
            <!-- 日志管理 -->
            <el-sub-menu index="logs">
              <template #title>
                <el-icon><Document /></el-icon>
                <span>日志管理</span>
              </template>
              <el-menu-item index="AccessLogs" @click="router.push('/logs/access')">访问日志</el-menu-item>
              <el-menu-item index="LogAnalyzer" @click="router.push('/logs/analyzer')">日志分析</el-menu-item>
            </el-sub-menu>
            
            <!-- 监控管理 -->
            <el-menu-item index="RegionMonitor" @click="router.push('/monitor/region')">
              <el-icon><Aim /></el-icon>
              <span>区域监控</span>
            </el-menu-item>
            
            <!-- 存储管理 -->
            <el-menu-item index="ObjectStorage" @click="router.push('/storage/object')">
              <el-icon><Box /></el-icon>
              <span>对象存储</span>
            </el-menu-item>
            
            <!-- 媒体服务 -->
            <el-menu-item index="HLSEncryption" @click="router.push('/media/hls')">
              <el-icon><VideoPlay /></el-icon>
              <span>HLS加密</span>
            </el-menu-item>
            
            <!-- 边缘计算 -->
            <el-menu-item index="EdgeComputing" @click="router.push('/edge/computing')">
              <el-icon><Cpu /></el-icon>
              <span>边缘计算</span>
            </el-menu-item>
            
            <!-- 运维管理 -->
            <el-sub-menu index="ops">
              <template #title>
                <el-icon><Setting /></el-icon>
                <span>运维管理</span>
              </template>
              <el-menu-item index="BatchOperations" @click="router.push('/ops/batch')">批量操作</el-menu-item>
              <el-menu-item index="Notification" @click="router.push('/ops/notification')">消息通知</el-menu-item>
              <el-menu-item index="Performance" @click="router.push('/ops/performance')">性能优化</el-menu-item>
            </el-sub-menu>
            
            <!-- 计费管理 -->
            <el-sub-menu index="billing">
              <template #title>
                <el-icon><Money /></el-icon>
                <span>计费管理</span>
              </template>
              <el-menu-item index="BillingPlans" @click="router.push('/billing/plans')">套餐管理</el-menu-item>
              <el-menu-item index="TrafficPackages" @click="router.push('/billing/packages')">流量包</el-menu-item>
              <el-menu-item index="Bills" @click="router.push('/billing/bills')">账单管理</el-menu-item>
            </el-sub-menu>
            
            <!-- 高防管理 -->
            <el-menu-item index="HighDefense" @click="router.push('/defense/high-defense')">
              <el-icon><Umbrella /></el-icon>
              <span>高防IP</span>
            </el-menu-item>
            
            <!-- 系统管理 -->
            <el-sub-menu index="system">
              <template #title>
                <el-icon><Tools /></el-icon>
                <span>系统管理</span>
              </template>
              <el-menu-item index="IPLibrary" @click="router.push('/system/ip-library')">IP库配置</el-menu-item>
              <el-menu-item index="HTTP3Config" @click="router.push('/system/http3')">HTTP/3配置</el-menu-item>
            </el-sub-menu>
            
            <el-menu-item index="Commands" @click="router.push('/commands')">
              <el-icon><Operation /></el-icon>
              <span>指令分发</span>
            </el-menu-item>
          </el-menu>
        </nav>
        
        <div class="p-4 border-t border-gray-700">
          <div class="flex items-center gap-3">
            <el-avatar :size="40" class="bg-blue-500">
              <el-icon><User /></el-icon>
            </el-avatar>
            <div>
              <p class="font-medium">Admin</p>
              <p class="text-gray-400 text-xs">管理员</p>
            </div>
          </div>
        </div>
      </aside>

      <!-- 主内容 -->
      <main class="flex-1 flex flex-col overflow-hidden">
        <header class="bg-white shadow-sm px-6 py-4 flex items-center justify-between">
          <h2 class="text-xl font-bold text-gray-800">{{ currentRoute?.meta?.title || '仪表盘' }}</h2>
          <div class="flex items-center gap-4">
            <el-button :icon="Refresh" circle @click="refreshData" />
            <el-tag type="success" effect="dark">
              <el-icon class="animate-pulse"><CircleCheckFilled /></el-icon>
              系统正常
            </el-tag>
          </div>
        </header>

        <div class="flex-1 overflow-auto p-6">
          <router-view />
        </div>
      </main>
    </div>
  </el-config-provider>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { Refresh, CircleCheckFilled, Cloudy, DataAnalysis, Grid, Files, Operation, Bell, TrendCharts, User, Lock, Connection, Position, Document, Aim, Box, VideoPlay, Cpu, Setting, Money, Umbrella, Tools } from '@element-plus/icons-vue'
import { useAlertStore } from './stores'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'

const locale = zhCn
const router = useRouter()
const route = useRoute()
const alertStore = useAlertStore()

const activeMenu = computed(() => route.name)
const currentRoute = computed(() => route)
const alertCount = computed(() => alertStore.firingAlerts.length)

const refreshData = () => {
  alertStore.fetchAlerts()
}

onMounted(() => {
  refreshData()
  setInterval(refreshData, 30000)
})
</script>

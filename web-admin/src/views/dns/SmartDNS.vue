<template>
  <div class="smart-dns">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>智能DNS配置</span>
          <div>
            <el-button type="warning" @click="handleRestart" :loading="restarting">
              重启DNS服务
            </el-button>
            <el-button type="primary" @click="handleSave">保存配置</el-button>
          </div>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <!-- 服务状态 -->
        <el-tab-pane label="服务状态" name="status">
          <el-row :gutter="20">
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>服务状态</template>
                <div class="status-value">
                  <el-tag :type="serviceStatus.running ? 'success' : 'danger'" size="large">
                    {{ serviceStatus.running ? '运行中' : '已停止' }}
                  </el-tag>
                </div>
              </el-card>
            </el-col>
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>监听端口</template>
                <div class="status-value">{{ serviceStatus.port }}</div>
              </el-card>
            </el-col>
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>今日查询量</template>
                <div class="status-value">{{ formatNumber(serviceStatus.queriesToday) }}</div>
              </el-card>
            </el-col>
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>健康节点</template>
                <div class="status-value">{{ serviceStatus.healthyNodes }}/{{ serviceStatus.totalNodes }}</div>
              </el-card>
            </el-col>
          </el-row>
        </el-tab-pane>

        <!-- 基本配置 -->
        <el-tab-pane label="基本配置" name="basic">
          <el-form :model="config" label-width="160px">
            <el-form-item label="启用智能DNS">
              <el-switch v-model="config.enabled" />
            </el-form-item>

            <el-form-item label="监听端口">
              <el-input-number v-model="config.port" :min="1" :max="65535" />
            </el-form-item>

            <el-form-item label="上游DNS">
              <el-input v-model="config.upstreamDNS" placeholder="如: 8.8.8.8, 114.114.114.114" />
            </el-form-item>

            <el-form-item label="响应策略">
              <el-select v-model="config.responseStrategy">
                <el-option label="地理位置" value="geo" />
                <el-option label="最低延迟" value="latency" />
                <el-option label="负载均衡" value="load_balance" />
                <el-option label="健康检测" value="health" />
              </el-select>
            </el-form-item>

            <el-form-item label="启用缓存">
              <el-switch v-model="config.enableCache" />
            </el-form-item>

            <el-form-item label="缓存时间">
              <el-input-number v-model="config.cacheTTL" :min="0" :max="86400" />
              <span class="unit">秒</span>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- GFW防御 -->
        <el-tab-pane label="GFW防御" name="gfw">
          <el-form :model="gfwConfig" label-width="160px">
            <el-form-item label="启用GFW防御">
              <el-switch v-model="gfwConfig.enabled" />
            </el-form-item>

            <el-form-item label="故障转移">
              <el-switch v-model="gfwConfig.enableFailover" />
            </el-form-item>
          </el-form>

          <el-divider>备用IP池</el-divider>

          <div class="table-toolbar">
            <el-button type="primary" @click="showAddBackupIpDialog = true">添加备用IP</el-button>
          </div>

          <el-table :data="backupIps" style="width: 100%">
            <el-table-column prop="ip" label="IP地址" width="150" />
            <el-table-column prop="region" label="地区" width="100" />
            <el-table-column prop="weight" label="权重" width="80" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteBackupIp(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 地理位置路由 -->
        <el-tab-pane label="地理位置路由" name="geo">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddGeoRouteDialog = true">添加路由规则</el-button>
          </div>

          <el-table :data="geoRoutes" style="width: 100%">
            <el-table-column prop="domain" label="域名" width="200" />
            <el-table-column prop="region" label="匹配地区" width="120" />
            <el-table-column prop="targetIps" label="目标IP" />
            <el-table-column prop="strategy" label="策略" width="100" />
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button size="small" @click="editGeoRoute(row)">编辑</el-button>
                <el-button type="danger" size="small" @click="deleteGeoRoute(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 添加备用IP对话框 -->
    <el-dialog v-model="showAddBackupIpDialog" title="添加备用IP" width="500px">
      <el-form :model="backupIpForm" label-width="100px">
        <el-form-item label="IP地址">
          <el-input v-model="backupIpForm.ip" placeholder="如: 1.2.3.4" />
        </el-form-item>
        <el-form-item label="地区">
          <el-select v-model="backupIpForm.region">
            <el-option label="中国大陆" value="cn" />
            <el-option label="香港" value="hk" />
            <el-option label="美国" value="us" />
          </el-select>
        </el-form-item>
        <el-form-item label="权重">
          <el-input-number v-model="backupIpForm.weight" :min="1" :max="100" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddBackupIpDialog = false">取消</el-button>
        <el-button type="primary" @click="addBackupIp">确定</el-button>
      </template>
    </el-dialog>

    <!-- 添加地理位置路由对话框 -->
    <el-dialog v-model="showAddGeoRouteDialog" title="添加路由规则" width="600px">
      <el-form :model="geoRouteForm" label-width="100px">
        <el-form-item label="域名">
          <el-input v-model="geoRouteForm.domain" placeholder="如: example.com" />
        </el-form-item>
        <el-form-item label="匹配地区">
          <el-select v-model="geoRouteForm.region">
            <el-option label="中国大陆" value="cn" />
            <el-option label="香港" value="hk" />
            <el-option label="美国" value="us" />
          </el-select>
        </el-form-item>
        <el-form-item label="目标IP">
          <el-input v-model="geoRouteForm.targetIps" placeholder="多个IP用逗号分隔" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddGeoRouteDialog = false">取消</el-button>
        <el-button type="primary" @click="saveGeoRoute">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { smartDnsApi } from '../../api/cdn'

const activeTab = ref('status')
const restarting = ref(false)
const showAddBackupIpDialog = ref(false)
const showAddGeoRouteDialog = ref(false)

const serviceStatus = reactive({ running: false, port: 53, queriesToday: 0, totalNodes: 0, healthyNodes: 0 })
const config = reactive({ enabled: true, port: 53, upstreamDNS: '8.8.8.8, 114.114.114.114', responseStrategy: 'geo', enableCache: true, cacheTTL: 600 })
const gfwConfig = reactive({ enabled: true, enableFailover: true })
const backupIps = ref([])
const geoRoutes = ref([])
const backupIpForm = reactive({ ip: '', region: 'cn', weight: 50 })
const geoRouteForm = reactive({ id: null, domain: '', region: 'cn', targetIps: '', strategy: 'all' })

const formatNumber = (num) => {
  if (!num) return '0'
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

const loadStatus = async () => {
  try {
    const { data } = await smartDnsApi.getStatus()
    Object.assign(serviceStatus, data)
  } catch (e) { console.error(e) }
}

const loadConfig = async () => {
  try {
    const { data } = await smartDnsApi.getConfig()
    Object.assign(config, data)
  } catch (e) { ElMessage.error('加载配置失败') }
}

const loadGfwConfig = async () => {
  try {
    const { data } = await smartDnsApi.getGfwConfig()
    Object.assign(gfwConfig, data)
  } catch (e) { ElMessage.error('加载GFW配置失败') }
}

const loadBackupIps = async () => {
  try {
    const { data } = await smartDnsApi.getBackupIps()
    backupIps.value = data
  } catch (e) { ElMessage.error('加载备用IP失败') }
}

const loadGeoRoutes = async () => {
  try {
    const { data } = await smartDnsApi.getGeoRoutes()
    geoRoutes.value = data
  } catch (e) { ElMessage.error('加载路由规则失败') }
}

const handleSave = async () => {
  try {
    await smartDnsApi.updateConfig(config)
    await smartDnsApi.updateGfwConfig(gfwConfig)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

const handleRestart = async () => {
  try {
    await ElMessageBox.confirm('确定要重启DNS服务吗？', '提示')
    restarting.value = true
    await smartDnsApi.restart()
    ElMessage.success('重启成功')
    loadStatus()
  } catch (e) { /* 用户取消 */ }
  restarting.value = false
}

const addBackupIp = async () => {
  try {
    await smartDnsApi.addBackupIp(backupIpForm)
    ElMessage.success('添加成功')
    showAddBackupIpDialog.value = false
    backupIpForm.ip = ''
    loadBackupIps()
  } catch (e) { ElMessage.error('添加失败') }
}

const deleteBackupIp = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此备用IP吗？', '提示')
    await smartDnsApi.deleteBackupIp(id)
    ElMessage.success('删除成功')
    loadBackupIps()
  } catch (e) { /* 用户取消 */ }
}

const saveGeoRoute = async () => {
  try {
    if (geoRouteForm.id) {
      await smartDnsApi.updateGeoRoute(geoRouteForm.id, geoRouteForm)
    } else {
      await smartDnsApi.addGeoRoute(geoRouteForm)
    }
    ElMessage.success('保存成功')
    showAddGeoRouteDialog.value = false
    geoRouteForm.domain = ''
    geoRouteForm.targetIps = ''
    loadGeoRoutes()
  } catch (e) { ElMessage.error('保存失败') }
}

const editGeoRoute = (route) => {
  Object.assign(geoRouteForm, route)
  showAddGeoRouteDialog.value = true
}

const deleteGeoRoute = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此路由规则吗？', '提示')
    await smartDnsApi.deleteGeoRoute(id)
    ElMessage.success('删除成功')
    loadGeoRoutes()
  } catch (e) { /* 用户取消 */ }
}

onMounted(() => {
  loadStatus()
  loadConfig()
  loadGfwConfig()
  loadBackupIps()
  loadGeoRoutes()
})
</script>

<style scoped>
.smart-dns { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
.table-toolbar { display: flex; align-items: center; margin-bottom: 16px }
.status-value { font-size: 24px; font-weight: bold }
</style>

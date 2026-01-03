<template>
  <div class="shield-config">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>5秒盾配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <!-- 基本配置 -->
        <el-tab-pane label="基本配置" name="basic">
          <el-form :model="config" label-width="160px">
            <el-form-item label="启用5秒盾">
              <el-switch v-model="config.enabled" />
              <span class="form-tip">启用后将对新访客进行JS挑战验证</span>
            </el-form-item>

            <el-form-item label="挑战模式">
              <el-select v-model="config.challengeMode">
                <el-option label="JavaScript挑战" value="js_challenge" />
                <el-option label="CAPTCHA验证" value="captcha" />
                <el-option label="简洁模式" value="simple" />
              </el-select>
            </el-form-item>

            <el-form-item label="Cookie有效期">
              <el-input-number v-model="config.cookieDuration" :min="60" :max="86400" />
              <span class="unit">秒</span>
            </el-form-item>

            <el-form-item label="冷却时间">
              <el-input-number v-model="config.cooldownPeriod" :min="5" :max="300" />
              <span class="unit">秒</span>
            </el-form-item>

            <el-form-item label="IP限制阈值">
              <el-input-number v-model="config.ipThreshold" :min="1" :max="100" />
              <span class="unit">次/分钟</span>
            </el-form-item>

            <el-form-item label="严格模式">
              <el-switch v-model="config.strictMode" />
              <span class="form-tip">严格模式下，挑战失败的用户将被加入临时黑名单</span>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- 白名单管理 -->
        <el-tab-pane label="白名单" name="whitelist">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddWhitelistDialog = true">
              添加白名单
            </el-button>
            <el-input
              v-model="whitelistSearch"
              placeholder="搜索白名单"
              style="width: 240px; margin-left: auto"
              clearable
            />
          </div>

          <el-table :data="whitelist" style="width: 100%">
            <el-table-column prop="type" label="类型" width="100">
              <template #default="{ row }">
                <el-tag :type="row.type === 'ip' ? 'success' : 'primary'" size="small">
                  {{ row.type }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="值" />
            <el-table-column prop="remark" label="备注" />
            <el-table-column prop="createdAt" label="添加时间" width="180" />
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteWhitelist(row.id)">
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 黑名单管理 -->
        <el-tab-pane label="黑名单" name="blacklist">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddBlacklistDialog = true">
              添加黑名单
            </el-button>
            <el-input
              v-model="blacklistSearch"
              placeholder="搜索黑名单"
              style="width: 240px; margin-left: auto"
              clearable
            />
          </div>

          <el-table :data="blacklist" style="width: 100%">
            <el-table-column prop="type" label="类型" width="100">
              <template #default="{ row }">
                <el-tag type="danger" size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="值" />
            <el-table-column prop="expireAt" label="过期时间" width="180" />
            <el-table-column prop="reason" label="封禁原因" />
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button type="success" size="small" @click="unblockBlacklist(row.id)">
                  解封
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 统计信息 -->
        <el-tab-pane label="统计" name="stats">
          <el-row :gutter="20">
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>今日挑战次数</template>
                <div class="stat-value">{{ stats.todayChallenges }}</div>
              </el-card>
            </el-col>
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>通过率</template>
                <div class="stat-value">{{ stats.passRate }}%</div>
              </el-card>
            </el-col>
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>拦截次数</template>
                <div class="stat-value">{{ stats.blockedCount }}</div>
              </el-card>
            </el-col>
            <el-col :span="6">
              <el-card shadow="never">
                <template #header>白名单IP数</template>
                <div class="stat-value">{{ stats.whitelistCount }}</div>
              </el-card>
            </el-col>
          </el-row>

          <el-card style="margin-top: 20px">
            <template #header>挑战趋势</template>
            <div ref="chartRef" class="chart-container"></div>
          </el-card>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 添加白名单对话框 -->
    <el-dialog v-model="showAddWhitelistDialog" title="添加白名单" width="500px">
      <el-form :model="whitelistForm" label-width="100px">
        <el-form-item label="类型">
          <el-select v-model="whitelistForm.type">
            <el-option label="IP地址" value="ip" />
            <el-option label="IP段" value="ip_range" />
            <el-option label="国家" value="country" />
            <el-option label="运营商" value="isp" />
          </el-select>
        </el-form-item>
        <el-form-item label="值">
          <el-input v-model="whitelistForm.value" placeholder="如: 192.168.1.1 或 192.168.1.0/24" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="whitelistForm.remark" placeholder="添加备注说明" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddWhitelistDialog = false">取消</el-button>
        <el-button type="primary" @click="addWhitelist">确定</el-button>
      </template>
    </el-dialog>

    <!-- 添加黑名单对话框 -->
    <el-dialog v-model="showAddBlacklistDialog" title="添加黑名单" width="500px">
      <el-form :model="blacklistForm" label-width="100px">
        <el-form-item label="类型">
          <el-select v-model="blacklistForm.type">
            <el-option label="IP地址" value="ip" />
            <el-option label="IP段" value="ip_range" />
          </el-select>
        </el-form-item>
        <el-form-item label="值">
          <el-input v-model="blacklistForm.value" placeholder="如: 192.168.1.1" />
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker
            v-model="blacklistForm.expireAt"
            type="datetime"
            placeholder="选择过期时间（留空表示永久）"
          />
        </el-form-item>
        <el-form-item label="封禁原因">
          <el-input v-model="blacklistForm.reason" placeholder="添加封禁原因" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddBlacklistDialog = false">取消</el-button>
        <el-button type="primary" @click="addBlacklist">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, watch } from 'vue'
import * as echarts from 'echarts'
import { ElMessage, ElMessageBox } from 'element-plus'
import { shieldApi } from '../../api/cdn'

const activeTab = ref('basic')
const chartRef = ref(null)
let chart = null

// 配置数据
const config = reactive({
  enabled: true,
  challengeMode: 'js_challenge',
  cookieDuration: 3600,
  cooldownPeriod: 10,
  ipThreshold: 30,
  strictMode: false
})

// 白名单
const whitelist = ref([])
const whitelistSearch = ref('')
const showAddWhitelistDialog = ref(false)
const whitelistForm = reactive({
  type: 'ip',
  value: '',
  remark: ''
})

// 黑名单
const blacklist = ref([])
const blacklistSearch = ref('')
const showAddBlacklistDialog = ref(false)
const blacklistForm = reactive({
  type: 'ip',
  value: '',
  expireAt: null,
  reason: ''
})

// 统计数据
const stats = reactive({
  todayChallenges: 0,
  passRate: 0,
  blockedCount: 0,
  whitelistCount: 0
})

// 加载配置
const loadConfig = async () => {
  try {
    const { data } = await shieldApi.getConfig()
    Object.assign(config, data)
  } catch (error) {
    ElMessage.error('加载配置失败')
  }
}

// 加载白名单
const loadWhitelist = async () => {
  try {
    const { data } = await shieldApi.getWhitelist()
    whitelist.value = data
  } catch (error) {
    ElMessage.error('加载白名单失败')
  }
}

// 加载黑名单
const loadBlacklist = async () => {
  try {
    const { data } = await shieldApi.getBlacklist()
    blacklist.value = data
  } catch (error) {
    ElMessage.error('加载黑名单失败')
  }
}

// 加载统计
const loadStats = async () => {
  try {
    const { data } = await shieldApi.getStats()
    Object.assign(stats, data)
  } catch (error) {
    ElMessage.error('加载统计失败')
  }
}

// 保存配置
const handleSave = async () => {
  try {
    await shieldApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (error) {
    ElMessage.error('保存失败')
  }
}

// 添加白名单
const addWhitelist = async () => {
  try {
    await shieldApi.addWhitelist(whitelistForm)
    ElMessage.success('添加成功')
    showAddWhitelistDialog.value = false
    whitelistForm.value = ''
    whitelistForm.remark = ''
    loadWhitelist()
  } catch (error) {
    ElMessage.error('添加失败')
  }
}

// 删除白名单
const deleteWhitelist = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此白名单吗？', '提示')
    await shieldApi.removeWhitelist(id)
    ElMessage.success('删除成功')
    loadWhitelist()
  } catch (error) {
    // 用户取消
  }
}

// 添加黑名单
const addBlacklist = async () => {
  try {
    await shieldApi.addBlacklist(blacklistForm)
    ElMessage.success('添加成功')
    showAddBlacklistDialog.value = false
    blacklistForm.value = ''
    blacklistForm.reason = ''
    loadBlacklist()
  } catch (error) {
    ElMessage.error('添加失败')
  }
}

// 解封黑名单
const unblockBlacklist = async (id) => {
  try {
    await shieldApi.removeBlacklist(id)
    ElMessage.success('解封成功')
    loadBlacklist()
  } catch (error) {
    ElMessage.error('解封失败')
  }
}

// 初始化图表
const initChart = () => {
  if (chartRef.value) {
    chart = echarts.init(chartRef.value)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['挑战次数', '通过次数', '拦截次数'] },
      xAxis: {
        type: 'category',
        data: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00']
      },
      yAxis: { type: 'value' },
      series: [
        { name: '挑战次数', type: 'line', data: [120, 132, 101, 134, 90, 230] },
        { name: '通过次数', type: 'line', data: [110, 122, 91, 124, 80, 210] },
        { name: '拦截次数', type: 'line', data: [10, 10, 10, 10, 10, 20] }
      ]
    })
  }
}

onMounted(() => {
  loadConfig()
  loadWhitelist()
  loadBlacklist()
  loadStats()
  setTimeout(initChart, 100)
})

watch(activeTab, (val) => {
  if (val === 'stats') {
    setTimeout(initChart, 100)
  }
})
</script>

<style scoped>
.shield-config {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.form-tip {
  margin-left: 12px;
  color: #909399;
  font-size: 12px;
}

.unit {
  margin-left: 8px;
  color: #606266;
}

.table-toolbar {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: #409eff;
}

.chart-container {
  height: 300px;
}
</style>

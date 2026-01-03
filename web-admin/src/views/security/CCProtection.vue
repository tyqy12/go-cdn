<template>
  <div class="cc-protection">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>CC防护配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <!-- 基本配置 -->
        <el-tab-pane label="基本配置" name="basic">
          <el-form :model="config" label-width="160px">
            <el-form-item label="启用CC防护">
              <el-switch v-model="config.enabled" />
            </el-form-item>

            <el-form-item label="检测模式">
              <el-select v-model="config.detectionMode">
                <el-option label="滑动窗口" value="sliding_window" />
                <el-option label="固定窗口" value="fixed_window" />
                <el-option label="令牌桶" value="token_bucket" />
                <el-option label="漏桶" value="leaky_bucket" />
              </el-select>
            </el-form-item>

            <el-form-item label="请求阈值">
              <el-input-number v-model="config.requestThreshold" :min="10" :max="10000" />
              <span class="unit">次/秒</span>
            </el-form-item>

            <el-form-item label="阻断时间">
              <el-input-number v-model="config.blockDuration" :min="10" :max="3600" />
              <span class="unit">秒</span>
            </el-form-item>

            <el-form-item label="启用机器学习">
              <el-switch v-model="config.enableML" />
              <span class="form-tip">启用后将使用机器学习模型检测异常流量</span>
            </el-form-item>

            <el-form-item label="ML敏感度">
              <el-slider
                v-model="config.mlSensitivity"
                :min="1"
                :max="10"
                :format-tooltip="(val) => val + '级'"
              />
            </el-form-item>

            <el-form-item label="IP白名单">
              <el-input
                v-model="config.ipWhitelist"
                type="textarea"
                :rows="3"
                placeholder="每行一个IP或IP段"
              />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- 防护规则 -->
        <el-tab-pane label="防护规则" name="rules">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddRuleDialog = true">
              添加规则
            </el-button>
          </div>

          <el-table :data="rules" style="width: 100%">
            <el-table-column prop="name" label="规则名称" width="150" />
            <el-table-column prop="type" label="类型" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="condition" label="匹配条件" />
            <el-table-column prop="action" label="动作" width="100">
              <template #default="{ row }">
                <el-tag :type="row.action === 'block' ? 'danger' : 'warning'" size="small">
                  {{ row.action }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="priority" label="优先级" width="80" />
            <el-table-column prop="enabled" label="状态" width="80">
              <template #default="{ row }">
                <el-switch
                  :model-value="row.enabled"
                  @change="toggleRule(row.id, $event)"
                />
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button size="small" @click="editRule(row)">编辑</el-button>
                <el-button type="danger" size="small" @click="deleteRule(row.id)">
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 攻击记录 -->
        <el-tab-pane label="攻击记录" name="attacks">
          <div class="table-toolbar">
            <el-date-picker
              v-model="attackDateRange"
              type="daterange"
              range-separator="至"
              start-placeholder="开始日期"
              end-placeholder="结束日期"
              @change="loadAttacks"
            />
            <el-button style="margin-left: 16px" @click="loadAttacks">刷新</el-button>
          </div>

          <el-table :data="attacks" style="width: 100%">
            <el-table-column prop="attackType" label="攻击类型" width="120">
              <template #default="{ row }">
                <el-tag type="danger" size="small">{{ row.attackType }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="sourceIP" label="源IP" width="140" />
            <el-table-column prop="targetPath" label="目标路径" />
            <el-table-column prop="requestCount" label="请求数" width="100" />
            <el-table-column prop="blockedCount" label="拦截数" width="100" />
            <el-table-column prop="startTime" label="开始时间" width="180" />
            <el-table-column prop="duration" label="持续时间" width="100">
              <template #default="{ row }">
                {{ row.duration }}s
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 机器学习状态 -->
        <el-tab-pane label="ML状态" name="ml">
          <el-row :gutter="20">
            <el-col :span="8">
              <el-card shadow="never">
                <template #header>模型状态</template>
                <div class="ml-status">
                  <el-tag :type="mlStatus.loaded ? 'success' : 'info'" size="large">
                    {{ mlStatus.loaded ? '已加载' : '未加载' }}
                  </el-tag>
                </div>
              </el-card>
            </el-col>
            <el-col :span="8">
              <el-card shadow="never">
                <template #header>最后训练</template>
                <div class="ml-info">{{ mlStatus.lastTraining || '从未训练' }}</div>
              </el-card>
            </el-col>
            <el-col :span="8">
              <el-card shadow="never">
                <template #header>模型准确率</template>
                <div class="ml-info">{{ mlStatus.accuracy }}%</div>
              </el-card>
            </el-col>
          </el-row>

          <el-card style="margin-top: 20px">
            <template #header>操作</template>
            <el-button type="primary" @click="trainML" :loading="training">
              重新训练模型
            </el-button>
          </el-card>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 添加规则对话框 -->
    <el-dialog v-model="showAddRuleDialog" title="添加规则" width="600px">
      <el-form :model="ruleForm" label-width="100px">
        <el-form-item label="规则名称">
          <el-input v-model="ruleForm.name" placeholder="输入规则名称" />
        </el-form-item>
        <el-form-item label="规则类型">
          <el-select v-model="ruleForm.type">
            <el-option label="URL匹配" value="url" />
            <el-option label="User-Agent" value="user_agent" />
            <el-option label="Referer" value="referer" />
            <el-option label="请求头" value="header" />
            <el-option label="IP匹配" value="ip" />
            <el-option label="请求方法" value="method" />
          </el-select>
        </el-form-item>
        <el-form-item label="匹配条件">
          <el-input
            v-model="ruleForm.condition"
            type="textarea"
            :rows="2"
            placeholder="支持正则表达式"
          />
        </el-form-item>
        <el-form-item label="触发动作">
          <el-select v-model="ruleForm.action">
            <el-option label="阻断请求" value="block" />
            <el-option label="验证码挑战" value="challenge" />
            <el-option label="返回403" value="forbidden" />
            <el-option label="返回503" value="service_unavailable" />
          </el-select>
        </el-form-item>
        <el-form-item label="优先级">
          <el-input-number v-model="ruleForm.priority" :min="1" :max="100" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddRuleDialog = false">取消</el-button>
        <el-button type="primary" @click="saveRule">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ccProtectionApi } from '../../api/cdn'

const activeTab = ref('basic')
const showAddRuleDialog = ref(false)
const training = ref(false)

// 配置数据
const config = reactive({
  enabled: true,
  detectionMode: 'sliding_window',
  requestThreshold: 100,
  blockDuration: 300,
  enableML: true,
  mlSensitivity: 5,
  ipWhitelist: ''
})

// 规则列表
const rules = ref([])
const ruleForm = reactive({
  id: null,
  name: '',
  type: 'url',
  condition: '',
  action: 'block',
  priority: 50
})

// 攻击记录
const attacks = ref([])
const attackDateRange = ref(null)

// ML状态
const mlStatus = reactive({
  loaded: false,
  lastTraining: '',
  accuracy: 0
})

// 加载配置
const loadConfig = async () => {
  try {
    const { data } = await ccProtectionApi.getConfig()
    Object.assign(config, data)
  } catch (error) {
    ElMessage.error('加载配置失败')
  }
}

// 加载规则
const loadRules = async () => {
  try {
    const { data } = await ccProtectionApi.getRules()
    rules.value = data
  } catch (error) {
    ElMessage.error('加载规则失败')
  }
}

// 加载攻击记录
const loadAttacks = async () => {
  try {
    const params = {}
    if (attackDateRange.value) {
      params.startTime = attackDateRange.value[0]
      params.endTime = attackDateRange.value[1]
    }
    const { data } = await ccProtectionApi.getAttacks(params)
    attacks.value = data
  } catch (error) {
    ElMessage.error('加载攻击记录失败')
  }
}

// 加载ML状态
const loadMLStatus = async () => {
  try {
    const { data } = await ccProtectionApi.getMLStatus()
    Object.assign(mlStatus, data)
  } catch (error) {
    console.error('加载ML状态失败')
  }
}

// 保存配置
const handleSave = async () => {
  try {
    await ccProtectionApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (error) {
    ElMessage.error('保存失败')
  }
}

// 保存规则
const saveRule = async () => {
  try {
    if (ruleForm.id) {
      await ccProtectionApi.updateRule(ruleForm.id, ruleForm)
    } else {
      await ccProtectionApi.addRule(ruleForm)
    }
    ElMessage.success('保存成功')
    showAddRuleDialog.value = false
    loadRules()
  } catch (error) {
    ElMessage.error('保存失败')
  }
}

// 编辑规则
const editRule = (rule) => {
  Object.assign(ruleForm, rule)
  showAddRuleDialog.value = true
}

// 删除规则
const deleteRule = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此规则吗？', '提示')
    await ccProtectionApi.deleteRule(id)
    ElMessage.success('删除成功')
    loadRules()
  } catch (error) {
    // 用户取消
  }
}

// 切换规则状态
const toggleRule = async (id, enabled) => {
  try {
    await ccProtectionApi.toggleRule(id, enabled)
    loadRules()
  } catch (error) {
    ElMessage.error('操作失败')
  }
}

// 训练ML模型
const trainML = async () => {
  try {
    training.value = true
    await ccProtectionApi.trainML()
    ElMessage.success('训练开始，请稍候...')
    loadMLStatus()
  } catch (error) {
    ElMessage.error('训练失败')
  } finally {
    training.value = false
  }
}

onMounted(() => {
  loadConfig()
  loadRules()
  loadAttacks()
  loadMLStatus()
})
</script>

<style scoped>
.cc-protection {
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

.ml-status,
.ml-info {
  font-size: 16px;
  font-weight: 500;
}
</style>

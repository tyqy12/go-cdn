<template>
  <div class="dns-scheduler">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>DNS智能调度</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <el-tab-pane label="调度策略" name="strategy">
          <el-form :model="config" label-width="160px">
            <el-form-item label="调度策略">
              <el-select v-model="config.strategy">
                <el-option label="地理位置" value="geo" />
                <el-option label="最低延迟" value="latency" />
                <el-option label="负载均衡" value="load_balance" />
              </el-select>
            </el-form-item>
            <el-form-item label="启用故障转移">
              <el-switch v-model="config.failover" />
            </el-form-item>
            <el-form-item label="TTL时间">
              <el-input-number v-model="config.ttl" :min="60" :max="3600" />
              <span class="unit">秒</span>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="DNS提供商" name="providers">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddProviderDialog = true">添加提供商</el-button>
          </div>
          <el-table :data="providers" style="width: 100%">
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="type" label="类型" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="endpoint" label="API地址" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteProvider(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="showAddProviderDialog" title="添加DNS提供商" width="500px">
      <el-form :model="providerForm" label-width="100px">
        <el-form-item label="名称">
          <el-input v-model="providerForm.name" placeholder="输入名称" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="providerForm.type">
            <el-option label="阿里云" value="aliyun" />
            <el-option label="腾讯云" value="tencent" />
            <el-option label="DNSPod" value="dnspod" />
          </el-select>
        </el-form-item>
        <el-form-item label="API地址">
          <el-input v-model="providerForm.endpoint" placeholder="API地址" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddProviderDialog = false">取消</el-button>
        <el-button type="primary" @click="addProvider">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { dnsSchedulerApi } from '../../api/cdn'

const activeTab = ref('strategy')
const showAddProviderDialog = ref(false)
const config = reactive({ strategy: 'geo', failover: true, ttl: 600 })
const providers = ref([])
const providerForm = reactive({ name: '', type: 'aliyun', endpoint: '', accessKey: '', secretKey: '' })

const loadConfig = async () => {
  try {
    const { data } = await dnsSchedulerApi.getConfig()
    Object.assign(config, data)
  } catch (e) { ElMessage.error('加载配置失败') }
}

const loadProviders = async () => {
  try {
    const { data } = await dnsSchedulerApi.getProviders()
    providers.value = data
  } catch (e) { ElMessage.error('加载提供商失败') }
}

const handleSave = async () => {
  try {
    await dnsSchedulerApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

const addProvider = async () => {
  try {
    await dnsSchedulerApi.addProvider(providerForm)
    ElMessage.success('添加成功')
    showAddProviderDialog.value = false
    loadProviders()
  } catch (e) { ElMessage.error('添加失败') }
}

const deleteProvider = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此提供商吗？', '提示')
    await dnsSchedulerApi.deleteProvider(id)
    ElMessage.success('删除成功')
    loadProviders()
  } catch (e) { /* 用户取消 */ }
}

onMounted(() => { loadConfig(); loadProviders() })
</script>

<style scoped>
.dns-scheduler { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
.table-toolbar { display: flex; align-items: center; margin-bottom: 16px }
</style>

<template>
  <div class="url-auth">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>URL鉴权配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <el-tab-pane label="基本配置" name="basic">
          <el-form :model="config" label-width="160px">
            <el-form-item label="启用URL鉴权">
              <el-switch v-model="config.enabled" />
            </el-form-item>
            <el-form-item label="鉴权方式">
              <el-select v-model="config.authType">
                <el-option label="时间戳签名" value="timestamp" />
                <el-option label="MD5签名" value="md5" />
                <el-option label="AES加密" value="aes" />
              </el-select>
            </el-form-item>
            <el-form-item label="密钥">
              <el-input v-model="config.secretKey" type="password" show-password />
            </el-form-item>
            <el-form-item label="有效时间">
              <el-input-number v-model="config.validTime" :min="60" :max="86400" />
              <span class="unit">秒</span>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="密钥管理" name="keys">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddKeyDialog = true">添加密钥</el-button>
          </div>
          <el-table :data="keys" style="width: 100%">
            <el-table-column prop="name" label="密钥名称" width="150" />
            <el-table-column prop="key" label="密钥" width="200" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-switch :model-value="row.status === 'active'" @change="toggleKey(row.id, $event)" />
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteKey(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="防盗链规则" name="hotlink">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddRuleDialog = true">添加规则</el-button>
          </div>
          <el-table :data="hotlinkRules" style="width: 100%">
            <el-table-column prop="domain" label="域名" width="200" />
            <el-table-column prop="type" label="类型" width="100">
              <template #default="{ row }">
                <el-tag size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="action" label="动作" width="100">
              <template #default="{ row }">
                <el-tag :type="row.action === 'allow' ? 'success' : 'danger'" size="small">{{ row.action }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteRule(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="showAddKeyDialog" title="添加密钥" width="500px">
      <el-form :model="keyForm" label-width="100px">
        <el-form-item label="密钥名称">
          <el-input v-model="keyForm.name" placeholder="输入名称" />
        </el-form-item>
        <el-form-item label="密钥">
          <el-input v-model="keyForm.key" placeholder="输入密钥" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddKeyDialog = false">取消</el-button>
        <el-button type="primary" @click="addKey">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showAddRuleDialog" title="添加防盗链规则" width="500px">
      <el-form :model="ruleForm" label-width="100px">
        <el-form-item label="域名">
          <el-input v-model="ruleForm.domain" placeholder="如: example.com" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="ruleForm.type">
            <el-option label="允许" value="allow" />
            <el-option label="禁止" value="deny" />
          </el-select>
        </el-form-item>
        <el-form-item label="动作">
          <el-select v-model="ruleForm.action">
            <el-option label="返回403" value="forbidden" />
            <el-option label="返回302" value="redirect" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddRuleDialog = false">取消</el-button>
        <el-button type="primary" @click="addRule">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { urlAuthApi } from '../../api/cdn'

const activeTab = ref('basic')
const showAddKeyDialog = ref(false)
const showAddRuleDialog = ref(false)
const config = reactive({ enabled: false, authType: 'md5', secretKey: '', validTime: 3600 })
const keys = ref([])
const hotlinkRules = ref([])
const keyForm = reactive({ name: '', key: '' })
const ruleForm = reactive({ id: null, domain: '', type: 'allow', action: 'forbidden' })

const loadConfig = async () => {
  try {
    const { data } = await urlAuthApi.getConfig()
    Object.assign(config, data)
  } catch (e) { ElMessage.error('加载配置失败') }
}

const loadKeys = async () => {
  try {
    const { data } = await urlAuthApi.getKeys()
    keys.value = data
  } catch (e) { ElMessage.error('加载密钥失败') }
}

const loadHotlinkRules = async () => {
  try {
    const { data } = await urlAuthApi.getHotlinkRules()
    hotlinkRules.value = data
  } catch (e) { ElMessage.error('加载规则失败') }
}

const handleSave = async () => {
  try {
    await urlAuthApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

const addKey = async () => {
  try {
    await urlAuthApi.addKey(keyForm)
    ElMessage.success('添加成功')
    showAddKeyDialog.value = false
    keyForm.name = ''
    keyForm.key = ''
    loadKeys()
  } catch (e) { ElMessage.error('添加失败') }
}

const deleteKey = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此密钥吗？', '提示')
    await urlAuthApi.deleteKey(id)
    ElMessage.success('删除成功')
    loadKeys()
  } catch (e) { /* 用户取消 */ }
}

const toggleKey = async (id, status) => {
  try {
    await urlAuthApi.toggleKey(id, status)
    loadKeys()
  } catch (e) { ElMessage.error('操作失败') }
}

const addRule = async () => {
  try {
    await urlAuthApi.addHotlinkRule(ruleForm)
    ElMessage.success('添加成功')
    showAddRuleDialog.value = false
    loadHotlinkRules()
  } catch (e) { ElMessage.error('添加失败') }
}

const deleteRule = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此规则吗？', '提示')
    await urlAuthApi.deleteHotlinkRule(id)
    ElMessage.success('删除成功')
    loadHotlinkRules()
  } catch (e) { /* 用户取消 */ }
}

onMounted(() => { loadConfig(); loadKeys(); loadHotlinkRules() })
</script>

<style scoped>
.url-auth { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
.table-toolbar { display: flex; align-items: center; margin-bottom: 16px }
</style>

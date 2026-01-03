<template>
  <div class="performance-config">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>性能优化配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <el-tab-pane label="缓存配置" name="cache">
          <el-form :model="config" label-width="160px">
            <el-form-item label="启用缓存">
              <el-switch v-model="config.cacheEnabled" />
            </el-form-item>
            <el-form-item label="默认缓存时间">
              <el-input-number v-model="config.defaultTTL" :min="0" :max="86400" />
              <span class="unit">秒</span>
            </el-form-item>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { performanceApi } from '../../api/cdn'

const activeTab = ref('cache')
const config = reactive({ cacheEnabled: true, defaultTTL: 3600 })

const loadConfig = async () => {
  try {
    const { data } = await performanceApi.getConfig()
    Object.assign(config, data)
  } catch (e) { console.error(e) }
}

const handleSave = async () => {
  try {
    await performanceApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

onMounted(() => loadConfig())
</script>

<style scoped>
.performance-config { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
</style>

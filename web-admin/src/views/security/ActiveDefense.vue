<template>
  <div class="active-defense">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>主动防御配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-form :model="config" label-width="160px">
        <el-form-item label="启用主动防御">
          <el-switch v-model="config.enabled" />
        </el-form-item>
        <el-form-item label="自动封禁阈值">
          <el-input-number v-model="config.threshold" :min="1" :max="100" />
          <span class="form-tip">分钟内请求次数超过此值自动封禁</span>
        </el-form-item>
        <el-form-item label="封禁时长">
          <el-input-number v-model="config.banDuration" :min="1" :max="1440" />
          <span class="form-tip">分钟</span>
        </el-form-item>
        <el-form-item label="封禁阈值倍数">
          <el-input-number v-model="config.rateLimitMultiplier" :min="1" :max="10" :step="0.5" />
          <span class="form-tip">触发阈值后限流倍数</span>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { shieldApi } from '../../api/cdn'

const config = reactive({ enabled: false, threshold: 10, banDuration: 60, rateLimitMultiplier: 2 })

const loadConfig = async () => {
  try {
    const { data } = await shieldApi.getConfig()
    Object.assign(config, data)
  } catch (e) { /* 空数据 */ }
}

const handleSave = async () => {
  try {
    await shieldApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

onMounted(() => loadConfig())
</script>

<style scoped>
.active-defense { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.form-tip { margin-left: 8px; color: #909399; font-size: 12px }
</style>

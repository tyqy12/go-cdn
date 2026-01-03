<template>
  <div class="hls-encryption">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>HLS加密配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-form :model="config" label-width="160px">
        <el-form-item label="启用HLS加密">
          <el-switch v-model="config.enabled" />
        </el-form-item>
        <el-form-item label="加密方式">
          <el-select v-model="config.encryptionType">
            <el-option label="AES-128" value="aes128" />
            <el-option label="SAMPLE-AES" value="sample_aes" />
          </el-select>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { hlsEncryptionApi } from '../../api/cdn'

const config = reactive({ enabled: false, encryptionType: 'aes128' })

const loadConfig = async () => {
  try {
    const { data } = await hlsEncryptionApi.getConfig()
    Object.assign(config, data)
  } catch (e) { /* 空数据 */ }
}

const handleSave = async () => {
  try {
    await hlsEncryptionApi.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

onMounted(() => loadConfig())
</script>

<style scoped>
.hls-encryption { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

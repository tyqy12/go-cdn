<template>
  <div class="http3-config">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>HTTP/3配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-form :model="config" label-width="160px">
        <el-form-item label="启用HTTP/3">
          <el-switch v-model="config.enabled" />
        </el-form-item>
        <el-form-item label="QUIC端口">
          <el-input-number v-model="config.port" :min="1" :max="65535" />
        </el-form-item>
        <el-form-item label="启用0-RTT">
          <el-switch v-model="config.zeroRtt" />
        </el-form-item>
        <el-form-item label="拥塞控制算法">
          <el-select v-model="config.congestionControl">
            <el-option label="BBR" value="bbr" />
            <el-option label="Cubic" value="cubic" />
          </el-select>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { http3Api } from '../../api/cdn'

const config = reactive({ enabled: true, port: 443, zeroRtt: true, congestionControl: 'bbr' })

const loadConfig = async () => {
  try {
    const { data } = await http3Api.getConfig()
    Object.assign(config, data)
  } catch (e) { /* 空数据 */ }
}

const handleSave = async () => {
  try {
    await http3Api.updateConfig(config)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

onMounted(() => loadConfig())
</script>

<style scoped>
.http3-config { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

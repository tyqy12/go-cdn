<template>
  <div class="log-analyzer">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>日志分析配置</span>
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </template>

      <el-form :model="config" label-width="160px">
        <el-form-item label="启用日志分析">
          <el-switch v-model="config.enabled" />
        </el-form-item>
        <el-form-item label="分析维度">
          <el-checkbox-group v-model="config.dimensions">
            <el-checkbox label="ip">IP分析</el-checkbox>
            <el-checkbox label="url">URL分析</el-checkbox>
            <el-checkbox label="user_agent">User-Agent分析</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { accessLogApi } from '../../api/cdn'

const config = reactive({ enabled: true, dimensions: ['ip', 'url'] })

const handleSave = async () => {
  ElMessage.success('配置已保存')
}

onMounted(() => {})
</script>

<style scoped>
.log-analyzer { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

<template>
  <div class="ip-library">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>IP库配置</span>
          <el-button type="primary" @click="handleUpdate">更新IP库</el-button>
        </div>
      </template>

      <el-form :model="config" label-width="160px">
        <el-form-item label="IP库类型">
          <el-select v-model="config.provider">
            <el-option label="GeoIP2" value="geoip2" />
            <el-option label="IP2Location" value="ip2location" />
            <el-option label="纯真IP库" value="cz88" />
          </el-select>
        </el-form-item>
        <el-form-item label="自动更新">
          <el-switch v-model="config.autoUpdate" />
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { ipLibraryApi } from '../../api/cdn'

const config = reactive({ provider: 'geoip2', autoUpdate: true })

const handleUpdate = async () => {
  ElMessage.success('IP库更新中...')
}
</script>

<style scoped>
.ip-library { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

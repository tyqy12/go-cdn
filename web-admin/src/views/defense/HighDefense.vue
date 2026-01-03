<template>
  <div class="high-defense">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>高防IP管理</span>
        </div>
      </template>

      <el-table :data="ips" style="width: 100%">
        <el-table-column prop="ip" label="高防IP" width="160" />
        <el-table-column prop="bandwidth" label="防护带宽" width="120">
          <template #default="{ row }">{{ row.bandwidth }}Gbps</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'danger'" size="small">
              {{ row.status === 'active' ? '防护中' : '已停止' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { highDefenseApi } from '../../api/cdn'

const ips = ref([])

const loadIps = async () => {
  try {
    const { data } = await highDefenseApi.list()
    ips.value = data
  } catch (e) { /* 加载失败 */ }
}

onMounted(() => loadIps())
</script>

<style scoped>
.high-defense { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

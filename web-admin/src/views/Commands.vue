<template>
  <div class="space-y-6">
    <!-- 指令执行 -->
    <el-card>
      <template #header>
        <span class="font-bold">执行指令</span>
      </template>
      <el-form :model="commandForm" label-width="100px">
        <el-form-item label="指令类型">
          <el-select v-model="commandForm.command" class="w-full">
            <el-option label="重载配置 (reload)" value="reload" />
            <el-option label="重启服务 (restart)" value="restart" />
            <el-option label="停止服务 (stop)" value="stop" />
          </el-select>
        </el-form-item>
        <el-form-item label="目标类型">
          <el-select v-model="commandForm.targetType" class="w-full" @change="commandForm.targetIds = []">
            <el-option label="全部节点" value="all" />
            <el-option label="按地区" value="region" />
            <el-option label="按类型" value="type" />
            <el-option label="指定节点" value="node" />
          </el-select>
        </el-form-item>
        <el-form-item label="选择目标" v-if="commandForm.targetType !== 'all'">
          <el-checkbox-group v-model="commandForm.targetIds">
            <template v-if="commandForm.targetType === 'region'">
              <el-checkbox v-for="r in nodeStore.regions" :key="r" :label="r">{{ r }}</el-checkbox>
            </template>
            <template v-if="commandForm.targetType === 'type'">
              <el-checkbox label="edge">边缘节点</el-checkbox>
              <el-checkbox label="core">核心节点</el-checkbox>
            </template>
            <template v-if="commandForm.targetType === 'node'">
              <el-checkbox v-for="n in nodeStore.nodes" :key="n.id" :label="n.id">{{ n.name }}</el-checkbox>
            </template>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="executeCommand" :disabled="!canExecute">
            <el-icon><Promotion /></el-icon>执行指令
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 执行历史 -->
    <el-card>
      <template #header>执行历史</template>
      <el-table :data="commandStore.history" v-loading="commandStore.loading">
        <el-table-column prop="command" label="指令" width="120">
          <template #default="{ row }">
            <el-tag>{{ row.command }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="target" label="目标" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'success' ? 'success' : row.status === 'pending' ? 'warning' : 'danger'">
              {{ row.status === 'success' ? '成功' : row.status === 'pending' ? '进行中' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="执行时间">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Promotion } from '@element-plus/icons-vue'
import { useNodeStore, useCommandStore } from '../stores'

const nodeStore = useNodeStore()
const commandStore = useCommandStore()

const commandForm = ref({
  command: 'reload',
  targetType: 'all',
  targetIds: []
})

const canExecute = computed(() => {
  return commandForm.value.targetType === 'all' || commandForm.value.targetIds.length > 0
})

const executeCommand = async () => {
  try {
    await ElMessageBox.confirm(`确定要执行批量 ${commandForm.value.command} 吗？`, '确认', { type: 'warning' })
    await commandStore.execute({
      command: commandForm.value.command,
      target_type: commandForm.value.targetType,
      target_ids: commandForm.value.targetIds
    })
    ElMessage.success('指令已提交执行')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('指令执行失败')
    }
  }
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN')
}

onMounted(() => {
  nodeStore.fetchNodes()
  commandStore.fetchHistory()
})
</script>

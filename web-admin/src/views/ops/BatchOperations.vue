<template>
  <div class="batch-operations">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>批量操作</span>
          <el-button type="primary" @click="showCreateDialog = true">创建任务</el-button>
        </div>
      </template>

      <el-table :data="tasks" style="width: 100%">
        <el-table-column prop="name" label="任务名称" width="150" />
        <el-table-column prop="operationType" label="操作类型" width="120" />
        <el-table-column prop="progress" label="进度" width="200">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" />
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'running' ? 'warning' : 'info'" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" @click="cancelTask(row.id)" v-if="row.status === 'running'">取消</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showCreateDialog" title="创建批量操作" width="500px">
      <el-form :model="taskForm" label-width="100px">
        <el-form-item label="任务名称">
          <el-input v-model="taskForm.name" placeholder="输入任务名称" />
        </el-form-item>
        <el-form-item label="操作类型">
          <el-select v-model="taskForm.operationType">
            <el-option label="批量更新配置" value="update_config" />
            <el-option label="批量重启节点" value="restart_nodes" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="createTask">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { batchApi } from '../../api/cdn'

const showCreateDialog = ref(false)
const tasks = ref([])
const taskForm = reactive({ name: '', operationType: 'update_config', targetIds: [], params: '{}' })

const loadTasks = async () => {
  try {
    const { data } = await batchApi.list()
    tasks.value = data
  } catch (e) { ElMessage.error('加载任务列表失败') }
}

const createTask = async () => {
  try {
    await batchApi.create(taskForm)
    ElMessage.success('任务创建成功')
    showCreateDialog.value = false
    loadTasks()
  } catch (e) { ElMessage.error('创建失败') }
}

const cancelTask = async (id) => {
  try {
    await ElMessageBox.confirm('确定要取消此任务吗？', '提示')
    await batchApi.cancel(id)
    ElMessage.success('任务已取消')
    loadTasks()
  } catch (e) { /* 用户取消 */ }
}

onMounted(() => loadTasks())
</script>

<style scoped>
.batch-operations { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

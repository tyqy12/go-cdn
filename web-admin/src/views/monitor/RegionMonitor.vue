<template>
  <div class="region-monitor">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>区域监控</span>
          <el-button type="primary" @click="showAddTerminalDialog = true">添加监控终端</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <!-- 监控终端 -->
        <el-tab-pane label="监控终端" name="terminals">
          <div class="table-toolbar">
            <el-input v-model="terminalSearch" placeholder="搜索终端" style="width: 240px" clearable />
          </div>

          <el-table :data="filteredTerminals" style="width: 100%">
            <el-table-column prop="name" label="终端名称" width="150" />
            <el-table-column prop="region" label="所在区域" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.region }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="isp" label="运营商" width="100" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'online' ? 'success' : 'danger'" size="small">
                  {{ row.status === 'online' ? '在线' : '离线' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="200">
              <template #default="{ row }">
                <el-button size="small" @click="toggleTerminal(row)">
                  {{ row.status === 'online' ? '禁用' : '启用' }}
                </el-button>
                <el-button type="danger" size="small" @click="deleteTerminal(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 监控任务 -->
        <el-tab-pane label="监控任务" name="tasks">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddTaskDialog = true">创建任务</el-button>
          </div>

          <el-table :data="tasks" style="width: 100%">
            <el-table-column prop="name" label="任务名称" width="150" />
            <el-table-column prop="target" label="监控目标" />
            <el-table-column prop="type" label="监控类型" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="interval" label="检测间隔" width="100">
              <template #default="{ row }">{{ row.interval }}s</template>
            </el-table-column>
            <el-table-column prop="status" label="状态" width="80">
              <template #default="{ row }">
                <el-switch :model-value="row.status === 'active'" @change="toggleTask(row.id, $event)" />
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteTask(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 监控结果 -->
        <el-tab-pane label="监控结果" name="results">
          <div class="table-toolbar">
            <el-select v-model="resultTask" placeholder="选择任务" style="width: 200px">
              <el-option v-for="task in tasks" :key="task.id" :label="task.name" :value="task.id" />
            </el-select>
            <el-button style="margin-left: 16px" @click="loadResults">查询</el-button>
          </div>

          <el-table :data="results" style="width: 100%">
            <el-table-column prop="timestamp" label="检测时间" width="180" />
            <el-table-column prop="terminal" label="检测终端" width="120" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small">
                  {{ row.status === 'success' ? '正常' : '异常' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="latency" label="延迟" width="100">
              <template #default="{ row }">{{ row.latency }}ms</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 添加终端对话框 -->
    <el-dialog v-model="showAddTerminalDialog" title="添加监控终端" width="500px">
      <el-form :model="terminalForm" label-width="100px">
        <el-form-item label="终端名称">
          <el-input v-model="terminalForm.name" placeholder="输入终端名称" />
        </el-form-item>
        <el-form-item label="所在区域">
          <el-select v-model="terminalForm.region">
            <el-option label="中国大陆" value="cn" />
            <el-option label="香港" value="hk" />
            <el-option label="美国" value="us" />
          </el-select>
        </el-form-item>
        <el-form-item label="运营商">
          <el-select v-model="terminalForm.isp">
            <el-option label="电信" value="ct" />
            <el-option label="联通" value="cu" />
            <el-option label="移动" value="cm" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddTerminalDialog = false">取消</el-button>
        <el-button type="primary" @click="saveTerminal">保存</el-button>
      </template>
    </el-dialog>

    <!-- 添加任务对话框 -->
    <el-dialog v-model="showAddTaskDialog" title="创建监控任务" width="500px">
      <el-form :model="taskForm" label-width="100px">
        <el-form-item label="任务名称">
          <el-input v-model="taskForm.name" placeholder="输入任务名称" />
        </el-form-item>
        <el-form-item label="监控类型">
          <el-select v-model="taskForm.type">
            <el-option label="HTTP" value="http" />
            <el-option label="HTTPS" value="https" />
            <el-option label="TCP" value="tcp" />
            <el-option label="Ping" value="ping" />
          </el-select>
        </el-form-item>
        <el-form-item label="监控目标">
          <el-input v-model="taskForm.target" placeholder="如: https://example.com" />
        </el-form-item>
        <el-form-item label="检测间隔">
          <el-input-number v-model="taskForm.interval" :min="10" :max="3600" />
          <span class="unit">秒</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddTaskDialog = false">取消</el-button>
        <el-button type="primary" @click="saveTask">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { regionMonitorApi } from '../../api/cdn'

const activeTab = ref('terminals')
const terminalSearch = ref('')
const showAddTerminalDialog = ref(false)
const showAddTaskDialog = ref(false)
const resultTask = ref('')

const terminals = ref([])
const tasks = ref([])
const results = ref([])

const terminalForm = reactive({ id: null, name: '', region: 'cn', isp: 'ct', location: '', apiUrl: '' })
const taskForm = reactive({ id: null, name: '', type: 'http', target: '', interval: 60, timeout: 5000, terminals: [] })

const filteredTerminals = computed(() => terminals.value.filter(t => !terminalSearch.value || t.name.includes(terminalSearch.value)))

const loadTerminals = async () => {
  try {
    const { data } = await regionMonitorApi.listTerminals()
    terminals.value = data
  } catch (e) { ElMessage.error('加载监控终端失败') }
}

const loadTasks = async () => {
  try {
    const { data } = await regionMonitorApi.listTasks()
    tasks.value = data
  } catch (e) { ElMessage.error('加载监控任务失败') }
}

const loadResults = async () => {
  try {
    const params = resultTask.value ? { taskId: resultTask.value } : {}
    const { data } = await regionMonitorApi.getResults(params)
    results.value = data
  } catch (e) { ElMessage.error('加载监控结果失败') }
}

const saveTerminal = async () => {
  try {
    if (terminalForm.id) await regionMonitorApi.updateTerminal(terminalForm.id, terminalForm)
    else await regionMonitorApi.createTerminal(terminalForm)
    ElMessage.success('保存成功')
    showAddTerminalDialog.value = false
    loadTerminals()
  } catch (e) { ElMessage.error('保存失败') }
}

const saveTask = async () => {
  try {
    if (taskForm.id) await regionMonitorApi.updateTask(taskForm.id, taskForm)
    else await regionMonitorApi.createTask(taskForm)
    ElMessage.success('创建成功')
    showAddTaskDialog.value = false
    loadTasks()
  } catch (e) { ElMessage.error('创建失败') }
}

const deleteTask = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此任务吗？', '提示')
    await regionMonitorApi.deleteTask(id)
    ElMessage.success('删除成功')
    loadTasks()
  } catch (e) { /* 用户取消 */ }
}

const toggleTask = async (id, status) => {
  try {
    if (status) await regionMonitorApi.enableTask(id)
    else await regionMonitorApi.disableTask(id)
    loadTasks()
  } catch (e) { ElMessage.error('操作失败') }
}

const toggleTerminal = async (terminal) => {
  try {
    if (terminal.status === 'online') await regionMonitorApi.disableTerminal(terminal.id)
    else await regionMonitorApi.enableTerminal(terminal.id)
    loadTerminals()
  } catch (e) { ElMessage.error('操作失败') }
}

const deleteTerminal = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此终端吗？', '提示')
    await regionMonitorApi.deleteTerminal(id)
    ElMessage.success('删除成功')
    loadTerminals()
  } catch (e) { /* 用户取消 */ }
}

watch(resultTask, () => loadResults())
onMounted(() => { loadTerminals(); loadTasks(); loadResults() })
</script>

<style scoped>
.region-monitor { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
.table-toolbar { display: flex; align-items: center; margin-bottom: 16px }
</style>

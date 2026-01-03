<template>
  <div class="edge-computing">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>边缘运算配置</span>
          <el-button type="primary" @click="showCreateDialog = true">创建函数</el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <!-- 函数列表 -->
        <el-tab-pane label="函数列表" name="functions">
          <div class="table-toolbar">
            <el-input v-model="functionSearch" placeholder="搜索函数" style="width: 240px" clearable />
          </div>

          <el-table :data="filteredFunctions" style="width: 100%">
            <el-table-column prop="name" label="函数名称" width="150" />
            <el-table-column prop="runtime" label="运行时" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.runtime }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="描述" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'deployed' ? 'success' : 'info'" size="small">
                  {{ row.status === 'deployed' ? '已部署' : '未部署' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="executions" label="执行次数" width="100" />
            <el-table-column prop="avgLatency" label="平均延迟" width="100">
              <template #default="{ row }">{{ row.avgLatency }}ms</template>
            </el-table-column>
            <el-table-column label="操作" width="200" fixed="right">
              <template #default="{ row }">
                <el-button size="small" @click="testFunction(row)">测试</el-button>
                <el-button size="small" :type="row.status === 'deployed' ? 'warning' : 'primary'" @click="toggleDeploy(row)">
                  {{ row.status === 'deployed' ? '取消部署' : '部署' }}
                </el-button>
                <el-button type="danger" size="small" @click="deleteFunction(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 全局配置 -->
        <el-tab-pane label="全局配置" name="config">
          <el-form :model="globalConfig" label-width="160px">
            <el-form-item label="启用边缘计算">
              <el-switch v-model="globalConfig.enabled" />
            </el-form-item>
            <el-form-item label="默认超时时间">
              <el-input-number v-model="globalConfig.defaultTimeout" :min="1000" :max="30000" />
              <span class="unit">毫秒</span>
            </el-form-item>
            <el-form-item label="内存限制">
              <el-input-number v-model="globalConfig.memoryLimit" :min="16" :max="512" />
              <span class="unit">MB</span>
            </el-form-item>
            <el-form-item label="日志级别">
              <el-select v-model="globalConfig.logLevel">
                <el-option label="debug" value="debug" />
                <el-option label="info" value="info" />
                <el-option label="warn" value="warn" />
                <el-option label="error" value="error" />
              </el-select>
            </el-form-item>
          </el-form>
          <div style="margin-top: 20px">
            <el-button type="primary" @click="saveGlobalConfig">保存配置</el-button>
          </div>
        </el-tab-pane>

        <!-- 运行时管理 -->
        <el-tab-pane label="运行时管理" name="runtimes">
          <div class="table-toolbar">
            <el-button type="primary" @click="showAddRuntimeDialog = true">添加运行时</el-button>
          </div>

          <el-table :data="runtimes" style="width: 100%">
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="version" label="版本" width="100" />
            <el-table-column prop="type" label="类型" width="100" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button type="danger" size="small" @click="deleteRuntime(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 创建函数对话框 -->
    <el-dialog v-model="showCreateDialog" title="创建函数" width="700px">
      <el-form :model="functionForm" label-width="100px">
        <el-form-item label="函数名称">
          <el-input v-model="functionForm.name" placeholder="输入函数名称" />
        </el-form-item>
        <el-form-item label="运行时">
          <el-select v-model="functionForm.runtime">
            <el-option v-for="rt in runtimes" :key="rt.id" :label="`${rt.name} ${rt.version}`" :value="`${rt.name}:${rt.version}`" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="functionForm.description" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="函数代码">
          <el-input v-model="functionForm.code" type="textarea" :rows="10" placeholder="输入JavaScript代码" />
        </el-form-item>
        <el-form-item label="超时时间">
          <el-input-number v-model="functionForm.timeout" :min="1000" :max="30000" />
          <span class="unit">毫秒</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="saveFunction">创建</el-button>
      </template>
    </el-dialog>

    <!-- 添加运行时对话框 -->
    <el-dialog v-model="showAddRuntimeDialog" title="添加运行时" width="500px">
      <el-form :model="runtimeForm" label-width="100px">
        <el-form-item label="名称">
          <el-input v-model="runtimeForm.name" placeholder="如: quickjs" />
        </el-form-item>
        <el-form-item label="版本">
          <el-input v-model="runtimeForm.version" placeholder="如: 1.0.0" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="runtimeForm.type">
            <el-option label="JavaScript" value="javascript" />
            <el-option label="Lua" value="lua" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddRuntimeDialog = false">取消</el-button>
        <el-button type="primary" @click="saveRuntime">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { edgeComputingApi } from '../../api/cdn'

const activeTab = ref('functions')
const showCreateDialog = ref(false)
const showAddRuntimeDialog = ref(false)
const functionSearch = ref('')

const functions = ref([])
const runtimes = ref([])
const functionForm = reactive({ name: '', runtime: 'quickjs:1.0.0', description: '', code: '', timeout: 5000 })
const runtimeForm = reactive({ id: null, name: '', version: '', type: 'javascript' })
const globalConfig = reactive({ enabled: true, defaultTimeout: 5000, memoryLimit: 128, logLevel: 'info' })

const filteredFunctions = computed(() => {
  return functions.value.filter(fn => !functionSearch.value || fn.name.includes(functionSearch.value))
})

const loadFunctions = async () => {
  try {
    const { data } = await edgeComputingApi.list()
    functions.value = data
  } catch (e) { ElMessage.error('加载函数列表失败') }
}

const loadRuntimes = async () => {
  try {
    const { data } = await edgeComputingApi.getRuntimes()
    runtimes.value = data
  } catch (e) { ElMessage.error('加载运行时列表失败') }
}

const loadGlobalConfig = async () => {
  try {
    const { data } = await edgeComputingApi.getGlobalConfig()
    Object.assign(globalConfig, data)
  } catch (e) { ElMessage.error('加载全局配置失败') }
}

const saveFunction = async () => {
  try {
    await edgeComputingApi.create(functionForm)
    ElMessage.success('创建成功')
    showCreateDialog.value = false
    loadFunctions()
  } catch (e) { ElMessage.error('创建失败') }
}

const testFunction = (fn) => { ElMessage.info('测试功能开发中') }

const toggleDeploy = async (fn) => {
  try {
    if (fn.status === 'deployed') {
      await edgeComputingApi.undeploy(fn.id)
      ElMessage.success('取消部署成功')
    } else {
      await edgeComputingApi.deploy(fn.id)
      ElMessage.success('部署成功')
    }
    loadFunctions()
  } catch (e) { ElMessage.error('操作失败') }
}

const deleteFunction = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此函数吗？', '提示')
    await edgeComputingApi.delete(id)
    ElMessage.success('删除成功')
    loadFunctions()
  } catch (e) { /* 用户取消 */ }
}

const saveGlobalConfig = async () => {
  try {
    await edgeComputingApi.updateGlobalConfig(globalConfig)
    ElMessage.success('保存成功')
  } catch (e) { ElMessage.error('保存失败') }
}

const saveRuntime = async () => {
  try {
    await edgeComputingApi.addRuntime(runtimeForm)
    ElMessage.success('添加成功')
    showAddRuntimeDialog.value = false
    loadRuntimes()
  } catch (e) { ElMessage.error('添加失败') }
}

const deleteRuntime = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此时运行时吗？', '提示')
    await edgeComputingApi.deleteRuntime(id)
    ElMessage.success('删除成功')
    loadRuntimes()
  } catch (e) { /* 用户取消 */ }
}

onMounted(() => {
  loadFunctions()
  loadRuntimes()
  loadGlobalConfig()
})
</script>

<style scoped>
.edge-computing { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
.table-toolbar { display: flex; align-items: center; margin-bottom: 16px }
</style>

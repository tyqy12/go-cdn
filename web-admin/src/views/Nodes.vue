<template>
  <div class="space-y-6">
    <!-- 筛选器 -->
    <el-card>
      <el-row :gutter="20">
        <el-col :span="6">
          <el-select v-model="nodeStore.filter.type" placeholder="节点类型" clearable class="w-full">
            <el-option label="边缘节点" value="edge" />
            <el-option label="核心节点" value="core" />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-select v-model="nodeStore.filter.region" placeholder="地区" clearable class="w-full">
            <el-option v-for="r in nodeStore.regions" :key="r" :label="r" :value="r" />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-select v-model="nodeStore.filter.status" placeholder="状态" clearable class="w-full">
            <el-option label="在线" value="online" />
            <el-option label="离线" value="offline" />
            <el-option label="降级" value="degraded" />
          </el-select>
        </el-col>
        <el-col :span="6" class="flex gap-2">
          <el-button type="primary" @click="nodeStore.fetchNodes" :loading="nodeStore.loading">
            <el-icon><Refresh /></el-icon>刷新
          </el-button>
          <el-button type="success" @click="showQuickInstallDialog">
            <el-icon><Download /></el-icon>快速安装
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 节点表格 -->
    <el-card>
      <template #header>
        <div class="flex justify-between items-center">
          <span>节点列表</span>
          <el-button type="primary" @click="showDeployDialog">
            <el-icon><Plus /></el-icon>生成部署脚本
          </el-button>
        </div>
      </template>
      <el-table :data="nodeStore.filteredNodes" v-loading="nodeStore.loading" style="width: 100%">
        <el-table-column prop="name" label="节点名称" min-width="150">
          <template #default="{ row }">
            <div>
              <p class="font-medium">{{ row.name }}</p>
              <p class="text-gray-400 text-sm">{{ row.ip }}</p>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            <el-tag :type="row.type === 'edge' ? 'primary' : 'success'" size="small">
              {{ row.type === 'edge' ? '边缘' : '核心' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="region" label="地区" width="80" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : row.status === 'offline' ? 'danger' : 'warning'">
              {{ row.status === 'online' ? '在线' : row.status === 'offline' ? '离线' : '降级' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="connections" label="连接数" width="120">
          <template #default="{ row }">{{ formatNumber(row.connections) }}</template>
        </el-table-column>
        <el-table-column prop="cpu_percent" label="CPU" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.cpu_percent" :stroke-width="10" />
          </template>
        </el-table-column>
        <el-table-column prop="memory_percent" label="内存" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.memory_percent" :stroke-width="10" status="success" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-tooltip content="重启">
                <el-button size="small" type="warning" @click="handleCommand(row.id, 'restart')">
                  <el-icon><RefreshRight /></el-icon>
                </el-button>
              </el-tooltip>
              <el-tooltip content="重载配置">
                <el-button size="small" type="primary" @click="handleCommand(row.id, 'reload')">
                  <el-icon><Refresh /></el-icon>
                </el-button>
              </el-tooltip>
              <el-tooltip content="部署脚本">
                <el-button size="small" type="success" @click="showDeployForNode(row)">
                  <el-icon><Document /></el-icon>
                </el-button>
              </el-tooltip>
              <el-tooltip content="详情">
                <el-button size="small" @click="showDetail(row)">
                  <el-icon><View /></el-icon>
                </el-button>
              </el-tooltip>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 详情对话框 -->
    <el-dialog v-model="detailVisible" title="节点详情" width="600px">
      <el-descriptions :column="2" border v-if="currentNode">
        <el-descriptions-item label="节点ID">{{ currentNode.id }}</el-descriptions-item>
        <el-descriptions-item label="节点名称">{{ currentNode.name }}</el-descriptions-item>
        <el-descriptions-item label="IP地址">{{ currentNode.ip }}</el-descriptions-item>
        <el-descriptions-item label="节点类型">{{ currentNode.type }}</el-descriptions-item>
        <el-descriptions-item label="地区">{{ currentNode.region }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="currentNode.status === 'online' ? 'success' : 'danger'">
            {{ currentNode.status }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="活跃连接">{{ currentNode.connections }}</el-descriptions-item>
        <el-descriptions-item label="运行时长">{{ formatDuration(currentNode.uptime) }}</el-descriptions-item>
        <el-descriptions-item label="CPU使用">{{ currentNode.cpu_percent }}%</el-descriptions-item>
        <el-descriptions-item label="内存使用">{{ currentNode.memory_percent }}%</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- 部署脚本对话框 -->
    <el-dialog v-model="deployDialogVisible" title="生成部署脚本" width="650px">
      <el-form :model="deployForm" label-width="120px" :rules="deployRules" ref="deployFormRef">
        <el-form-item label="节点名称" prop="nodeName">
          <el-input v-model="deployForm.nodeName" placeholder="例如: hk-edge-001" />
        </el-form-item>
        <el-form-item label="节点类型" prop="nodeType">
          <el-select v-model="deployForm.nodeType" class="w-full">
            <el-option label="边缘节点 (Edge)" value="edge" />
            <el-option label="L2中转节点 (L2)" value="l2" />
            <el-option label="核心节点 (Core)" value="core" />
          </el-select>
        </el-form-item>
        <el-form-item label="地区" prop="region">
          <el-select v-model="deployForm.region" class="w-full">
            <el-option label="香港" value="hk" />
            <el-option label="大陆" value="cn" />
            <el-option label="新加坡" value="sg" />
            <el-option label="美国" value="us" />
          </el-select>
        </el-form-item>
        <el-form-item label="Master地址" prop="masterAddr">
          <el-input v-model="deployForm.masterAddr" placeholder="master.example.com:50051" />
        </el-form-item>
        <el-form-item label="标签">
          <el-select v-model="deployForm.tags" multiple placeholder="选择标签" class="w-full">
            <el-option label="生产环境" value="production" />
            <el-option label="测试环境" value="testing" />
            <el-option label="高可用" value="ha" />
          </el-select>
        </el-form-item>
        <el-divider content-position="left">可选组件</el-divider>
        <el-form-item label="安装组件">
          <el-checkbox-group v-model="deployForm.options">
            <el-checkbox label="installGost" value="installGost">安装gost代理</el-checkbox>
            <el-checkbox label="installNodeExporter" value="installNodeExporter">安装监控组件</el-checkbox>
            <el-checkbox label="enableTLS" value="enableTLS">启用TLS加密</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="deployDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="generateScript" :loading="generating">
          生成脚本
        </el-button>
      </template>
    </el-dialog>

    <!-- 脚本预览对话框 -->
    <el-dialog v-model="scriptDialogVisible" title="部署脚本" width="900px">
      <el-alert type="info" :closable="false" class="mb-4">
        <template #title>
          脚本已生成，请在目标服务器上执行。脚本24小时内有效。
        </template>
      </el-alert>
      <el-input
        type="textarea"
        v-model="generatedScript"
        :rows="25"
        readonly
        class="script-preview"
      />
      <template #footer>
        <el-button @click="scriptDialogVisible = false">关闭</el-button>
        <el-button @click="copyScript" type="primary">
          <el-icon><CopyDocument /></el-icon>复制脚本
        </el-button>
        <el-button @click="downloadScript" type="success">
          <el-icon><Download /></el-icon>下载脚本
        </el-button>
      </template>
    </el-dialog>

    <!-- 快速安装对话框 -->
    <el-dialog v-model="quickInstallDialogVisible" title="快速安装" width="550px">
      <el-alert type="info" :closable="false" class="mb-4">
        <template #title>
          在目标服务器上执行以下命令即可完成部署
        </template>
      </el-alert>
      <el-form :model="quickInstallForm" label-width="100px">
        <el-form-item label="Master地址">
          <el-input v-model="quickInstallForm.masterAddr" placeholder="master.example.com:50051" />
        </el-form-item>
        <el-form-item label="节点类型">
          <el-select v-model="quickInstallForm.nodeType" class="w-full">
            <el-option label="边缘节点 (Edge)" value="edge" />
            <el-option label="L2中转节点 (L2)" value="l2" />
            <el-option label="核心节点 (Core)" value="core" />
          </el-select>
        </el-form-item>
        <el-form-item label="地区">
          <el-select v-model="quickInstallForm.region" class="w-full">
            <el-option label="香港" value="hk" />
            <el-option label="大陆" value="cn" />
            <el-option label="新加坡" value="sg" />
            <el-option label="美国" value="us" />
          </el-select>
        </el-form-item>
      </el-form>
      <el-input
        type="textarea"
        v-model="quickInstallCommand"
        readonly
        class="mt-4"
        :rows="3"
      />
      <template #footer>
        <el-button @click="quickInstallDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="generateQuickInstallCommand" :loading="generatingQuick">
          生成命令
        </el-button>
        <el-button @click="copyQuickInstallCommand" type="success" :disabled="!quickInstallCommand">
          <el-icon><CopyDocument /></el-icon>复制命令
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, watch, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, RefreshRight, View, Plus, Download, Document, CopyDocument } from '@element-plus/icons-vue'
import { useNodeStore, useDeployStore } from '../stores'
import { deployApi } from '../api'

const nodeStore = useNodeStore()
const deployStore = useDeployStore()

// 对话框状态
const detailVisible = ref(false)
const deployDialogVisible = ref(false)
const scriptDialogVisible = ref(false)
const quickInstallDialogVisible = ref(false)
const currentNode = ref(null)

// 表单引用
const deployFormRef = ref(null)

// 部署表单
const deployForm = reactive({
  nodeName: '',
  nodeType: 'edge',
  region: 'hk',
  masterAddr: '',
  tags: [],
  options: []
})

// 快速安装表单
const quickInstallForm = reactive({
  masterAddr: '',
  nodeType: 'edge',
  region: 'hk'
})

// 生成状态
const generating = ref(false)
const generatingQuick = ref(false)

// 生成的脚本
const generatedScript = ref('')
const currentScriptId = ref('')

// 快速安装命令
const quickInstallCommand = ref('')

// 表单验证规则
const deployRules = {
  nodeName: [
    { required: true, message: '请输入节点名称', trigger: 'blur' },
    { min: 3, max: 64, message: '节点名称长度必须在3-64字符之间', trigger: 'blur' }
  ],
  nodeType: [
    { required: true, message: '请选择节点类型', trigger: 'change' }
  ],
  region: [
    { required: true, message: '请选择地区', trigger: 'change' }
  ],
  masterAddr: [
    { required: true, message: '请输入Master地址', trigger: 'blur' }
  ]
}

// 格式化数字
const formatNumber = (num) => {
  if (!num) return '0'
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

// 格式化时长
const formatDuration = (seconds) => {
  if (!seconds) return '-'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

// 执行命令
const handleCommand = async (id, command) => {
  try {
    await ElMessageBox.confirm(`确定要对节点执行 ${command} 操作吗？`, '确认', { type: 'warning' })
    await nodeStore.executeCommand(id, command)
  } catch {}
}

// 显示详情
const showDetail = (node) => {
  currentNode.value = node
  detailVisible.value = true
}

// 显示部署对话框
const showDeployDialog = () => {
  // 重置表单
  deployForm.nodeName = ''
  deployForm.nodeType = 'edge'
  deployForm.region = 'hk'
  deployForm.masterAddr = ''
  deployForm.tags = []
  deployForm.options = []
  deployDialogVisible.value = true
}

// 为指定节点显示部署对话框
const showDeployForNode = (node) => {
  deployForm.nodeName = `${node.region}-${node.type}-${node.name}`
  deployForm.nodeType = node.type
  deployForm.region = node.region
  deployForm.masterAddr = nodeStore.masterAddr || 'master.example.com:50051'
  deployForm.tags = node.tags || []
  deployForm.options = []
  deployDialogVisible.value = true
}

// 生成部署脚本
const generateScript = async () => {
  try {
    await deployFormRef.value.validate()
  } catch {
    return
  }

  generating.value = true
  try {
    const data = {
      nodeName: deployForm.nodeName,
      nodeType: deployForm.nodeType,
      region: deployForm.region,
      masterAddr: deployForm.masterAddr,
      tags: deployForm.tags,
      options: {
        installGost: deployForm.options.includes('installGost'),
        installNodeExporter: deployForm.options.includes('installNodeExporter'),
        enableTLS: deployForm.options.includes('enableTLS')
      }
    }

    await deployStore.generateScript(data)
    generatedScript.value = deployStore.currentScript
    currentScriptId.value = deployStore.currentScriptId

    deployDialogVisible.value = false
    scriptDialogVisible.value = true
    ElMessage.success('部署脚本生成成功')
  } catch (error) {
    console.error('生成部署脚本失败:', error)
    ElMessage.error('生成部署脚本失败')
  } finally {
    generating.value = false
  }
}

// 复制脚本
const copyScript = async () => {
  try {
    await navigator.clipboard.writeText(generatedScript.value)
    ElMessage.success('脚本已复制到剪贴板')
  } catch {
    ElMessage.error('复制失败，请手动选择文本复制')
  }
}

// 下载脚本
const downloadScript = async () => {
  try {
    const response = await deployApi.downloadScript(currentScriptId.value)
    const blob = new Blob([generatedScript.value], { type: 'text/plain' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `deploy-${currentScriptId.value}.sh`
    link.click()
    window.URL.revokeObjectURL(url)
  } catch (error) {
    console.error('下载脚本失败:', error)
  }
}

// 显示快速安装对话框
const showQuickInstallDialog = () => {
  quickInstallForm.masterAddr = nodeStore.masterAddr || ''
  quickInstallForm.nodeType = 'edge'
  quickInstallForm.region = 'hk'
  quickInstallCommand.value = ''
  quickInstallDialogVisible.value = true
}

// 生成快速安装命令
const generateQuickInstallCommand = () => {
  if (!quickInstallForm.masterAddr) {
    ElMessage.warning('请输入Master地址')
    return
  }

  quickInstallCommand.value = `curl -fsSL https://install.ai-cdn.com/agent.sh | bash -s -- --master ${quickInstallForm.masterAddr} --type ${quickInstallForm.nodeType} --region ${quickInstallForm.region}`
}

// 复制快速安装命令
const copyQuickInstallCommand = async () => {
  try {
    await navigator.clipboard.writeText(quickInstallCommand.value)
    ElMessage.success('命令已复制到剪贴板')
  } catch {
    ElMessage.error('复制失败，请手动选择文本复制')
  }
}

// 页面加载时获取节点列表
onMounted(() => {
  nodeStore.fetchNodes()
})
</script>
<style scoped>
.script-preview :deep(.el-textarea__inner) {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 12px;
  line-height: 1.5;
}
</style>

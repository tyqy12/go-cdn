<template>
  <div class="space-y-6">
    <el-card>
      <template #header>
        <div class="flex justify-between items-center">
          <span class="font-bold">配置版本列表</span>
          <el-button type="primary" @click="showCreateDialog = true">
            <el-icon><Plus /></el-icon>新建配置
          </el-button>
        </div>
      </template>
      <el-table :data="configStore.configs" v-loading="configStore.loading">
        <el-table-column prop="version" label="版本" width="120">
          <template #default="{ row }">
            <el-tag>{{ row.version }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" />
        <el-table-column prop="node_type" label="节点类型" width="100" />
        <el-table-column prop="regions" label="适用地区" width="150">
          <template #default="{ row }">{{ row.regions?.join(', ') }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'published' ? 'success' : row.status === 'draft' ? 'info' : 'danger'">
              {{ row.status === 'published' ? '已发布' : row.status === 'draft' ? '草稿' : '归档' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200">
          <template #default="{ row }">
            <el-button-group>
              <el-button v-if="row.status === 'draft'" type="success" size="small" @click="handlePublish(row.version)">
                发布
              </el-button>
              <el-button v-if="row.status === 'published'" type="warning" size="small" @click="handleRollback(row.version)">
                回滚
              </el-button>
              <el-button size="small" @click="showDetail(row)">查看</el-button>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showCreateDialog" title="新建配置" width="500px">
      <el-form :model="newConfig" label-width="100px">
        <el-form-item label="版本号">
          <el-input v-model="newConfig.version" placeholder="v1.0.0" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="newConfig.description" />
        </el-form-item>
        <el-form-item label="节点类型">
          <el-select v-model="newConfig.node_type" class="w-full">
            <el-option label="边缘节点" value="edge" />
            <el-option label="核心节点" value="core" />
            <el-option label="全部" value="all" />
          </el-select>
        </el-form-item>
        <el-form-item label="适用地区">
          <el-checkbox-group v-model="newConfig.regions">
            <el-checkbox v-for="r in nodeStore.regions" :key="r" :label="r">{{ r }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { useConfigStore, useNodeStore } from '../stores'

const configStore = useConfigStore()
const nodeStore = useNodeStore()
const showCreateDialog = ref(false)
const newConfig = ref({ version: '', description: '', node_type: 'edge', regions: [] })

const handlePublish = async (version) => {
  try {
    await ElMessageBox.confirm(`确定要发布配置 ${version} 吗？`, '确认')
    await configStore.publish(version)
  } catch {}
}

const handleRollback = async (version) => {
  try {
    await ElMessageBox.confirm(`确定要回滚到配置 ${version} 吗？`, '确认')
    await configStore.rollback(version)
  } catch {}
}

const handleCreate = async () => {
  showCreateDialog.value = false
  // API call would go here
}

const showDetail = (config) => {
  alert(`配置详情\n版本: ${config.version}\n描述: ${config.description}\n节点类型: ${config.node_type}`)
}

const formatTime = (time) => time ? new Date(time).toLocaleString('zh-CN') : '-'

onMounted(() => {
  nodeStore.fetchNodes()
  configStore.fetchConfigs()
})
</script>

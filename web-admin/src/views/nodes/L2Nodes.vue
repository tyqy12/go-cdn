<template>
  <div class="l2-nodes">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>L2节点管理</span>
          <el-button type="primary" @click="showCreateDialog = true">添加节点</el-button>
        </div>
      </template>

      <div class="table-toolbar">
        <el-input v-model="search" placeholder="搜索节点" style="width: 240px" clearable />
      </div>

      <el-table :data="filteredNodes" style="width: 100%">
        <el-table-column prop="name" label="节点名称" width="150" />
        <el-table-column prop="ip" label="IP地址" width="140" />
        <el-table-column prop="region" label="地区" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.region }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'danger'" size="small">
              {{ row.status === 'online' ? '在线' : '离线' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200">
          <template #default="{ row }">
            <el-button size="small" @click="editNode(row)">编辑</el-button>
            <el-button size="small" :type="row.status === 'online' ? 'warning' : 'primary'" @click="toggleNode(row)">
              {{ row.status === 'online' ? '下线' : '上线' }}
            </el-button>
            <el-button type="danger" size="small" @click="deleteNode(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showCreateDialog" :title="editingNode ? '编辑节点' : '添加节点'" width="500px">
      <el-form :model="nodeForm" label-width="100px">
        <el-form-item label="节点名称">
          <el-input v-model="nodeForm.name" placeholder="输入节点名称" />
        </el-form-item>
        <el-form-item label="IP地址">
          <el-input v-model="nodeForm.ip" placeholder="如: 192.168.1.100" />
        </el-form-item>
        <el-form-item label="地区">
          <el-select v-model="nodeForm.region">
            <el-option label="中国大陆" value="cn" />
            <el-option label="香港" value="hk" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="saveNode">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { l2NodeApi } from '../../api/cdn'

const showCreateDialog = ref(false)
const editingNode = ref(null)
const search = ref('')
const nodes = ref([])
const nodeForm = reactive({ id: null, name: '', ip: '', region: 'cn', role: 'l2_proxy' })

const filteredNodes = computed(() => {
  return nodes.value.filter(n => !search.value || n.name.includes(search.value))
})

const loadNodes = async () => {
  try {
    const { data } = await l2NodeApi.list()
    nodes.value = data
  } catch (e) { ElMessage.error('加载节点列表失败') }
}

const saveNode = async () => {
  try {
    if (editingNode.value) await l2NodeApi.update(editingNode.value, nodeForm)
    else await l2NodeApi.create(nodeForm)
    ElMessage.success('保存成功')
    showCreateDialog.value = false
    loadNodes()
  } catch (e) { ElMessage.error('保存失败') }
}

const editNode = (node) => {
  editingNode.value = node.id
  Object.assign(nodeForm, node)
  showCreateDialog.value = true
}

const deleteNode = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此节点吗？', '提示')
    await l2NodeApi.delete(id)
    ElMessage.success('删除成功')
    loadNodes()
  } catch (e) { /* 用户取消 */ }
}

const toggleNode = async (node) => {
  try {
    if (node.status === 'online') await l2NodeApi.offline(node.id)
    else await l2NodeApi.online(node.id)
    loadNodes()
  } catch (e) { ElMessage.error('操作失败') }
}

onMounted(() => loadNodes())
</script>

<style scoped>
.l2-nodes { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.table-toolbar { display: flex; align-items: center; margin-bottom: 16px }
</style>

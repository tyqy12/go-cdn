<template>
  <div class="object-storage">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>对象存储配置</span>
          <el-button type="primary" @click="showCreateDialog = true">添加存储</el-button>
        </div>
      </template>

      <el-table :data="storages" style="width: 100%">
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="type" label="类型" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="endpoint" label="Endpoint" />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" @click="testStorage(row)">测试</el-button>
            <el-button type="danger" size="small" @click="deleteStorage(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showCreateDialog" title="添加存储" width="500px">
      <el-form :model="storageForm" label-width="100px">
        <el-form-item label="存储名称">
          <el-input v-model="storageForm.name" placeholder="输入存储名称" />
        </el-form-item>
        <el-form-item label="存储类型">
          <el-select v-model="storageForm.type">
            <el-option label="阿里云OSS" value="oss" />
            <el-option label="AWS S3" value="s3" />
          </el-select>
        </el-form-item>
        <el-form-item label="Endpoint">
          <el-input v-model="storageForm.endpoint" placeholder="API地址" />
        </el-form-item>
        <el-form-item label="存储桶">
          <el-input v-model="storageForm.bucket" placeholder="Bucket名称" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="saveStorage">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { objectStorageApi } from '../../api/cdn'

const showCreateDialog = ref(false)
const storages = ref([])
const storageForm = reactive({ id: null, name: '', type: 'oss', endpoint: '', bucket: '' })

const loadStorages = async () => {
  try {
    const { data } = await objectStorageApi.list()
    storages.value = data
  } catch (e) { ElMessage.error('加载存储列表失败') }
}

const saveStorage = async () => {
  try {
    await objectStorageApi.create(storageForm)
    ElMessage.success('保存成功')
    showCreateDialog.value = false
    loadStorages()
  } catch (e) { ElMessage.error('保存失败') }
}

const deleteStorage = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此存储配置吗？', '提示')
    await objectStorageApi.delete(id)
    ElMessage.success('删除成功')
    loadStorages()
  } catch (e) { /* 用户取消 */ }
}

const testStorage = async (storage) => {
  try {
    await objectStorageApi.test(storage.id)
    ElMessage.success('连接测试成功')
  } catch (e) { ElMessage.error('连接测试失败') }
}

onMounted(() => loadStorages())
</script>

<style scoped>
.object-storage { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

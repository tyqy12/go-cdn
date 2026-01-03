<template>
  <div class="packages">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>流量包管理</span>
          <el-button type="primary" @click="showCreateDialog = true">创建流量包</el-button>
        </div>
      </template>

      <el-table :data="packages" style="width: 100%">
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="traffic" label="流量" width="120">
          <template #default="{ row }">{{ row.traffic }}GB</template>
        </el-table-column>
        <el-table-column prop="price" label="价格" width="100">
          <template #default="{ row }">¥{{ row.price }}</template>
        </el-table-column>
        <el-table-column prop="validity" label="有效期" width="100">
          <template #default="{ row }">{{ row.validity }}天</template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" @click="editPackage(row)">编辑</el-button>
            <el-button type="danger" size="small" @click="deletePackage(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showCreateDialog" title="创建流量包" width="500px">
      <el-form :model="packageForm" label-width="100px">
        <el-form-item label="名称">
          <el-input v-model="packageForm.name" placeholder="输入名称" />
        </el-form-item>
        <el-form-item label="流量">
          <el-input-number v-model="packageForm.traffic" :min="1" />
          <span class="form-tip">GB</span>
        </el-form-item>
        <el-form-item label="价格">
          <el-input-number v-model="packageForm.price" :min="0" :precision="2" />
          <span class="form-tip">元</span>
        </el-form-item>
        <el-form-item label="有效期">
          <el-input-number v-model="packageForm.validity" :min="1" />
          <span class="form-tip">天</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="savePackage">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { packagesApi } from '../../api/cdn'

const showCreateDialog = ref(false)
const packages = ref([])
const packageForm = reactive({ id: null, name: '', traffic: 100, price: 10, validity: 30 })

const loadPackages = async () => {
  try {
    const { data } = await packagesApi.list()
    packages.value = data
  } catch (e) { ElMessage.error('加载流量包列表失败') }
}

const savePackage = async () => {
  try {
    await packagesApi.create(packageForm)
    ElMessage.success('保存成功')
    showCreateDialog.value = false
    loadPackages()
  } catch (e) { ElMessage.error('保存失败') }
}

const editPackage = (pkg) => {
  Object.assign(packageForm, pkg)
  showCreateDialog.value = true
}

const deletePackage = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此流量包吗？', '提示')
    ElMessage.success('删除成功')
    loadPackages()
  } catch (e) { /* 用户取消 */ }
}

onMounted(() => loadPackages())
</script>

<style scoped>
.packages { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.form-tip { margin-left: 8px; color: #909399; font-size: 12px }
</style>

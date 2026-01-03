<template>
  <div class="billing-plans">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>套餐管理</span>
          <el-button type="primary" @click="showCreateDialog = true">创建套餐</el-button>
        </div>
      </template>

      <el-table :data="plans" style="width: 100%">
        <el-table-column prop="name" label="套餐名称" width="150" />
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="price" label="价格/月" width="100">
          <template #default="{ row }">¥{{ row.price }}</template>
        </el-table-column>
        <el-table-column prop="traffic" label="流量限额" width="120">
          <template #default="{ row }">{{ formatTraffic(row.traffic) }}</template>
        </el-table-column>
        <el-table-column prop="bandwidth" label="带宽限制" width="100">
          <template #default="{ row }">{{ row.bandwidth }}Mbps</template>
        </el-table-column>
        <el-table-column prop="nodes" label="节点数" width="80" />
        <el-table-column prop="storage" label="存储" width="100">
          <template #default="{ row }">{{ row.storage }}GB</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-switch :model-value="row.status === 'active'" @change="toggleStatus(row.id, $event)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="editPlan(row)">编辑</el-button>
            <el-button type="danger" size="small" @click="deletePlan(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 创建/编辑套餐对话框 -->
    <el-dialog v-model="showCreateDialog" :title="editingPlan ? '编辑套餐' : '创建套餐'" width="600px">
      <el-form :model="planForm" label-width="100px">
        <el-form-item label="套餐名称">
          <el-input v-model="planForm.name" placeholder="输入套餐名称" />
        </el-form-item>
        <el-form-item label="套餐类型">
          <el-select v-model="planForm.type">
            <el-option label="个人版" value="personal" />
            <el-option label="企业版" value="enterprise" />
            <el-option label="旗舰版" value="Flagship" />
          </el-select>
        </el-form-item>
        <el-form-item label="价格/月">
          <el-input-number v-model="planForm.price" :min="0" :precision="2" />
          <span class="unit">元</span>
        </el-form-item>
        <el-form-item label="流量限额">
          <el-input-number v-model="planForm.traffic" :min="0" />
          <span class="unit">GB</span>
        </el-form-item>
        <el-form-item label="带宽限制">
          <el-input-number v-model="planForm.bandwidth" :min="1" :max="10000" />
          <span class="unit">Mbps</span>
        </el-form-item>
        <el-form-item label="节点数">
          <el-input-number v-model="planForm.nodes" :min="1" :max="1000" />
        </el-form-item>
        <el-form-item label="存储空间">
          <el-input-number v-model="planForm.storage" :min="0" />
          <span class="unit">GB</span>
        </el-form-item>
        <el-form-item label="功能特性">
          <el-checkbox-group v-model="planForm.features">
            <el-checkbox label="cdn">CDN加速</el-checkbox>
            <el-checkbox label="ssl">SSL证书</el-checkbox>
            <el-checkbox label="ddos">DDoS防护</el-checkbox>
            <el-checkbox label="waf">WAF防护</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="savePlan">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { billingApi } from '../../api/cdn'

const showCreateDialog = ref(false)
const editingPlan = ref(null)
const plans = ref([])
const planForm = reactive({ id: null, name: '', type: 'personal', price: 99, traffic: 1000, bandwidth: 100, nodes: 10, storage: 100, features: [] })

const formatTraffic = (gb) => gb >= 1024 ? (gb / 1024).toFixed(1) + 'TB' : gb + 'GB'

const loadPlans = async () => {
  try {
    const { data } = await billingApi.listPlans()
    plans.value = data
  } catch (e) { ElMessage.error('加载套餐列表失败') }
}

const savePlan = async () => {
  try {
    if (editingPlan.value) await billingApi.updatePlan(editingPlan.value, planForm)
    else await billingApi.createPlan(planForm)
    ElMessage.success('保存成功')
    showCreateDialog.value = false
    loadPlans()
  } catch (e) { ElMessage.error('保存失败') }
}

const editPlan = (plan) => {
  editingPlan.value = plan.id
  Object.assign(planForm, plan)
  showCreateDialog.value = true
}

const deletePlan = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此套餐吗？', '提示')
    await billingApi.deletePlan(id)
    ElMessage.success('删除成功')
    loadPlans()
  } catch (e) { /* 用户取消 */ }
}

const toggleStatus = async (id, status) => {
  try {
    await billingApi.updatePlan(id, { status: status ? 'active' : 'inactive' })
    loadPlans()
  } catch (e) { ElMessage.error('操作失败') }
}

onMounted(() => loadPlans())
</script>

<style scoped>
.billing-plans { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.unit { margin-left: 8px; color: #606266 }
</style>

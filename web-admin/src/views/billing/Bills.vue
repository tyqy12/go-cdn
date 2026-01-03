<template>
  <div class="bills">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>账单管理</span>
          <el-date-picker
            v-model="dateRange"
            type="daterange"
            range-separator="至"
            start-placeholder="开始日期"
            end-placeholder="结束日期"
            @change="loadBills"
          />
        </div>
      </template>

      <el-table :data="bills" style="width: 100%">
        <el-table-column prop="id" label="账单ID" width="150" />
        <el-table-column prop="user" label="用户" width="100" />
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.type === 'traffic' ? '流量' : '套餐' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="amount" label="金额" width="100">
          <template #default="{ row }">¥{{ row.amount }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'paid' ? 'success' : 'warning'" size="small">
              {{ row.status === 'paid' ? '已支付' : '待支付' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="创建时间" width="180" />
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          :page-size="pageSize"
          layout="total, prev, pager, next"
          :total="total"
          @current-change="loadBills"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { billingApi } from '../../api/cdn'

const bills = ref([])
const dateRange = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)

const loadBills = async () => {
  try {
    const params = { page: currentPage.value, limit: pageSize.value }
    const { data, total: totalCount } = await billingApi.bills(params)
    bills.value = data
    total.value = totalCount
  } catch (e) { ElMessage.error('加载账单列表失败') }
}

onMounted(() => loadBills())
</script>

<style scoped>
.bills { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.pagination { margin-top: 16px; display: flex; justify-content: flex-end }
</style>

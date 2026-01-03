<template>
  <div class="logs-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>访问日志</span>
          <div>
            <el-button @click="handleExport">导出日志</el-button>
            <el-button type="primary" @click="showAnalyzeDialog = true">日志分析</el-button>
          </div>
        </div>
      </template>

      <el-form :model="searchForm" inline class="search-form">
        <el-form-item label="域名">
          <el-input v-model="searchForm.domain" placeholder="输入域名" clearable />
        </el-form-item>
        <el-form-item label="状态码">
          <el-select v-model="searchForm.statusCode" placeholder="选择状态码" clearable>
            <el-option label="200" value="200" />
            <el-option label="404" value="404" />
            <el-option label="500" value="500" />
          </el-select>
        </el-form-item>
        <el-form-item label="时间范围">
          <el-date-picker v-model="searchForm.timeRange" type="datetimerange" range-separator="至" start-placeholder="开始" end-placeholder="结束" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">搜索</el-button>
          <el-button @click="handleReset">重置</el-button>
        </el-form-item>
      </el-form>

      <el-table :data="logs" style="width: 100%" v-loading="loading">
        <el-table-column prop="timestamp" label="时间" width="180" />
        <el-table-column prop="domain" label="域名" width="180" />
        <el-table-column prop="path" label="请求路径" show-overflow-tooltip />
        <el-table-column prop="method" label="方法" width="80" />
        <el-table-column prop="statusCode" label="状态码" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.statusCode)" size="small">{{ row.statusCode }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="clientIP" label="客户端IP" width="140" />
        <el-table-column prop="responseTime" label="响应时间" width="100">
          <template #default="{ row }">
            <span :class="{ 'slow-response': row.responseTime > 1000 }">{{ row.responseTime }}ms</span>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-container">
        <el-pagination v-model:current-page="pagination.page" v-model:page-size="pagination.size" :total="pagination.total" layout="total, sizes, prev, pager, next" @size-change="handleSearch" @current-change="handleSearch" />
      </div>
    </el-card>

    <el-dialog v-model="showAnalyzeDialog" title="日志分析" width="500px">
      <el-form :model="analyzeForm" label-width="100px">
        <el-form-item label="分析类型">
          <el-select v-model="analyzeForm.type">
            <el-option label="UV统计" value="uv" />
            <el-option label="PV统计" value="pv" />
            <el-option label="流量统计" value="traffic" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAnalyzeDialog = false">取消</el-button>
        <el-button type="primary" @click="runAnalyze">开始分析</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { accessLogApi } from '../../api/cdn'

const loading = ref(false)
const showAnalyzeDialog = ref(false)
const logs = ref([])
const searchForm = reactive({ domain: '', statusCode: '', timeRange: null })
const analyzeForm = reactive({ type: 'uv', timeRange: null, domain: '' })
const pagination = reactive({ page: 1, size: 50, total: 0 })

const getStatusType = (code) => {
  if (code >= 200 && code < 300) return 'success'
  if (code >= 400 && code < 500) return 'warning'
  if (code >= 500) return 'danger'
  return 'info'
}

const loadLogs = async () => {
  loading.value = true
  try {
    const params = { page: pagination.page, size: pagination.size, domain: searchForm.domain, statusCode: searchForm.statusCode }
    const { data } = await accessLogApi.list(params)
    logs.value = data.list
    pagination.total = data.total
  } catch (e) { ElMessage.error('加载日志失败') }
  loading.value = false
}

const handleSearch = () => { pagination.page = 1; loadLogs() }
const handleReset = () => { searchForm.domain = ''; searchForm.statusCode = ''; searchForm.timeRange = null; handleSearch() }
const handleExport = async () => { ElMessage.success('导出开始') }
const runAnalyze = async () => { ElMessage.success('分析任务已提交'); showAnalyzeDialog.value = false }

onMounted(() => loadLogs())
</script>

<style scoped>
.logs-page { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
.search-form { margin-bottom: 16px; padding: 16px; background: #f5f7fa; border-radius: 4px }
.pagination-container { margin-top: 16px; display: flex; justify-content: flex-end }
.slow-response { color: #f56c6c; font-weight: bold }
</style>

<template>
  <div class="space-y-6">
    <el-row :gutter="20">
      <el-col :span="12">
        <el-card>
          <template #header>连接数趋势</template>
          <div ref="connectionChart" class="h-80"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>QPS趋势</template>
          <div ref="qpsChart" class="h-80"></div>
        </el-card>
      </el-col>
    </el-row>
    <el-row :gutter="20">
      <el-col :span="8">
        <el-card>
          <template #header>延迟分布</template>
          <div ref="latencyChart" class="h-64"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <template #header>错误率</template>
          <div ref="errorChart" class="h-64"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <template #header>流量统计</template>
          <div ref="trafficChart" class="h-64"></div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { metricsApi } from '../api'

const connectionChart = ref(null)
const qpsChart = ref(null)
const latencyChart = ref(null)
const errorChart = ref(null)
const trafficChart = ref(null)

let charts = []

// 获取监控数据
const fetchMetrics = async () => {
  try {
    const res = await metricsApi.aggregate({})
    if (res.data) {
      updateCharts(res.data)
    }
  } catch (error) {
    console.error('获取监控数据失败:', error)
    initCharts() // 使用默认数据
  }
}

const updateCharts = (data) => {
  // 更新连接数图表
  if (connectionChart.value) {
    const chart = echarts.init(connectionChart.value)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: data.timestamps || ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'] },
      yAxis: { type: 'value' },
      series: [{ data: data.connections || [120, 132, 101, 134, 90, 230], type: 'line', smooth: true, areaStyle: {} }]
    })
    charts.push(chart)
  }

  // 更新 QPS 图表
  if (qpsChart.value) {
    const chart = echarts.init(qpsChart.value)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: data.timestamps || ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'] },
      yAxis: { type: 'value' },
      series: [{ data: data.qps || [80, 92, 81, 94, 80, 130], type: 'line', smooth: true, areaStyle: {} }]
    })
    charts.push(chart)
  }

  // 更新延迟分布
  if (latencyChart.value) {
    const chart = echarts.init(latencyChart.value)
    chart.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie',
        radius: '60%',
        data: [
          { value: data.latencyP50 || 68, name: '<50ms' },
          { value: data.latencyP95 || 25, name: '50-100ms' },
          { value: data.latencyP99 || 7, name: '>100ms' }
        ]
      }]
    })
    charts.push(chart)
  }

  // 更新错误率
  if (errorChart.value) {
    const chart = echarts.init(errorChart.value)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: data.timestamps || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] },
      yAxis: { type: 'value' },
      series: [{ data: data.errorRate || [0.1, 0.15, 0.12, 0.08, 0.11, 0.2, 0.18], type: 'bar', color: '#ef4444' }]
    })
    charts.push(chart)
  }

  // 更新流量统计
  if (trafficChart.value) {
    const chart = echarts.init(trafficChart.value)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: data.timestamps || ['00:00', '06:00', '12:00', '18:00'] },
      yAxis: { type: 'value', axisLabel: { formatter: '{value} MB' } },
      series: [
        { name: '入站', data: data.bandwidthIn || [120, 200, 150, 80], type: 'bar' },
        { name: '出站', data: data.bandwidthOut || [100, 180, 120, 60], type: 'bar' }
      ]
    })
    charts.push(chart)
  }
}

const initCharts = () => {
  // 默认初始化
  updateCharts({})
}

onMounted(() => {
  initCharts()
  fetchMetrics()
})

onUnmounted(() => charts.forEach(c => c.dispose()))
</script>

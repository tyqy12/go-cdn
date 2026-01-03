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

const connectionChart = ref(null)
const qpsChart = ref(null)
const latencyChart = ref(null)
const errorChart = ref(null)
const trafficChart = ref(null)

let charts = []

const initCharts = () => {
  const options = {
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'] },
    yAxis: { type: 'value' },
    series: [{ data: [120, 132, 101, 134, 90, 230], type: 'line', smooth: true, areaStyle: {} }]
  }

  if (connectionChart.value) {
    const chart = echarts.init(connectionChart.value)
    chart.setOption({ ...options, title: { text: '活跃连接数' } })
    charts.push(chart)
  }
  if (qpsChart.value) {
    const chart = echarts.init(qpsChart.value)
    chart.setOption({ ...options, title: { text: '每秒请求数' }, series: [{ ...options.series[0], data: [80, 92, 81, 94, 80, 130] }] })
    charts.push(chart)
  }
  if (latencyChart.value) {
    const chart = echarts.init(latencyChart.value)
    chart.setOption({ tooltip: { trigger: 'item' }, series: [{ type: 'pie', radius: '60%', data: [
      { value: 68, name: '<50ms' },
      { value: 25, name: '50-100ms' },
      { value: 7, name: '>100ms' }
    ] }] })
    charts.push(chart)
  }
  if (errorChart.value) {
    const chart = echarts.init(errorChart.value)
    chart.setOption({ tooltip: { trigger: 'axis' }, xAxis: { type: 'category', data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] },
      yAxis: { type: 'value' },
      series: [{ data: [0.1, 0.15, 0.12, 0.08, 0.11, 0.2, 0.18], type: 'bar', color: '#ef4444' }] })
    charts.push(chart)
  }
  if (trafficChart.value) {
    const chart = echarts.init(trafficChart.value)
    chart.setOption({ tooltip: { trigger: 'axis' }, xAxis: { type: 'category', data: ['00:00', '06:00', '12:00', '18:00'] },
      yAxis: { type: 'value', axisLabel: { formatter: '{value} MB' } },
      series: [{ name: '入站', data: [120, 200, 150, 80], type: 'bar' }, { name: '出站', data: [100, 180, 120, 60], type: 'bar' }] })
    charts.push(chart)
  }
}

onMounted(initCharts)
onUnmounted(() => charts.forEach(c => c.dispose()))
</script>

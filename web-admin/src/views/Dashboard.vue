<template>
  <div class="space-y-6">
    <!-- 统计卡片 -->
    <el-row :gutter="20">
      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-gray-500 text-sm">总节点数</p>
              <p class="text-3xl font-bold mt-1">{{ nodeStore.nodes.length }}</p>
            </div>
            <el-icon class="text-4xl text-blue-500"><Grid /></el-icon>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-gray-500 text-sm">在线节点</p>
              <p class="text-3xl font-bold text-green-500 mt-1">{{ nodeStore.onlineNodes }}</p>
            </div>
            <el-icon class="text-4xl text-green-500"><CircleCheckFilled /></el-icon>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-gray-500 text-sm">活跃连接</p>
              <p class="text-3xl font-bold text-purple-500 mt-1">{{ formatNumber(nodeStore.totalConnections) }}</p>
            </div>
            <el-icon class="text-4xl text-purple-500"><Connection /></el-icon>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-gray-500 text-sm">活跃告警</p>
              <p class="text-3xl font-bold text-red-500 mt-1">{{ alertStore.firingAlerts.length }}</p>
            </div>
            <el-icon class="text-4xl text-red-500"><WarningFilled /></el-icon>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 世界地图 -->
    <el-card>
      <template #header>
        <div class="flex items-center justify-between">
          <span>全球节点分布</span>
          <el-tag type="info" size="small">实时监控</el-tag>
        </div>
      </template>
      <div ref="worldMapChart" class="h-96"></div>
    </el-card>

    <!-- 图表区 -->
    <el-row :gutter="20">
      <el-col :span="12">
        <el-card>
          <template #header>节点分布</template>
          <div ref="regionChart" class="h-64"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>最近告警</template>
          <el-table :data="alertStore.firingAlerts.slice(0, 5)" style="width: 100%">
            <el-table-column prop="name" label="告警名称" />
            <el-table-column prop="severity" label="级别">
              <template #default="{ row }">
                <el-tag :type="row.severity === 'critical' ? 'danger' : 'warning'" size="small">
                  {{ row.severity }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="node" label="节点" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import * as echarts from 'echarts'
import { Grid, CircleCheckFilled, Connection, WarningFilled } from '@element-plus/icons-vue'
import { useNodeStore, useAlertStore } from '../stores'

const nodeStore = useNodeStore()
const alertStore = useAlertStore()
const regionChart = ref(null)
const worldMapChart = ref(null)

const formatNumber = (num) => {
  if (!num) return '0'
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

// 节点坐标映射（经纬度）
const nodeCoordinates = {
  '北京': [116.4074, 39.9042],
  '上海': [121.4737, 31.2304],
  '广州': [113.2644, 23.1291],
  '深圳': [114.0558, 22.5429],
  '香港': [114.1694, 22.3193],
  '东京': [139.6917, 35.6895],
  '新加坡': [103.8198, 1.3521],
  '洛杉矶': [-118.2437, 34.0522],
  '纽约': [-74.0060, 40.7128],
  '伦敦': [-0.1276, 51.5074],
  '法兰克福': [8.6821, 50.1109],
  '悉尼': [151.2093, -33.8688],
  '首尔': [126.9780, 37.5665],
  '孟买': [72.8777, 19.0760],
  '迪拜': [55.2708, 25.2048],
  '阿姆斯特丹': [4.9041, 52.3676],
  '巴黎': [2.3522, 48.8566],
  '柏林': [13.4050, 52.5200],
  '莫斯科': [37.6173, 55.7558],
  '圣保罗': [-46.6333, -23.5505],
  '芝加哥': [-87.6298, 41.8781],
  '多伦多': [-79.3832, 43.6532],
  '温哥华': [-123.1207, 49.2827],
  '新加坡-2': [103.8198, 1.3521],
  '东京-2': [139.6917, 35.6895],
  '首尔-2': [126.9780, 37.5665],
}

const getNodeCoordinate = (nodeName) => {
  // 精确匹配
  if (nodeCoordinates[nodeName]) {
    return nodeCoordinates[nodeName]
  }
  
  // 模糊匹配
  for (const [key, coord] of Object.entries(nodeCoordinates)) {
    if (nodeName.includes(key) || key.includes(nodeName)) {
      return coord
    }
  }
  
  // 默认返回中国中心位置
  return [104.1954, 35.8617]
}

onMounted(async () => {
  try {
    await nodeStore.fetchNodes()
  } catch (error) {
    console.error('获取节点数据失败:', error)
  }
  
  // 初始化饼图
  if (regionChart.value) {
    const chart = echarts.init(regionChart.value)
    const regionData = nodeStore.regions.map(r => ({
      name: r,
      value: nodeStore.nodes.filter(n => n.region === r).length
    }))
    
    chart.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        data: regionData,
        emphasis: { itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0, 0, 0, 0.5)' } }
      }]
    })
  }
  
  // 初始化世界地图
  if (worldMapChart.value) {
    const mapChart = echarts.init(worldMapChart.value)
    
    // 动态加载世界地图数据
    fetch('https://raw.githubusercontent.com/apache/echarts/master/test/data/map/json/world.json')
      .then(response => response.json())
      .then(worldJson => {
        echarts.registerMap('world', worldJson)
        
        // 准备节点数据
        const mapData = nodeStore.nodes.map(node => {
          const coord = getNodeCoordinate(node.name || node.region || '')
          return {
            name: node.name || node.region,
            value: [...coord, node.connections || 0, node.status],
            status: node.status,
            connections: node.connections || 0
          }
        })
        
        mapChart.setOption({
          tooltip: {
            trigger: 'item',
            formatter: function(params) {
              if (params.data) {
                const status = params.data.status === 'online' ? '在线' : '离线'
                const connections = params.data.connections || 0
                return `<b>${params.name}</b><br/>状态: ${status}<br/>连接数: ${formatNumber(connections)}`
              }
              return params.name
            }
          },
          geo: {
            map: 'world',
            roam: true,
            zoom: 1.2,
            scaleLimit: {
              min: 1,
              max: 10
            },
            itemStyle: {
              areaColor: '#f3f4f6',
              borderColor: '#d1d5db'
            },
            emphasis: {
              itemStyle: {
                areaColor: '#e5e7eb'
              },
              label: {
                show: false
              }
            },
            label: {
              show: false
            }
          },
          series: [
            {
              name: '节点分布',
              type: 'scatter',
              coordinateSystem: 'geo',
              data: mapData,
              symbolSize: function(val) {
                const connections = val[2] || 0
                return Math.max(8, Math.min(30, connections / 10000 + 10))
              },
              itemStyle: {
                color: function(params) {
                  return params.data.status === 'online' ? '#10b981' : '#ef4444'
                },
                shadowBlur: 10,
                shadowColor: 'rgba(0, 0, 0, 0.3)'
              },
              emphasis: {
                scale: true
              }
            },
            {
              name: '节点连接',
              type: 'effectScatter',
              coordinateSystem: 'geo',
              data: mapData.filter(n => n.status === 'online'),
              symbolSize: function(val) {
                const connections = val[2] || 0
                return Math.max(8, Math.min(30, connections / 10000 + 10))
              },
              itemStyle: {
                color: '#3b82f6',
                shadowBlur: 10,
                shadowColor: 'rgba(59, 130, 246, 0.5)'
              },
              rippleEffect: {
                brushType: 'stroke',
                scale: 3
              }
            }
          ]
        })
      })
      .catch(error => {
        console.error('加载世界地图数据失败:', error)
      })
    
    // 响应式调整
    window.addEventListener('resize', () => mapChart.resize())
  }
})
</script>

<style scoped>
.stat-card {
  transition: all 0.3s;
}
.stat-card:hover {
  transform: translateY(-2px);
}
</style>

<template>
  <div class="notification-config">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>消息通知配置</span>
          <el-button type="primary" @click="showCreateDialog = true">添加通知</el-button>
        </div>
      </template>

      <el-table :data="notifications" style="width: 100%">
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="channel" label="通知渠道" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ row.channel }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" @click="testNotification(row)">测试</el-button>
            <el-button type="danger" size="small" @click="deleteNotification(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showCreateDialog" title="添加通知" width="500px">
      <el-form :model="notificationForm" label-width="100px">
        <el-form-item label="名称">
          <el-input v-model="notificationForm.name" placeholder="输入名称" />
        </el-form-item>
        <el-form-item label="通知渠道">
          <el-select v-model="notificationForm.channel">
            <el-option label="邮件" value="email" />
            <el-option label="钉钉" value="dingtalk" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateDialog = false">取消</el-button>
        <el-button type="primary" @click="saveNotification">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { notificationApi } from '../../api/cdn'

const showCreateDialog = ref(false)
const notifications = ref([])
const notificationForm = reactive({ id: null, name: '', channel: 'email', eventType: [], recipients: '' })

const loadNotifications = async () => {
  try {
    const { data } = await notificationApi.list()
    notifications.value = data
  } catch (e) { ElMessage.error('加载通知配置失败') }
}

const saveNotification = async () => {
  try {
    await notificationApi.create(notificationForm)
    ElMessage.success('保存成功')
    showCreateDialog.value = false
    loadNotifications()
  } catch (e) { ElMessage.error('保存失败') }
}

const deleteNotification = async (id) => {
  try {
    await ElMessageBox.confirm('确定要删除此通知配置吗？', '提示')
    await notificationApi.delete(id)
    ElMessage.success('删除成功')
    loadNotifications()
  } catch (e) { /* 用户取消 */ }
}

const testNotification = async (notification) => {
  try {
    await notificationApi.test(notification.id)
    ElMessage.success('测试消息已发送')
  } catch (e) { ElMessage.error('发送失败') }
}

onMounted(() => loadNotifications())
</script>

<style scoped>
.notification-config { padding: 20px }
.card-header { display: flex; justify-content: space-between; align-items: center }
</style>

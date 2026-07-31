<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  api, banDevice, unbanDevice, batchBanDevices, batchUnbanDevices, fetchDeviceBans,
  type Device, type DeviceBan, type GUIDRule, type Node, type OnlineSession, type PermissionGroup, type User,
} from './api'

type Dashboard = { users: number; devices: number; nodes: number; online: number }
type ThemeMode = 'system' | 'light' | 'dark'

const me = ref<User | null>(null)
const loading = ref(true)
const persistentSections = ['overview', 'devices', 'nodes', 'online', 'groups', 'users', 'settings']
const hashSection = window.location.hash.match(/^#\/([^/]+)/)?.[1]
const savedSection = window.localStorage.getItem('openppp2.activeSection')
const initialSection = hashSection && persistentSections.includes(hashSection)
  ? hashSection
  : savedSection && persistentSections.includes(savedSection) ? savedSection : 'overview'
const active = ref(initialSection)
const dashboard = reactive<Dashboard>({ users: 0, devices: 0, nodes: 0, online: 0 })
const users = ref<User[]>([])
const devices = ref<Device[]>([])
const nodes = ref<Node[]>([])
const permissionGroups = ref<PermissionGroup[]>([])
const online = ref<OnlineSession[]>([])
const rules = ref<GUIDRule[]>([])
const deviceBans = ref<DeviceBan[]>([])
const onlineSub = ref<'list' | 'blacklist'>('list')
const selectedNode = ref<Node | null>(null)
const heartbeatNow = ref(Date.now())
let heartbeatTimer: number | undefined
const login = reactive({ username: 'admin', password: '' })
const loginBusy = ref(false)
const deviceDialog = ref(false)
const nodeDialog = ref(false)
const editingNode = ref<Node | null>(null)
const groupDialog = ref(false)
const editingGroup = ref<PermissionGroup | null>(null)
const userDialog = ref(false)
const ruleDialog = ref(false)
const communicationKey = ref('')
const publicURL = ref('')
const settingsSaving = ref(false)
const systemDarkMode = window.matchMedia('(prefers-color-scheme: dark)')
const savedTheme = window.localStorage.getItem('openppp2.theme')
const themeMode = ref<ThemeMode>(
  savedTheme === 'light' || savedTheme === 'dark' || savedTheme === 'system' ? savedTheme : 'system',
)
const deviceForm = reactive({ name: '', guid: '' })
const userForm = reactive({ username: '', displayName: '', password: '', role: 'user', groupIds: [] as number[], trafficLimit: -1 })
const nodeForm = reactive({
  key: '', name: '', accessMode: 'blacklist', duplicateGuidPolicy: 'replace_old',
  enabled: true, published: true,
})
const ruleForm = reactive({ guid: '', effect: 'deny', reason: '' })
const groupForm = reactive({ key: '', name: '', enabled: true, nodeIds: [] as number[] })
const deviceOwnerFilter = ref<number | undefined>(undefined)
const deviceSelection = ref<Set<number>>(new Set())
const onlineSelection = ref<OnlineSession[]>([])

const isAdmin = computed(() => me.value?.role === 'admin')
const nodeNames = computed(() => new Map(nodes.value.map((node) => [node.id, node.name])))
const groupNames = computed(() => new Map(permissionGroups.value.map((group) => [group.id, group.name])))
const managementTemplateReady = computed(() => (
  publicURL.value.trim() !== '' && nodeForm.key.trim() !== '' && communicationKey.value !== ''
))
const managementConfigTemplate = computed(() => [
  '        "management": {',
  '            "enabled": true,',
  `            "endpoint": ${JSON.stringify(publicURL.value.trim())},`,
  `            "node-id": ${JSON.stringify(nodeForm.key.trim())},`,
  `            "communication-key": ${JSON.stringify(communicationKey.value)}`,
  '        },',
].join('\r\n'))
watch(active, (section) => {
  if (persistentSections.includes(section)) {
    window.localStorage.setItem('openppp2.activeSection', section)
    if (window.location.hash !== `#/${section}`) window.location.hash = `/${section}`
  }
})
watch(deviceOwnerFilter, () => {
  deviceSelection.value = new Set()
})
function applyTheme() {
  const dark = themeMode.value === 'dark' || (themeMode.value === 'system' && systemDarkMode.matches)
  document.documentElement.classList.toggle('dark', dark)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
}
watch(themeMode, (mode) => {
  window.localStorage.setItem('openppp2.theme', mode)
  applyTheme()
}, { immediate: true })
function handleSystemThemeChange() {
  if (themeMode.value === 'system') applyTheme()
}
function syncSectionFromHash() {
  const section = window.location.hash.match(/^#\/([^/]+)/)?.[1]
  if (section && persistentSections.includes(section)) active.value = section
}
const formatTime = (value?: string) => value ? new Date(value).toLocaleString('zh-CN') : '—'
const formatBytes = (value: number) => {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}

async function loadAll() {
  const [stats, userList, deviceList, nodeList, onlineList, groupList, banList, settings] = await Promise.all([
    api<Dashboard>('/api/v1/dashboard'),
    api<User[]>('/api/v1/users'),
    api<Device[]>('/api/v1/devices'),
    api<Node[]>('/api/v1/nodes'),
    api<OnlineSession[]>('/api/v1/online'),
    isAdmin.value ? api<PermissionGroup[]>('/api/v1/permission-groups') : Promise.resolve([]),
    fetchDeviceBans(),
    isAdmin.value
      ? api<{ publicUrl: string; communicationKey: string }>('/api/v1/settings/general')
      : Promise.resolve({ publicUrl: '', communicationKey: '' }),
  ])
  Object.assign(dashboard, stats)
  users.value = userList
  devices.value = deviceList
  nodes.value = nodeList
  online.value = onlineList
  permissionGroups.value = groupList
  deviceBans.value = banList
  communicationKey.value = settings.communicationKey
  publicURL.value = settings.publicUrl
}

async function bootstrap() {
  try {
    me.value = await api<User>('/api/v1/me')
    if (me.value.role !== 'admin' && ['groups', 'users', 'settings'].includes(active.value)) active.value = 'overview'
    await loadAll()
  } catch {
    me.value = null
  } finally {
    loading.value = false
  }
}

async function signIn() {
  loginBusy.value = true
  try {
    me.value = await api<User>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(login),
    })
    if (me.value.role !== 'admin' && ['groups', 'users', 'settings'].includes(active.value)) active.value = 'overview'
    login.password = ''
    await loadAll()
  } catch (error) {
    ElMessage.error((error as Error).message)
  } finally {
    loginBusy.value = false
  }
}

async function signOut() {
  await api('/api/v1/auth/logout', { method: 'POST' })
  me.value = null
}

async function createDevice() {
  try {
    await api<{ device: Device; subscriptionToken: string; subscriptionUrl: string }>('/api/v1/devices', {
      method: 'POST',
      body: JSON.stringify(deviceForm),
    })
    deviceDialog.value = false
    Object.assign(deviceForm, { name: '', guid: '' })
    await loadAll()
    ElMessage.success('设备已创建，可直接复制订阅地址')
  } catch (error) {
    if (error instanceof Error) ElMessage.error(error.message)
  }
}

async function createUser() {
  try {
    const payload = {
      ...userForm,
      trafficLimit: userForm.trafficLimit === -1 ? -1 : Math.round(userForm.trafficLimit * 1024 ** 3),
    }
    await api('/api/v1/users', { method: 'POST', body: JSON.stringify(payload) })
    userDialog.value = false
    Object.assign(userForm, { username: '', displayName: '', password: '', role: 'user', groupIds: [], trafficLimit: -1 })
    await loadAll()
  } catch (error) {
    ElMessage.error((error as Error).message)
  }
}

function openCreateUser() {
  const defaultGroup = permissionGroups.value.find((group) => group.key === 'default')
  Object.assign(userForm, {
    username: '', displayName: '', password: '', role: 'user', trafficLimit: -1,
    groupIds: defaultGroup ? [defaultGroup.id] : [],
  })
  userDialog.value = true
}

async function setUserTraffic(user: User) {
  const current = user.trafficLimit > 0 ? Math.round(user.trafficLimit / 1024 ** 3) : -1
  try {
    const { value } = await ElMessageBox.prompt(
      `设置“${user.displayName}”的流量上限（GB）。已用 ${formatBytes(user.trafficUsed)}，上限 -1 表示不限量。`,
      '设置流量上限',
      {
        confirmButtonText: '保存',
        cancelButtonText: '取消',
        inputValue: String(current),
        inputPlaceholder: '例如 100，-1 表示不限量',
        inputValidator: (raw: string) => {
          const gb = Number(raw.trim())
          if (!Number.isFinite(gb) || gb < -1) return '请输入 -1 或大于等于 0 的数值（GB）'
          return true
        },
      },
    )
    const gb = Number(value.trim())
    const trafficLimit = gb === -1 ? -1 : Math.round(gb * 1024 ** 3)
    await api(`/api/v1/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ trafficLimit }) })
    await loadAll()
    ElMessage.success('流量上限已更新')
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function assignUserGroups(user: User, groupIds: number[]) {
  try {
    const updated = await api<User>(`/api/v1/users/${user.id}/permission-groups`, {
      method: 'PUT',
      body: JSON.stringify({ groupIds }),
    })
    user.groupIds = updated.groupIds
    await loadAll()
    ElMessage.success('用户权限组已更新')
  } catch (error) {
    ElMessage.error((error as Error).message)
    await loadAll()
  }
}

async function toggleUser(user: User) {
  try {
    const action = user.enabled ? '封禁' : '启用'
    await ElMessageBox.confirm(
      `确定${action}用户“${user.displayName}”吗？${user.enabled ? '该用户的设备 GUID 将从白名单移除，并加入所属黑名单节点的拒绝列表。' : ''}`,
      `${action}用户`,
      { type: 'warning', confirmButtonText: action, cancelButtonText: '取消' },
    )
    await api(`/api/v1/users/${user.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled: !user.enabled }),
    })
    await loadAll()
    ElMessage.success(`用户已${action}`)
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function deleteUser(user: User) {
  try {
    await ElMessageBox.confirm(
      `确定删除用户“${user.displayName}”吗？该用户的设备、订阅地址和登录会话会一并删除。`,
      '删除用户',
      { type: 'warning', confirmButtonText: '删除用户', cancelButtonText: '取消' },
    )
    await api(`/api/v1/users/${user.id}`, { method: 'DELETE' })
    await loadAll()
    ElMessage.success('用户已删除')
  } catch (error) {
    if (error instanceof Error) ElMessage.error(error.message)
  }
}

function openCreateNode() {
  editingNode.value = null
  Object.assign(nodeForm, {
    key: '', name: '', accessMode: 'blacklist', duplicateGuidPolicy: 'replace_old',
    enabled: true, published: true,
  })
  nodeDialog.value = true
}

function openEditNode(node: Node) {
  editingNode.value = node
  Object.assign(nodeForm, {
    key: node.key,
    name: node.name,
    accessMode: node.accessMode,
    duplicateGuidPolicy: node.duplicateGuidPolicy,
    enabled: node.enabled,
    published: node.published,
  })
  nodeDialog.value = true
}

async function saveNode() {
  try {
    if (editingNode.value) {
      await api(`/api/v1/nodes/${editingNode.value.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: nodeForm.name,
          enabled: nodeForm.enabled,
          published: nodeForm.published,
          accessMode: nodeForm.accessMode,
          duplicateGuidPolicy: nodeForm.duplicateGuidPolicy,
        }),
      })
      nodeDialog.value = false
      editingNode.value = null
      ElMessage.success('节点已更新')
      await loadAll()
      return
    }
    await api<Node>('/api/v1/nodes', {
      method: 'POST',
      body: JSON.stringify(nodeForm),
    })
    nodeDialog.value = false
    ElMessage.success('节点已创建，请在服务端填写节点标识和全局通讯密钥')
    await loadAll()
  } catch (error) {
    ElMessage.error((error as Error).message)
  }
}

async function saveSettings() {
  settingsSaving.value = true
  try {
    const result = await api<{ publicUrl: string; communicationKey: string }>('/api/v1/settings/general', {
      method: 'PUT',
      body: JSON.stringify({ publicUrl: publicURL.value, communicationKey: communicationKey.value }),
    })
    publicURL.value = result.publicUrl
    communicationKey.value = result.communicationKey
    await loadAll()
    ElMessage.success('设置已保存，订阅地址已立即更新')
  } catch (error) {
    ElMessage.error((error as Error).message)
  } finally {
    settingsSaving.value = false
  }
}

async function deleteNode(node: Node) {
  try {
    await ElMessageBox.confirm(
      `确定删除节点“${node.name}”吗？设备订阅关联、GUID 规则和在线记录会一并删除；远端 OpenPPP2 不会被停止。`,
      '删除服务端节点',
      { type: 'warning', confirmButtonText: '删除节点', cancelButtonText: '取消' },
    )
    await api(`/api/v1/nodes/${node.id}`, { method: 'DELETE' })
    if (selectedNode.value?.id === node.id) {
      selectedNode.value = null
      rules.value = []
      active.value = 'nodes'
    }
    ElMessage.success('节点已删除')
    await loadAll()
  } catch (error) {
    if (error instanceof Error) ElMessage.error(error.message)
  }
}

async function toggleDevice(device: Device) {
  try {
    await api(`/api/v1/devices/${device.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled: !device.enabled }),
    })
    await loadAll()
  } catch (error) {
    ElMessage.error((error as Error).message)
  }
}

async function deleteDevice(device: Device) {
  try {
    await ElMessageBox.confirm(`确定删除设备“${device.name}”及其所有订阅令牌吗？`, '删除设备', { type: 'warning' })
    await api(`/api/v1/devices/${device.id}`, { method: 'DELETE' })
    await loadAll()
  } catch (error) {
    if (error instanceof Error) ElMessage.error(error.message)
  }
}

async function copySubscription(device: Device) {
  await copy(device.subscriptionUrl)
}

async function copyWindowsSubscriptionCommand(device: Device) {
  const scriptUrl = `${device.subscriptionUrl}/scripts/install.ps1`
  await copy(`$u='${scriptUrl}'; $p=Join-Path $env:TEMP 'openppp2-subscription.ps1'; Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $p; & $p`)
}

async function copyUnixSubscriptionCommand(device: Device) {
  const scriptUrl = `${device.subscriptionUrl}/scripts/install.sh`
  await copy(`curl -fsSL '${scriptUrl}' | sh`)
}

async function banDeviceById(deviceId: number) {
  try {
    const { value: reason } = await ElMessageBox.prompt('请输入封禁原因（可选）', '封禁设备', {
      confirmButtonText: '封禁',
      cancelButtonText: '取消',
      inputPlaceholder: '原因',
    })
    await banDevice(deviceId, reason || '')
    ElMessage.success('设备已封禁')
    await loadAll()
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function unbanDeviceById(deviceId: number) {
  try {
    await ElMessageBox.confirm('确定解除该设备的封禁吗？', '解除封禁', {
      type: 'warning',
      confirmButtonText: '解除',
      cancelButtonText: '取消',
    })
    await unbanDevice(deviceId)
    ElMessage.success('设备已解除封禁')
    await loadAll()
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

const filteredDevices = computed(() => {
  if (isAdmin.value && deviceOwnerFilter.value !== undefined && deviceOwnerFilter.value > 0) {
    return devices.value.filter((device) => device.userId === deviceOwnerFilter.value)
  }
  return devices.value
})
const selectedDeviceCount = computed(() => deviceSelection.value.size)
const selectedOnlineCount = computed(() => onlineSelection.value.length)

function toggleDeviceSelection(deviceId: number, checked: boolean) {
  const next = new Set(deviceSelection.value)
  if (checked) next.add(deviceId)
  else next.delete(deviceId)
  deviceSelection.value = next
}

async function batchBanSelectedDevices() {
  const ids = [...deviceSelection.value]
  if (!ids.length) return
  try {
    const { value: reason } = await ElMessageBox.prompt(`将对选中的 ${ids.length} 台设备执行封禁。请输入封禁原因（可选）`, '批量封禁设备', {
      confirmButtonText: '封禁',
      cancelButtonText: '取消',
      inputPlaceholder: '原因',
    })
    const { banned } = await batchBanDevices(ids, reason || '')
    ElMessage.success(`已封禁 ${banned} 台设备`)
    deviceSelection.value = new Set()
    await loadAll()
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function batchUnbanSelectedDevices() {
  const ids = [...deviceSelection.value]
  if (!ids.length) return
  try {
    await ElMessageBox.confirm(`确定解除选中的 ${ids.length} 台设备的封禁吗？`, '批量解除封禁', {
      type: 'warning',
      confirmButtonText: '解除',
      cancelButtonText: '取消',
    })
    const { unbanned } = await batchUnbanDevices(ids)
    ElMessage.success(`已解除 ${unbanned} 台设备的封禁`)
    deviceSelection.value = new Set()
    await loadAll()
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function batchBanSelectedOnline() {
  const rows = onlineSelection.value.filter((row) => row.deviceId && !row.banned)
  const ids = [...new Set(rows.map((row) => row.deviceId!))]
  if (!ids.length) {
    ElMessage.warning('选中项中没有可封禁的设备')
    return
  }
  try {
    const { value: reason } = await ElMessageBox.prompt(`将对选中的 ${ids.length} 台设备执行封禁。请输入封禁原因（可选）`, '批量封禁在线设备', {
      confirmButtonText: '封禁',
      cancelButtonText: '取消',
      inputPlaceholder: '原因',
    })
    const { banned } = await batchBanDevices(ids, reason || '')
    ElMessage.success(`已封禁 ${banned} 台设备`)
    onlineSelection.value = []
    await loadAll()
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function batchUnbanSelectedOnline() {
  const rows = onlineSelection.value.filter((row) => row.deviceId && row.banned && row.canUnban)
  const ids = [...new Set(rows.map((row) => row.deviceId!))]
  if (!ids.length) {
    ElMessage.warning('选中项中没有可解除封禁的设备')
    return
  }
  try {
    await ElMessageBox.confirm(`确定解除选中的 ${ids.length} 台设备的封禁吗？`, '批量解除封禁', {
      type: 'warning',
      confirmButtonText: '解除',
      cancelButtonText: '取消',
    })
    const { unbanned } = await batchUnbanDevices(ids)
    ElMessage.success(`已解除 ${unbanned} 台设备的封禁`)
    onlineSelection.value = []
    await loadAll()
  } catch (error) {
    if (error instanceof Error && error.message !== 'cancel') ElMessage.error(error.message)
  }
}

async function updateNodeMode(node: Node, accessMode: string) {
  try {
    if (accessMode === node.accessMode) return
    if (accessMode === 'whitelist') {
      await ElMessageBox.confirm(
        node.whitelistGuidCount > 0
          ? `切换后仅允许权限组中的 ${node.whitelistGuidCount} 个有效设备 GUID 连接。`
          : '当前权限组中没有有效设备 GUID，切换后该节点将拒绝所有客户端。',
        '切换为白名单模式',
        { type: node.whitelistGuidCount > 0 ? 'warning' : 'error', confirmButtonText: '确认切换', cancelButtonText: '取消' },
      )
    }
    const updated = await api<Node>(`/api/v1/nodes/${node.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ accessMode }),
    })
    Object.assign(node, updated)
    ElMessage.success(accessMode === 'whitelist' ? '已切换为白名单模式' : '已切换为黑名单模式')
  } catch (error) {
    if (error instanceof Error) ElMessage.error(error.message)
  }
}

function openCreateGroup() {
  editingGroup.value = null
  Object.assign(groupForm, { key: '', name: '', enabled: true, nodeIds: [] })
  groupDialog.value = true
}

function openEditGroup(group: PermissionGroup) {
  editingGroup.value = group
  Object.assign(groupForm, {
    key: group.key, name: group.name, enabled: group.enabled,
    nodeIds: [...group.nodeIds],
  })
  groupDialog.value = true
}

async function saveGroup() {
  try {
    if (editingGroup.value) {
      await api(`/api/v1/permission-groups/${editingGroup.value.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: groupForm.name,
          enabled: groupForm.enabled,
          nodeIds: groupForm.nodeIds,
        }),
      })
      ElMessage.success('权限组已更新')
    } else {
      await api('/api/v1/permission-groups', {
        method: 'POST',
        body: JSON.stringify(groupForm),
      })
      ElMessage.success('权限组已创建')
    }
    groupDialog.value = false
    editingGroup.value = null
    await loadAll()
  } catch (error) {
    ElMessage.error((error as Error).message)
  }
}

async function deleteGroup(group: PermissionGroup) {
  try {
    await ElMessageBox.confirm(
      `确定删除权限组“${group.name}”吗？用户将无法再通过该组获取节点配置。`,
      '删除权限组',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
    await api(`/api/v1/permission-groups/${group.id}`, { method: 'DELETE' })
    ElMessage.success('权限组已删除')
    await loadAll()
  } catch (error) {
    if (error instanceof Error) ElMessage.error(error.message)
  }
}

async function openRules(node: Node) {
  selectedNode.value = node
  rules.value = await api<GUIDRule[]>(`/api/v1/nodes/${node.id}/rules`)
  active.value = 'rules'
}

async function createRule() {
  if (!selectedNode.value) return
  try {
    await api(`/api/v1/nodes/${selectedNode.value.id}/rules`, {
      method: 'POST',
      body: JSON.stringify(ruleForm),
    })
    ruleDialog.value = false
    Object.assign(ruleForm, { guid: '', effect: 'deny', reason: '' })
    rules.value = await api<GUIDRule[]>(`/api/v1/nodes/${selectedNode.value.id}/rules`)
  } catch (error) {
    ElMessage.error((error as Error).message)
  }
}

async function removeRule(rule: GUIDRule) {
  if (!selectedNode.value) return
  await api(`/api/v1/nodes/${selectedNode.value.id}/rules/${rule.id}`, { method: 'DELETE' })
  rules.value = rules.value.filter((item) => item.id !== rule.id)
}

async function copy(value: string) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value)
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = value
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      textarea.style.pointerEvents = 'none'
      document.body.appendChild(textarea)
      textarea.focus()
      textarea.select()
      const copied = document.execCommand('copy')
      textarea.remove()
      if (!copied) throw new Error('浏览器拒绝复制')
    }
    ElMessage.success('已复制')
  } catch {
    ElMessage.error('复制失败，请长按或选中文本手动复制')
  }
}

function formatAge(milliseconds: number) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000))
  if (seconds < 60) return `${seconds} 秒前`
  const minutes = Math.floor(seconds / 60)
  return minutes < 60 ? `${minutes} 分钟前` : `${Math.floor(minutes / 60)} 小时前`
}

function nodePresence(node: Node) {
  if (!node.enabled) return { tone: 'red', label: '已停用', detail: '节点已停用' }
  if (!node.lastSeenAt) return { tone: 'red', label: '离线', detail: '从未收到心跳' }
  const age = Math.max(0, heartbeatNow.value - new Date(node.lastSeenAt).getTime())
  if (age <= 90_000) return { tone: 'green', label: '在线', detail: formatAge(age) }
  if (age <= 10 * 60_000) return { tone: 'yellow', label: '等待心跳', detail: formatAge(age) }
  return { tone: 'red', label: '离线', detail: formatAge(age) }
}

let presenceRefreshing = false
async function refreshNodePresence() {
  heartbeatNow.value = Date.now()
  if (!me.value || presenceRefreshing) return
  presenceRefreshing = true
  try {
    nodes.value = await api<Node[]>('/api/v1/nodes')
  } catch {
    // Keep the last known state when a transient refresh fails.
  } finally {
    presenceRefreshing = false
  }
}

onMounted(() => {
  if (window.location.hash !== `#/${active.value}`) {
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#/${active.value}`)
  }
  window.addEventListener('hashchange', syncSectionFromHash)
  systemDarkMode.addEventListener('change', handleSystemThemeChange)
  heartbeatTimer = window.setInterval(refreshNodePresence, 10_000)
  bootstrap()
})
onUnmounted(() => {
  window.removeEventListener('hashchange', syncSectionFromHash)
  systemDarkMode.removeEventListener('change', handleSystemThemeChange)
  if (heartbeatTimer !== undefined) window.clearInterval(heartbeatTimer)
})
</script>

<template>
  <div v-if="loading" class="splash">
    <div class="brand-mark">O2</div>
    <span>正在载入管理中心</span>
  </div>

  <main v-else-if="!me" class="login-shell">
    <section class="login-intro">
      <div class="eyebrow">OPENPPP2 CONTROL DISTRIBUTION</div>
      <h1>配置统一，<br><span>节点保持独立。</span></h1>
      <p>面向多用户的 GUID、订阅与节点访问策略管理。数据流量不经过面板，节点失联仍可使用本地缓存。</p>
      <div class="intro-grid">
        <div><b>GUID</b><span>固定到设备</span></div>
        <div><b>SUB</b><span>权限组自动分配</span></div>
        <div><b>NODE</b><span>黑名单默认放行</span></div>
      </div>
    </section>
    <section class="login-panel">
      <div class="brand"><span class="brand-mark">O2</span><strong>OpenPPP2</strong></div>
      <div>
        <p class="muted">欢迎回来</p>
        <h2>登录管理中心</h2>
      </div>
      <el-form label-position="top" @submit.prevent="signIn">
        <el-form-item label="用户名">
          <el-input v-model="login.username" size="large" autocomplete="username" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="login.password" size="large" type="password" show-password autocomplete="current-password" @keyup.enter="signIn" />
        </el-form-item>
        <el-button type="primary" size="large" :loading="loginBusy" class="wide" @click="signIn">进入面板</el-button>
      </el-form>
    </section>
  </main>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark">O2</span><strong>OpenPPP2</strong></div>
      <nav>
        <button :class="{ active: active === 'overview' }" @click="active = 'overview'"><span>01</span>概览</button>
        <button :class="{ active: active === 'devices' }" @click="active = 'devices'"><span>02</span>设备与订阅</button>
        <button :class="{ active: active === 'nodes' }" @click="active = 'nodes'"><span>03</span>服务端节点</button>
        <button :class="{ active: active === 'online' }" @click="active = 'online'"><span>04</span>在线 GUID</button>
        <button v-if="isAdmin" :class="{ active: active === 'groups' }" @click="active = 'groups'"><span>05</span>权限组</button>
        <button v-if="isAdmin" :class="{ active: active === 'users' }" @click="active = 'users'"><span>06</span>用户</button>
        <button v-if="isAdmin" :class="{ active: active === 'settings' }" @click="active = 'settings'"><span>07</span>设置</button>
      </nav>
      <div class="sidebar-footer">
        <span>{{ me.displayName }}</span>
        <small>{{ me.role === 'admin' ? '管理员' : '用户' }}</small>
        <button @click="signOut">退出</button>
      </div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <p class="eyebrow">OPENPPP2 MANAGEMENT</p>
          <h1>{{ active === 'overview' ? '运行概览' : active === 'devices' ? '设备与订阅' : active === 'nodes' ? '服务端节点' : active === 'online' ? '在线 GUID' : active === 'groups' ? '权限组' : active === 'settings' ? '系统设置' : active === 'rules' ? `${selectedNode?.name} · 访问规则` : '用户管理' }}</h1>
        </div>
        <div class="status-pill"><i></i>管理服务正常</div>
      </header>

      <template v-if="active === 'overview'">
        <div class="metric-grid">
          <article><span>用户</span><strong>{{ dashboard.users }}</strong><small>已启用账户</small></article>
          <article><span>设备</span><strong>{{ dashboard.devices }}</strong><small>固定 GUID</small></article>
          <article><span>节点</span><strong>{{ dashboard.nodes }}</strong><small>配置分发目标</small></article>
          <article class="accent"><span>在线</span><strong>{{ dashboard.online }}</strong><small>最近 90 秒心跳</small></article>
        </div>
        <div class="panel-grid single">
          <article class="panel">
            <div class="panel-title"><div><p class="eyebrow">PRESENCE</p><h3>最近在线</h3></div><button class="text-button" @click="active = 'online'">查看全部</button></div>
            <div v-if="!online.length" class="empty">尚未收到服务端会话上报</div>
            <div v-for="session in online.slice(0, 5)" :key="session.id" class="activity-row">
              <span class="online-dot"></span>
              <code>{{ session.guid }}</code>
              <span>{{ nodeNames.get(session.nodeId) || `节点 ${session.nodeId}` }}</span>
              <time>{{ formatTime(session.lastHeartbeat) }}</time>
            </div>
          </article>
        </div>
      </template>

      <template v-else-if="active === 'devices'">
        <div class="action-row">
          <p>每台设备固定一个 GUID，并拥有独立订阅地址。</p>
          <div v-if="isAdmin" class="device-filter">
            <el-select v-model="deviceOwnerFilter" clearable filterable placeholder="筛选归属用户" style="width: 200px">
              <el-option v-for="user in users" :key="user.id" :label="user.displayName || user.username" :value="user.id" />
            </el-select>
            <el-button type="primary" @click="deviceDialog = true">添加设备</el-button>
          </div>
          <el-button v-else type="primary" @click="deviceDialog = true">添加设备</el-button>
        </div>
        <div v-if="selectedDeviceCount > 0" class="batch-bar">
          <span>已选 {{ selectedDeviceCount }} 台设备</span>
          <el-button type="danger" plain size="small" @click="batchBanSelectedDevices">批量封禁</el-button>
          <el-button type="success" plain size="small" @click="batchUnbanSelectedDevices">批量解封</el-button>
          <el-button text size="small" @click="deviceSelection = new Set()">清空</el-button>
        </div>
        <div class="card-list">
          <article v-for="device in filteredDevices" :key="device.id" class="device-card">
            <div class="device-head">
              <el-checkbox
                :model-value="deviceSelection.has(device.id)"
                @change="(checked: string | number | boolean) => toggleDeviceSelection(device.id, Boolean(checked))"
              />
              <div><span :class="['online-dot', { off: !device.online }]"></span><h3>{{ device.name }}</h3></div>
              <div class="device-tags">
                <el-tag v-if="isAdmin && device.ownerName" effect="plain" type="info">归属：{{ device.ownerName }}</el-tag>
                <el-tag :type="device.enabled ? 'success' : 'info'" effect="plain">{{ device.enabled ? '已启用' : '已禁用' }}</el-tag>
                <el-tag v-if="device.banned" type="danger" effect="plain">已封禁</el-tag>
              </div>
            </div>
            <code class="guid">{{ device.guid }}</code>
            <div class="field-label">订阅地址</div>
            <div class="subscription-address">
              <code>{{ device.subscriptionUrl }}</code>
              <el-button type="primary" @click="copySubscription(device)">复制订阅</el-button>
            </div>
            <div class="subscription-actions">
              <el-button @click="copyWindowsSubscriptionCommand(device)">复制 Windows 多配置命令</el-button>
              <el-button @click="copyUnixSubscriptionCommand(device)">复制 Linux/macOS 多配置命令</el-button>
            </div>
            <div class="field-label">权限组自动分配的订阅节点</div>
            <div class="tag-list">
              <el-tag v-for="groupName in device.permissionGroupNames" :key="groupName" effect="plain">{{ groupName }}</el-tag>
              <span v-if="!device.permissionGroupNames.length" class="muted">当前权限组没有可用节点</span>
            </div>
            <div class="device-meta"><span>最后在线</span><b>{{ formatTime(device.lastSeenAt) }}</b></div>
            <div v-if="device.banned" class="device-ban-note">
              <el-tag type="danger" effect="plain" size="small">封禁中</el-tag>
              <span>{{ device.banReason || '未填写原因' }}</span>
            </div>
            <div class="card-actions">
              <button v-if="!device.banned" @click="banDeviceById(device.id)">封禁</button>
              <button v-else-if="device.canUnban" @click="unbanDeviceById(device.id)">解除封禁</button>
              <button @click="toggleDevice(device)">{{ device.enabled ? '禁用' : '启用' }}</button>
              <button class="danger" @click="deleteDevice(device)">删除</button>
            </div>
          </article>
          <button class="add-card" @click="deviceDialog = true"><b>＋</b><span>添加一台设备</span></button>
        </div>
      </template>

      <template v-else-if="active === 'nodes'">
        <div class="action-row">
          <p>OpenPPP2 服务端直接拉取策略；这里不执行系统命令。</p>
          <el-button v-if="isAdmin" type="primary" @click="openCreateNode">添加节点</el-button>
        </div>
        <div class="table-panel">
          <el-table :data="nodes">
            <el-table-column label="节点" min-width="180">
              <template #default="{ row }">
                <b>{{ row.name }}</b>
                <small class="table-sub">{{ row.key }}</small>
                <small :class="['table-sub', row.configReady ? 'config-ready' : 'config-waiting']">
                  {{ row.configReady ? '配置已同步' : '等待服务端上传配置' }}
                </small>
              </template>
            </el-table-column>
            <el-table-column label="节点公网 IP" min-width="155">
              <template #default="{ row }"><code>{{ row.lastIp || '等待心跳' }}</code></template>
            </el-table-column>
            <el-table-column label="权限组" min-width="180">
              <template #default="{ row }">
                <div class="tag-list">
                  <el-tag v-for="groupId in row.groupIds" :key="groupId" size="small" effect="plain">{{ groupNames.get(groupId) || `组 ${groupId}` }}</el-tag>
                  <span v-if="!row.groupIds.length" class="muted">未分组</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="访问控制" width="255">
              <template #default="{ row }">
                <el-radio-group :model-value="row.accessMode" :disabled="!isAdmin" size="small" @change="(value: string) => updateNodeMode(row, value)">
                  <el-radio-button value="blacklist">黑名单·仅拒绝</el-radio-button>
                  <el-radio-button value="whitelist">白名单·严格</el-radio-button>
                </el-radio-group>
                <small class="table-sub">{{ row.accessMode === 'blacklist' ? '其他 GUID 均可运行' : `允许 ${row.whitelistGuidCount} 个组内 GUID` }}</small>
              </template>
            </el-table-column>
            <el-table-column prop="policyRevision" label="策略版本" width="110" />
            <el-table-column label="在线情况" min-width="190">
              <template #default="{ row }">
                <div class="node-presence">
                  <i :class="`presence-dot ${nodePresence(row).tone}`"></i>
                  <div><b>{{ nodePresence(row).label }}</b><small>{{ nodePresence(row).detail }}</small></div>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }"><el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '停用' }}</el-tag></template>
            </el-table-column>
            <el-table-column label="操作" width="245" fixed="right">
              <template #default="{ row }">
                <el-button text type="primary" @click="openRules(row)">GUID 规则</el-button>
                <el-button v-if="isAdmin" text type="primary" @click="openEditNode(row)">编辑</el-button>
                <el-button v-if="isAdmin" text type="danger" @click="deleteNode(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </template>

      <template v-else-if="active === 'rules'">
        <div class="action-row">
          <button class="back" @click="active = 'nodes'">← 返回节点</button>
          <el-button v-if="isAdmin" type="primary" @click="ruleDialog = true">添加规则</el-button>
        </div>
        <div class="table-panel">
          <el-table :data="rules">
            <el-table-column prop="guid" label="GUID" min-width="310"><template #default="{ row }"><code>{{ row.guid }}</code></template></el-table-column>
            <el-table-column label="效果" width="100"><template #default="{ row }"><el-tag :type="row.effect === 'deny' ? 'danger' : 'success'">{{ row.effect === 'deny' ? '拒绝' : '允许' }}</el-tag></template></el-table-column>
            <el-table-column prop="reason" label="原因" min-width="180" />
            <el-table-column label="" width="90"><template #default="{ row }"><el-button v-if="isAdmin" text type="danger" @click="removeRule(row)">删除</el-button></template></el-table-column>
          </el-table>
        </div>
      </template>

      <template v-else-if="active === 'online'">
        <div class="action-row">
          <el-radio-group v-model="onlineSub">
            <el-radio-button value="list">在线列表</el-radio-button>
            <el-radio-button value="blacklist">黑名单管理</el-radio-button>
          </el-radio-group>
          <el-button @click="loadAll">刷新</el-button>
        </div>
        <div v-if="onlineSub === 'list'" class="table-panel">
          <div v-if="selectedOnlineCount > 0" class="batch-bar">
            <span>已选 {{ selectedOnlineCount }} 条在线记录</span>
            <el-button type="danger" plain size="small" @click="batchBanSelectedOnline">批量封禁</el-button>
            <el-button type="success" plain size="small" @click="batchUnbanSelectedOnline">批量解封</el-button>
            <el-button text size="small" @click="onlineSelection = []">清空</el-button>
          </div>
          <el-table :data="online" @selection-change="(rows: OnlineSession[]) => onlineSelection = rows">
            <el-table-column type="selection" width="45" />
            <el-table-column prop="guid" label="GUID" min-width="310"><template #default="{ row }"><code>{{ row.guid }}</code></template></el-table-column>
            <el-table-column label="节点" min-width="150"><template #default="{ row }">{{ nodeNames.get(row.nodeId) || `节点 ${row.nodeId}` }}</template></el-table-column>
            <el-table-column v-if="isAdmin" label="归属" min-width="110"><template #default="{ row }">{{ row.ownerName || '未知' }}</template></el-table-column>
            <el-table-column prop="remoteIp" label="来源 IP" min-width="150" />
            <el-table-column label="流量" min-width="150"><template #default="{ row }">↓ {{ formatBytes(row.rxBytes) }} · ↑ {{ formatBytes(row.txBytes) }}</template></el-table-column>
            <el-table-column label="最后心跳" min-width="180"><template #default="{ row }">{{ formatTime(row.lastHeartbeat) }}</template></el-table-column>
            <el-table-column label="状态" width="120">
              <template #default="{ row }">
                <el-tag v-if="row.banned" type="danger">已封禁</el-tag>
                <el-tag v-else type="success">正常</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button v-if="!row.banned && row.deviceId" text type="danger" @click="banDeviceById(row.deviceId)">封禁</el-button>
                <el-button v-else-if="row.banned && row.canUnban && row.deviceId" text type="success" @click="unbanDeviceById(row.deviceId)">解除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
        <div v-else class="table-panel">
          <el-table :data="deviceBans">
            <el-table-column prop="guid" label="GUID" min-width="310"><template #default="{ row }"><code>{{ row.guid }}</code></template></el-table-column>
            <el-table-column prop="deviceName" label="设备" min-width="150" />
            <el-table-column prop="reason" label="原因" min-width="180" />
            <el-table-column prop="username" label="封禁者" width="120" />
            <el-table-column label="时间" width="180"><template #default="{ row }">{{ formatTime(row.createdAt) }}</template></el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button text type="success" :disabled="!row.canUnban" @click="unbanDeviceById(row.deviceId)">解除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </template>

      <template v-else-if="active === 'groups'">
        <div class="action-row">
          <p>权限组控制用户能拉取哪些节点配置；只有节点处于白名单模式时，组内设备 GUID 才限制实际连接。</p>
          <el-button type="primary" @click="openCreateGroup">添加权限组</el-button>
        </div>
        <div class="table-panel">
          <el-table :data="permissionGroups">
            <el-table-column label="权限组" min-width="180">
              <template #default="{ row }"><b>{{ row.name }}</b><small class="table-sub">{{ row.key }}</small></template>
            </el-table-column>
            <el-table-column label="用户" min-width="220">
              <template #default="{ row }">
                <div class="tag-list"><el-tag v-for="userId in row.userIds" :key="userId" size="small" effect="plain">{{ users.find((user) => user.id === userId)?.displayName || `用户 ${userId}` }}</el-tag><span v-if="!row.userIds.length" class="muted">无用户</span></div>
              </template>
            </el-table-column>
            <el-table-column label="节点" min-width="220">
              <template #default="{ row }">
                <div class="tag-list"><el-tag v-for="nodeId in row.nodeIds" :key="nodeId" size="small" effect="plain">{{ nodeNames.get(nodeId) || `节点 ${nodeId}` }}</el-tag><span v-if="!row.nodeIds.length" class="muted">无节点</span></div>
              </template>
            </el-table-column>
            <el-table-column label="有效 GUID" width="110"><template #default="{ row }">{{ row.guidCount }}</template></el-table-column>
            <el-table-column label="状态" width="90"><template #default="{ row }"><el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '停用' }}</el-tag></template></el-table-column>
            <el-table-column label="操作" width="145" fixed="right">
              <template #default="{ row }">
                <el-button text type="primary" @click="openEditGroup(row)">编辑</el-button>
                <el-button v-if="row.key !== 'default'" text type="danger" @click="deleteGroup(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </template>

      <template v-else-if="active === 'users'">
        <div class="action-row"><p>在用户栏为每个用户选择权限组；普通用户只能管理自己的设备和订阅选择。</p><el-button type="primary" @click="openCreateUser">添加用户</el-button></div>
        <div class="table-panel">
          <el-table :data="users">
            <el-table-column prop="displayName" label="名称" />
            <el-table-column prop="username" label="用户名" />
            <el-table-column label="角色"><template #default="{ row }">{{ row.role === 'admin' ? '管理员' : '用户' }}</template></el-table-column>
            <el-table-column label="权限组" min-width="260">
              <template #default="{ row }">
                <el-select :model-value="row.groupIds" multiple filterable class="wide" placeholder="选择权限组" @change="(value: number[]) => assignUserGroups(row, value)">
                  <el-option v-for="group in permissionGroups" :key="group.id" :label="group.name" :value="group.id" />
                </el-select>
              </template>
            </el-table-column>
            <el-table-column label="状态"><template #default="{ row }"><el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '禁用' }}</el-tag></template></el-table-column>
            <el-table-column label="流量" min-width="170">
              <template #default="{ row }">
                <div v-if="row.trafficLimit > 0" class="traffic-cell" :class="{ over: row.trafficUsed >= row.trafficLimit }">
                  <span>{{ formatBytes(row.trafficUsed) }} / {{ formatBytes(row.trafficLimit) }}</span>
                  <el-tag v-if="row.trafficUsed >= row.trafficLimit" type="danger" size="small" effect="plain">已用尽</el-tag>
                </div>
                <span v-else class="muted">不限量</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="210" fixed="right">
              <template #default="{ row }">
                <el-button text type="primary" :disabled="row.id === me?.id" @click="setUserTraffic(row)">流量</el-button>
                <el-button text :type="row.enabled ? 'warning' : 'success'" :disabled="row.id === me?.id" @click="toggleUser(row)">{{ row.enabled ? '封禁' : '启用' }}</el-button>
                <el-button text type="danger" :disabled="row.id === me?.id" @click="deleteUser(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </template>

      <template v-else-if="active === 'settings'">
        <div class="settings-grid">
          <article class="settings-card">
            <div>
              <p class="eyebrow">PUBLIC ACCESS</p>
              <h3>外部访问地址</h3>
              <p>用于生成订阅、配置下载和更新脚本地址。保存后立即生效，无需重启容器。</p>
            </div>
            <el-form label-position="top">
              <el-form-item label="OPENPPP2_PUBLIC_URL">
                <el-input v-model="publicURL" placeholder="https://panel.example.com" />
              </el-form-item>
            </el-form>
          </article>

          <article class="settings-card">
            <div>
              <p class="eyebrow">NODE AUTHENTICATION</p>
              <h3>节点通讯密钥</h3>
              <p>所有服务端节点共用此密钥，并通过节点标识区分。修改后节点也必须同步更新。</p>
            </div>
            <div class="setting-secret">
              <el-input v-model="communicationKey" show-password placeholder="输入任意字母、数字或符号组合" />
              <el-button @click="copy(communicationKey)">复制</el-button>
            </div>
          </article>

          <article class="settings-card">
            <div>
              <p class="eyebrow">APPEARANCE</p>
              <h3>显示主题</h3>
              <p>主题选择保存在当前浏览器。“跟随系统”会随操作系统深浅色设置自动变化。</p>
            </div>
            <el-radio-group v-model="themeMode">
              <el-radio-button value="system">跟随系统</el-radio-button>
              <el-radio-button value="light">浅色</el-radio-button>
              <el-radio-button value="dark">深色</el-radio-button>
            </el-radio-group>
          </article>
        </div>
        <div class="settings-save">
          <el-button type="primary" size="large" :loading="settingsSaving" @click="saveSettings">保存服务器设置</el-button>
        </div>
      </template>
    </section>
  </div>

  <el-dialog v-model="deviceDialog" title="添加设备" width="520">
    <el-form label-position="top">
      <el-form-item label="设备名称"><el-input v-model="deviceForm.name" placeholder="例如：Android 手机" /></el-form-item>
      <el-form-item label="固定 GUID（留空自动生成）"><el-input v-model="deviceForm.guid" placeholder="{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" /></el-form-item>
    </el-form>
    <template #footer><el-button @click="deviceDialog = false">取消</el-button><el-button type="primary" @click="createDevice">创建并生成订阅</el-button></template>
  </el-dialog>

  <el-dialog v-model="userDialog" title="添加用户" width="520">
    <el-form label-position="top">
      <el-form-item label="用户名"><el-input v-model="userForm.username" /></el-form-item>
      <el-form-item label="显示名称"><el-input v-model="userForm.displayName" /></el-form-item>
      <el-form-item label="初始密码"><el-input v-model="userForm.password" type="password" show-password /></el-form-item>
      <el-form-item label="角色"><el-radio-group v-model="userForm.role"><el-radio value="user">普通用户</el-radio><el-radio value="admin">管理员</el-radio></el-radio-group></el-form-item>
      <el-form-item label="流量上限(GB)">
        <el-input-number v-model="userForm.trafficLimit" :min="-1" :step="10" style="width: 100%" />
        <small class="table-sub">-1 表示不限量；达到上限后该用户全部设备（含新建）将停止通信</small>
      </el-form-item>
      <el-form-item label="权限组">
        <el-select v-model="userForm.groupIds" multiple filterable class="wide" placeholder="选择用户所属权限组">
          <el-option v-for="group in permissionGroups" :key="group.id" :label="group.name" :value="group.id" />
        </el-select>
      </el-form-item>
    </el-form>
    <template #footer><el-button @click="userDialog = false">取消</el-button><el-button type="primary" @click="createUser">创建用户</el-button></template>
  </el-dialog>

  <el-dialog v-model="nodeDialog" :title="editingNode ? '编辑服务端节点' : '添加服务端节点'" width="720">
    <el-form label-position="top">
      <div class="form-grid"><el-form-item label="节点标识"><el-input v-model="nodeForm.key" :disabled="!!editingNode" placeholder="hk01" /><small v-if="editingNode" class="table-sub">节点标识创建后不可修改</small></el-form-item><el-form-item label="显示名称"><el-input v-model="nodeForm.name" placeholder="香港 01" /></el-form-item></div>
      <el-form-item label="黑白名单模式">
        <el-radio-group v-model="nodeForm.accessMode">
          <el-radio-button value="blacklist">黑名单模式（只拒绝名单 GUID）</el-radio-button>
          <el-radio-button value="whitelist">白名单模式（仅允许权限组 GUID）</el-radio-button>
        </el-radio-group>
      </el-form-item>
      <el-form-item label="重复 GUID"><el-select v-model="nodeForm.duplicateGuidPolicy"><el-option label="新连接替换旧连接" value="replace_old" /><el-option label="拒绝新连接" value="reject_new" /></el-select></el-form-item>
      <div class="form-grid"><el-form-item label="节点状态"><el-switch v-model="nodeForm.enabled" active-text="允许节点拉取策略" inactive-text="停用节点" /></el-form-item><el-form-item label="订阅发布"><el-switch v-model="nodeForm.published" active-text="显示在订阅中" inactive-text="从订阅隐藏" /></el-form-item></div>
      <el-alert title="无需填写配置模板。服务端使用节点标识和通讯密钥连接后，会通过心跳自动上传原始配置。" type="info" :closable="false" />
      <div class="management-template">
        <div class="management-template-heading">
          <div>
            <strong>服务端接入配置</strong>
            <small>粘贴到服务端 appsettings.json 的 server 对象中</small>
          </div>
          <el-button
            type="primary"
            :disabled="!managementTemplateReady"
            @click="copy(managementConfigTemplate)"
          >复制配置</el-button>
        </div>
        <pre>{{ managementConfigTemplate }}</pre>
        <el-alert
          v-if="!managementTemplateReady"
          title="请填写节点标识，并先在服务器设置中保存外部访问地址和节点通讯密钥。"
          type="warning"
          :closable="false"
          show-icon
        />
      </div>
    </el-form>
    <template #footer><el-button @click="nodeDialog = false">取消</el-button><el-button type="primary" @click="saveNode">{{ editingNode ? '保存修改' : '创建节点' }}</el-button></template>
  </el-dialog>

  <el-dialog v-model="groupDialog" :title="editingGroup ? '编辑权限组' : '添加权限组'" width="680">
    <el-form label-position="top">
      <div class="form-grid">
        <el-form-item label="权限组标识"><el-input v-model="groupForm.key" :disabled="!!editingGroup" placeholder="standard" /><small v-if="editingGroup" class="table-sub">创建后不可修改</small></el-form-item>
        <el-form-item label="显示名称"><el-input v-model="groupForm.name" placeholder="普通用户组" /></el-form-item>
      </div>
      <el-form-item label="状态"><el-switch v-model="groupForm.enabled" active-text="启用" inactive-text="停用" /></el-form-item>
      <el-form-item label="包含服务端节点">
        <el-select v-model="groupForm.nodeIds" multiple filterable class="wide" placeholder="选择该组可以订阅的节点">
          <el-option v-for="node in nodes" :key="node.id" :label="`${node.name} (${node.key})`" :value="node.id" />
        </el-select>
      </el-form-item>
      <el-alert title="黑名单节点只按组分发配置，不限制其他 GUID；白名单节点只允许这些用户的有效设备 GUID。" type="info" :closable="false" />
    </el-form>
    <template #footer><el-button @click="groupDialog = false">取消</el-button><el-button type="primary" @click="saveGroup">{{ editingGroup ? '保存修改' : '创建权限组' }}</el-button></template>
  </el-dialog>

  <el-dialog v-model="ruleDialog" title="添加 GUID 规则" width="520">
    <el-form label-position="top">
      <el-form-item label="GUID"><el-input v-model="ruleForm.guid" /></el-form-item>
      <el-form-item label="效果"><el-radio-group v-model="ruleForm.effect"><el-radio value="deny">拒绝</el-radio><el-radio value="allow">允许</el-radio></el-radio-group></el-form-item>
      <el-form-item label="原因"><el-input v-model="ruleForm.reason" /></el-form-item>
    </el-form>
    <template #footer><el-button @click="ruleDialog = false">取消</el-button><el-button type="primary" @click="createRule">保存规则</el-button></template>
  </el-dialog>

</template>

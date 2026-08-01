export type User = {
  id: number
  username: string
  displayName: string
  role: 'admin' | 'user'
  enabled: boolean
  groupIds: number[]
  trafficLimit: number // 字节，-1 = 不限量
  trafficUsed: number // 字节，双向流量总和
}

export type Device = {
  id: number
  userId: number
  name: string
  guid: string
  enabled: boolean
  online: boolean
  nodeIds: number[]
  permissionGroupNames: string[]
  subscriptionUrl: string
  lastSeenAt?: string
  ownerName?: string
  banned?: boolean
  banReason?: string
  banId?: number
  selfBanned?: boolean
  canUnban?: boolean
}

export type Node = {
  id: number
  key: string
  name: string
  enabled: boolean
  published: boolean
  accessMode: 'blacklist' | 'whitelist'
  duplicateGuidPolicy: 'replace_old' | 'reject_new'
  configJson: string
  policyRevision: number
  groupIds: number[]
  whitelistGuidCount: number
  configReady: boolean
  lastSeenAt?: string
  lastIp?: string
}

export type PermissionGroup = {
  id: number
  key: string
  name: string
  enabled: boolean
  userIds: number[]
  nodeIds: number[]
  guidCount: number
}

export type GUIDRule = {
  id: number
  nodeId: number
  guid: string
  effect: 'allow' | 'deny'
  reason: string
  expiresAt?: string
}

export type OnlineSession = {
  id: number
  nodeId: number
  guid: string
  remoteIp: string
  rxBytes: number
  txBytes: number
  connectedAt: string
  lastHeartbeat: string
  deviceId?: number
  ownerName?: string
  banned?: boolean
  banReason?: string
  selfBanned?: boolean
  canUnban?: boolean
}

export type DeviceBan = {
  id: number
  deviceId: number
  guid: string
  bannedByUserId: number
  bannedByRole: 'admin' | 'user'
  reason: string
  unbannedAt?: string
  unbannedByUserId?: number
  createdAt: string
  updatedAt: string
  deviceName?: string
  username?: string
  selfBanned?: boolean
  canUnban?: boolean
}

export async function banDevice(deviceId: number, reason: string): Promise<DeviceBan> {
  return api<DeviceBan>(`/api/v1/devices/${deviceId}/ban`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })
}

export async function unbanDevice(deviceId: number): Promise<DeviceBan> {
  return api<DeviceBan>(`/api/v1/devices/${deviceId}/unban`, { method: 'POST' })
}

export async function batchBanDevices(ids: number[], reason: string): Promise<{ banned: number }> {
  return api<{ banned: number }>('/api/v1/devices/batch-ban', {
    method: 'POST',
    body: JSON.stringify({ ids, reason }),
  })
}

export async function batchUnbanDevices(ids: number[]): Promise<{ unbanned: number }> {
  return api<{ unbanned: number }>('/api/v1/devices/batch-unban', {
    method: 'POST',
    body: JSON.stringify({ ids }),
  })
}

export async function batchBanGuids(guids: string[], reason: string): Promise<{ banned: number }> {
  return api<{ banned: number }>('/api/v1/guid-bans/batch', {
    method: 'POST',
    body: JSON.stringify({ guids, reason }),
  })
}

export async function batchUnbanGuids(guids: string[]): Promise<{ unbanned: number }> {
  return api<{ unbanned: number }>('/api/v1/guid-bans/unban', {
    method: 'POST',
    body: JSON.stringify({ guids }),
  })
}

export async function fetchDeviceBans(): Promise<DeviceBan[]> {
  return api<DeviceBan[]>('/api/v1/device-bans')
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
    ...init,
  })
  if (response.status === 204) return undefined as T
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.error || `请求失败：HTTP ${response.status}`)
  return data as T
}

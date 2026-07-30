export type User = {
  id: number
  username: string
  displayName: string
  role: 'admin' | 'user'
  enabled: boolean
  groupIds: number[]
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

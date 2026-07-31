package model

import "time"

type SystemSetting struct {
	Key       string    `gorm:"size:80;primaryKey" json:"key"`
	Value     string    `gorm:"type:text;not null" json:"value"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type User struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"size:80;uniqueIndex;not null" json:"username"`
	DisplayName  string    `gorm:"size:120;not null" json:"displayName"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	Role         string    `gorm:"size:20;not null;default:user" json:"role"`
	Enabled      bool      `gorm:"not null;default:true" json:"enabled"`
	TrafficLimit int64     `gorm:"not null;default:-1" json:"trafficLimit"` // -1 = 不限量
	TrafficUsed  int64     `gorm:"not null;default:0" json:"trafficUsed"`   // 双向流量总和（rx+tx）
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type PermissionGroup struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	Key       string    `gorm:"size:80;uniqueIndex;not null" json:"key"`
	Name      string    `gorm:"size:120;not null" json:"name"`
	Enabled   bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type UserPermissionGroup struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	UserID    uint64    `gorm:"uniqueIndex:idx_user_permission_group;index;not null" json:"userId"`
	GroupID   uint64    `gorm:"uniqueIndex:idx_user_permission_group;index;not null" json:"groupId"`
	CreatedAt time.Time `json:"createdAt"`
}

type NodePermissionGroup struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	NodeID    uint64    `gorm:"uniqueIndex:idx_node_permission_group;index;not null" json:"nodeId"`
	GroupID   uint64    `gorm:"uniqueIndex:idx_node_permission_group;index;not null" json:"groupId"`
	CreatedAt time.Time `json:"createdAt"`
}

type Session struct {
	ID        uint64    `gorm:"primaryKey"`
	UserID    uint64    `gorm:"index;not null"`
	TokenHash string    `gorm:"size:64;uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"index;not null"`
	CreatedAt time.Time
}

type Device struct {
	ID         uint64     `gorm:"primaryKey" json:"id"`
	UserID     uint64     `gorm:"index;not null" json:"userId"`
	Name       string     `gorm:"size:120;not null" json:"name"`
	GUID       string     `gorm:"size:38;index;not null" json:"guid"`
	Enabled    bool       `gorm:"not null;default:true" json:"enabled"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
}

type SubscriptionToken struct {
	ID        uint64     `gorm:"primaryKey" json:"id"`
	DeviceID  uint64     `gorm:"index;not null" json:"deviceId"`
	TokenHash string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	RawToken  string     `gorm:"size:128;index" json:"-"`
	Name      string     `gorm:"size:120;not null" json:"name"`
	Enabled   bool       `gorm:"not null;default:true" json:"enabled"`
	Revision  uint64     `gorm:"not null;default:1" json:"revision"`
	LastUsed  *time.Time `json:"lastUsedAt"`
	CreatedAt time.Time  `json:"createdAt"`
}

type Node struct {
	ID                  uint64     `gorm:"primaryKey" json:"id"`
	Key                 string     `gorm:"size:80;uniqueIndex;not null" json:"key"`
	Name                string     `gorm:"size:120;not null" json:"name"`
	Enabled             bool       `gorm:"not null;default:true" json:"enabled"`
	Published           bool       `gorm:"not null;default:true" json:"published"`
	AccessMode          string     `gorm:"size:20;not null;default:blacklist" json:"accessMode"`
	DuplicateGUIDPolicy string     `gorm:"size:20;not null;default:replace_old" json:"duplicateGuidPolicy"`
	TokenHash           string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	ConfigJSON          string     `gorm:"type:text;not null" json:"configJson"`
	PolicyRevision      uint64     `gorm:"not null;default:1" json:"policyRevision"`
	LastSeenAt          *time.Time `json:"lastSeenAt"`
	LastIP              string     `gorm:"size:64" json:"lastIp"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
}

type DeviceNode struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	DeviceID  uint64    `gorm:"uniqueIndex:idx_device_node;not null" json:"deviceId"`
	NodeID    uint64    `gorm:"uniqueIndex:idx_device_node;index;not null" json:"nodeId"`
	CreatedAt time.Time `json:"createdAt"`
}

type GUIDRule struct {
	ID        uint64     `gorm:"primaryKey" json:"id"`
	NodeID    uint64     `gorm:"uniqueIndex:idx_node_guid_rule;index;not null" json:"nodeId"`
	GUID      string     `gorm:"size:38;uniqueIndex:idx_node_guid_rule;not null" json:"guid"`
	Effect    string     `gorm:"size:10;not null" json:"effect"`
	Reason    string     `gorm:"size:255" json:"reason"`
	ExpiresAt *time.Time `json:"expiresAt"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

type OnlineSession struct {
	ID            uint64     `gorm:"primaryKey" json:"id"`
	NodeID        uint64     `gorm:"uniqueIndex:idx_node_guid_online;index;not null" json:"nodeId"`
	GUID          string     `gorm:"size:38;uniqueIndex:idx_node_guid_online;index;not null" json:"guid"`
	RemoteIP      string     `gorm:"size:64" json:"remoteIp"`
	RXBytes       uint64     `gorm:"not null;default:0" json:"rxBytes"`
	TXBytes       uint64     `gorm:"not null;default:0" json:"txBytes"`
	ConnectedAt   time.Time  `json:"connectedAt"`
	LastHeartbeat time.Time  `gorm:"index;not null" json:"lastHeartbeat"`
	Disconnected  *time.Time `json:"disconnectedAt"`
}

type DeviceBan struct {
	ID               uint64     `gorm:"primaryKey" json:"id"`
	DeviceID         uint64     `gorm:"index;not null" json:"deviceId"`
	GUID             string     `gorm:"size:38;index;not null" json:"guid"`
	BannedByUserID   uint64     `gorm:"index;not null" json:"bannedByUserId"`
	BannedByRole     string     `gorm:"size:20;not null" json:"bannedByRole"`
	Reason           string     `gorm:"size:255" json:"reason"`
	UnbannedAt       *time.Time `json:"unbannedAt"`
	UnbannedByUserID *uint64    `json:"unbannedByUserId"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

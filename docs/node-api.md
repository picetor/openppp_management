# OpenPPP2 服务端接入协议

管理面板是策略分发端。OpenPPP2 服务端主动请求面板，面板不开放远程系统管理端口。

## 节点认证

所有节点共用面板中设置的固定通讯密钥，并通过各自的 `node-id` 区分：

```http
Authorization: Bearer <communication-key>
X-OpenPPP2-Node-ID: <node-id>
```

通讯密钥相当于面板与节点之间的固定密码，可以在面板中显示、复制和修改。修改后所有节点都需要同步更新。节点标识是创建节点时填写的字母数字组合。

## 拉取策略

```http
GET /api/v1/node/policy
Authorization: Bearer <communication-key>
X-OpenPPP2-Node-ID: hk01
```

黑名单模式返回示例：

```json
{
  "schema": "openppp2-node-policy",
  "version": 1,
  "revision": 4,
  "nodeId": "hk01",
  "enabled": true,
  "accessMode": "blacklist",
  "duplicateGuidPolicy": "replace_old",
  "blacklist": ["{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"],
  "whitelist": [],
  "generatedAt": "2026-07-29T12:00:00Z"
}
```

黑名单模式只拒绝 `blacklist` 中的 GUID，其他 GUID 默认放行。白名单模式只允许 `whitelist` 中的 GUID。服务端应缓存最后一次成功拉取的策略，面板不可用时继续使用缓存。

## 节点心跳

```http
POST /api/v1/node/heartbeat
Authorization: Bearer <communication-key>
X-OpenPPP2-Node-ID: hk01
Content-Type: application/json

{}
```

返回服务端时间和最新策略版本：

```json
{
  "serverTime": "2026-07-29T12:00:00Z",
  "policyRevision": 4
}
```

## 会话上报

上线或心跳：

```http
POST /api/v1/node/sessions
Authorization: Bearer <communication-key>
X-OpenPPP2-Node-ID: hk01
Content-Type: application/json

{
  "event": "heartbeat",
  "guid": "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
  "remoteIp": "203.0.113.10",
  "rxBytes": 1024000,
  "txBytes": 512000
}
```

离线：

```json
{
  "event": "offline",
  "guid": "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
  "rxBytes": 2048000,
  "txBytes": 900000
}
```

同一 GUID 可以同时存在于不同节点。同一节点内的会话以 `node + guid` 为逻辑唯一键。

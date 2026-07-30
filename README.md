# OpenPPP2 Management

## 交互式安装

Linux 主机需要预先安装 Git、Docker 和 Docker Compose v2。下载安装脚本后执行：

```bash
curl -fsSL https://raw.githubusercontent.com/picetor/openppp_management/main/install.sh \
  -o /tmp/openppp-management-install.sh
sudo sh /tmp/openppp-management-install.sh
```

安装程序支持 SQLite、外部 MySQL、本地 MySQL Docker 容器，以及自定义面板监听地址
（默认 `127.0.0.1`）、监听端口（默认 `8080`）、外部访问地址、管理员密码和节点通讯密钥。

默认安装目录为 `/opt/openppp_management`，最终配置保存在该目录的 `.env`。

## 更新现有安装

更新时不要重复执行安装脚本：脚本会重新询问配置并覆盖 `.env`。在现有安装目录中执行：

```bash
cd /opt/openppp_management
cp .env .env.backup
git pull --ff-only origin main
```

然后根据当前数据库部署方式重新构建并启动面板：

SQLite：

```bash
docker compose -f compose.sqlite.yaml up -d --build
```

本地 MySQL Docker 容器：

```bash
docker compose --profile mysql up -d --build
```

外部 MySQL：

```bash
docker compose up -d --build management
```

如果安装外部 MySQL 时生成了 `compose.mysql-external.yaml`，需要同时加载该文件：

```bash
docker compose -f compose.yaml -f compose.mysql-external.yaml up -d --build management
```

更新只替换程序和前端容器，不会删除 `data/` 中的 SQLite 数据或 Docker 数据卷。

OpenPPP2 Management 是一个多用户配置、固定 GUID、客户端订阅和服务端节点访问策略面板。

它只负责控制面：

- 用户维护自己的设备和固定 GUID。
- 用户为设备选择订阅节点。
- 面板生成兼容 `openppp2-subscription` v1 的设备专属订阅，并在设备页直接显示、复制。
- 节点使用黑名单或白名单策略。
- 黑名单为默认模式，未登记 GUID 允许连接。
- 权限组控制用户能够获取哪些节点配置。
- 白名单节点只允许其权限组用户的有效设备 GUID；黑名单节点不按权限组限制连接。
- OpenPPP2 服务端直接拉取策略并上报在线 GUID。
- VPN 数据不经过面板。

## 技术栈

- Go、Chi、GORM
- Vue 3、TypeScript、Element Plus
- MySQL（默认）或 SQLite（轻量部署）
- Docker

不包含反向代理和证书管理。容器默认绑定宿主机 `127.0.0.1:8080`，由部署者自行反代。

## SQLite 快速启动

复制环境变量示例并至少设置管理员密码：

```powershell
Copy-Item .env.example .env
```

然后使用 SQLite Compose：

```powershell
docker compose -f compose.sqlite.yaml up -d --build
```

访问 `http://127.0.0.1:8080`。

如果宿主机的 `8080` 已被占用，可以在 `.env` 中指定其他仅本机监听的端口：

```text
OPENPPP2_BIND_ADDRESS=127.0.0.1:18080
```

## MySQL 启动

在 `.env` 中设置：

```text
OPENPPP2_DATABASE_DRIVER=mysql
OPENPPP2_DATABASE_DSN=openppp2:数据库密码@tcp(mysql:3306)/openppp2_management?charset=utf8mb4&parseTime=true&loc=UTC
OPENPPP2_ADMIN_PASSWORD=管理员密码
MYSQL_PASSWORD=数据库密码
MYSQL_ROOT_PASSWORD=数据库Root密码
```

启动：

```powershell
docker compose --profile mysql up -d --build
```

## 使用流程

1. 管理员创建用户。
2. 管理员创建节点，并在面板设置所有节点共用的固定通讯密钥。
3. 用户添加属于当前登录账号的设备，系统生成固定 GUID；设备页可直接复制订阅地址。
4. 用户为设备勾选允许订阅的节点。
5. Android 客户端导入订阅地址，或从原始配置接口下载 `appsettings.json`。
6. OpenPPP2 服务端使用 `node-id + 通讯密钥` 拉取访问策略。

## 权限组与访问模式

管理员在“权限组”页面选择用户和服务端节点。用户只能在设备订阅中选择其
权限组包含的节点。

- 黑名单模式：权限组只控制配置分发；任何未命中黑名单的 GUID 都可以连接。
- 白名单模式：服务端只允许节点权限组中用户的已启用设备 GUID。
- 节点未加入权限组时，普通用户无法订阅；白名单节点将没有自动允许的 GUID。
- 本地紧急黑名单和节点 GUID 拒绝规则始终优先。

升级现有数据库时会自动创建 `default` 权限组，并把已有用户和节点加入其中，
避免现有订阅因升级失效。

标准订阅：

```text
GET /sub/v1/{device-token}
```

指定节点原始配置：

```text
GET /sub/v1/{device-token}/nodes/{node-key}/config
```

节点接入协议见 [docs/node-api.md](docs/node-api.md)。

## 本地开发

前端：

```powershell
Set-Location web
npm install
npm run dev
```

后端：

```powershell
$env:OPENPPP2_ADMIN_PASSWORD = "development-password"
$env:OPENPPP2_DATABASE_DRIVER = "sqlite"
go run ./cmd/management
```

前端开发服务器会把 `/api` 和 `/sub` 转发到后端的 `127.0.0.1:8080`。

## OpenPPP2 服务端接入

`D:\github\openppp2` 已实现直接接入，不需要单独 Agent。服务端支持：

- 使用节点标识和全局通讯密钥认证，定时拉取并缓存策略。
- 本地完成 GUID 黑白名单判断。
- 上报会话上线、心跳、流量增量和离线状态。
- 执行同节点重复 GUID 的 `replace_old` / `reject_new` 策略。
- 面板不可用时继续使用最后一次成功拉取的缓存。

在面板创建节点并设置固定通讯密钥，然后在服务端填写面板地址、
`node-id` 和 `communication-key`。完整的 `server.management` 配置示例见 OpenPPP2 仓库
`appsettings.json` 和 README 的“管理面板直连”章节。

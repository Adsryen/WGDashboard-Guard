# WGDashboard Docker 部署

## 快速开始

在仓库根目录执行：

```bash
cp docker/.env.example .env
docker compose --env-file .env -f docker/compose.yaml up -d --build
```

默认访问地址：`http://服务器地址:10086`。

首次启动会创建 WireGuard 配置和持久化数据。不要删除 Compose 创建的 `aconf`、`conf`、`data` 卷。

查看状态和日志：

```bash
docker compose --env-file .env -f docker/compose.yaml ps
docker compose --env-file .env -f docker/compose.yaml logs -f wgdashboard
```

停止服务：

```bash
docker compose --env-file .env -f docker/compose.yaml down
```

## 配置

复制 `docker/.env.example` 为 `.env` 后按需修改：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WGD_HTTP_PORT` | `10086` | 主机暴露的 Dashboard TCP 端口 |
| `WGD_PORT` | `10086` | 容器内 Dashboard 端口 |
| `WG_PORT` | `51820` | WireGuard UDP 端口 |
| `WG_AUTOSTART` | `wg0` | 启动时自动启动的 WireGuard 配置 |
| `TZ` | `UTC` | 容器时区 |
| `PUBLIC_IP` | 空 | Peer 配置使用的公网地址；为空时自动检测 |
| `WGD_USERNAME` | 空 | 可选的初始管理员用户名 |
| `WGD_PASSWORD` | 空 | 可选的初始管理员密码 |
| `WGD_ENABLE_TOTP` | 空 | 是否启用 TOTP |
| `WGD_DYNAMIC_CONFIG` | `true` | 是否允许启动时写入环境变量配置 |

需要发布多个 WireGuard 配置时，继续在 `ports` 中增加对应的 UDP 映射。

## 使用预构建镜像

如果项目发布了兼容镜像，可以在 `.env` 中设置：

```ini
WGD_IMAGE=ghcr.io/你的组织/wgdashboard-guard:latest
```

然后执行：

```bash
docker compose --env-file .env -f docker/compose.yaml pull
docker compose --env-file .env -f docker/compose.yaml up -d --no-build
```

使用当前源码构建时保留默认值，并执行 `--build`。

## 安全说明

- `NET_ADMIN` 是 WireGuard 容器正常管理接口所需权限，请不要把容器暴露到不可信主机。
- Dashboard 默认是 HTTP。生产环境建议放在 HTTPS 反向代理之后，或限制管理端口只允许 VPN/LAN 网段访问。
- 不要把包含密码的 `.env` 提交到 Git。
- 备份前先停止写入，再备份 `data`、`conf` 和 `aconf` 卷。

## 从源码构建

```bash
docker build -f docker/Dockerfile -t wgdashboard-guard:local .
```

镜像包含 WireGuard、AmneziaWG 工具和 Python 运行环境。构建阶段需要访问 GitHub 和 Python 包索引。

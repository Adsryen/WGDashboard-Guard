# WGDashboard-Guard

[English](README.en.md) · 中文

一个面向 WireGuard 的 Web 管理面板增强版，提供配置管理、Peer 管理、网络策略和网络审计能力。

> 本项目基于 [WGDashboard](https://github.com/donaldzou/WGDashboard) 二次开发。感谢上游项目作者 Donald Zou 及 WGDashboard 社区提供的基础能力和持续维护。

## 项目定位

WGDashboard-Guard 不是官方 WireGuard 项目，也不代表上游 WGDashboard。它在上游基础上重点增强：

- 网络策略管理与运行状态同步
- WireGuard 转发流量审计、模糊筛选和告警
- “是否属于隧道网段”和“是否命中策略允许目标”判断
- TOTP 多因素认证和可信设备会话
- 可选 HTTPS 证书加载
- 原生 systemd 和 Docker Compose 部署方式

## 快速部署

### 方式一：Ubuntu/Debian 一键安装

建议在全新的 Ubuntu/Debian 主机上执行。脚本会安装 Python、WireGuard 工具和依赖，复制当前代码到 `/opt/WGDashboard`，创建 systemd 服务，并保留已有配置和数据。

```bash
git clone https://github.com/Adsryen/WGDashboard-Guard.git
cd WGDashboard-Guard
sudo ./scripts/install.sh
```

安装完成后检查服务：

```bash
sudo systemctl status wg-dashboard
sudo journalctl -u wg-dashboard -f
```

默认端口为 `10086`，访问：`http://服务器地址:10086`。

自定义安装目录：

```bash
sudo ./scripts/install.sh --install-dir /srv/WGDashboard
```

安装脚本不会覆盖 `src/wg-dashboard.ini`、`src/db/`、`src/download/`、`src/backup/`、`src/log/` 和 `src/ssl/`。

### 方式二：Docker Compose

需要 Docker Engine 和 Docker Compose v2：

```bash
git clone https://github.com/Adsryen/WGDashboard-Guard.git
cd WGDashboard-Guard
cp docker/.env.example .env
docker compose --env-file .env -f docker/compose.yaml up -d --build
```

默认访问：`http://服务器地址:10086`。

```bash
docker compose --env-file .env -f docker/compose.yaml ps
docker compose --env-file .env -f docker/compose.yaml logs -f wgdashboard
docker compose --env-file .env -f docker/compose.yaml down
```

Docker 配置说明见 [`docker/README.md`](docker/README.md)，环境变量模板见 [`docker/.env.example`](docker/.env.example)。

## 配置与安全

- Dashboard 默认使用 HTTP；生产环境建议放在 HTTPS 反向代理后，或限制管理端口只允许 VPN/LAN 网段访问。
- `51820/udp` 是 WireGuard 端口，Dashboard 管理端口通常是 `10086/tcp`，两者不要混淆。
- 启用 TOTP 后，可以在登录页面选择“信任此设备”；可信会话时长可在 Dashboard 设置中调整。
- 不要把 `wg-dashboard.ini`、`.env`、TOTP 密钥、私钥或数据库提交到 Git。
- 使用防火墙限制管理端口时，请先确认允许了当前管理来源，避免把自己锁在服务器外。

网络审计说明见 [`docs/network-audit.md`](docs/network-audit.md)。网络策略说明见 [`docs/network-policy.md`](docs/network-policy.md)。

## 更新与备份

原生安装：

```bash
cd WGDashboard-Guard
git pull
sudo ./scripts/install.sh
```

Docker：

```bash
git pull
docker compose --env-file .env -f docker/compose.yaml up -d --build
```

升级前建议备份原生安装目录中的配置、数据库和 WireGuard 配置，或 Docker 的 `data`、`conf`、`aconf` 卷。

## 开发

后端依赖位于 [`src/requirements.txt`](src/requirements.txt)，前端代码位于 `src/static/app/`。提交前至少执行：

```bash
python3 -m unittest discover -s tests
docker compose --env-file .env -f docker/compose.yaml config
```

## 上游项目与许可证

- 上游项目：[WGDashboard](https://github.com/donaldzou/WGDashboard)
- 上游官网：[wgdashboard.dev](https://wgdashboard.dev)
- 本项目许可证：[Apache License 2.0](LICENSE)
- 安全问题请参阅：[SECURITY.md](SECURITY.md)

再次感谢上游 WGDashboard 项目及其贡献者。本仓库的 Guard 功能、审计、策略和部署增强均由本项目维护。

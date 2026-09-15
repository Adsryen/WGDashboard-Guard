# Gunicorn gthread worker 补丁

本目录保存对 gunicorn `gthread` worker 的魔改补丁（来源：上游 gunicorn 21.x
的 `gunicorn/workers/gthread.py`，经二次开发改造为"统一事件循环"，再叠加
2026-09-15 的稳定性修复）。

## 应用方法

venv 重建或 gunicorn 升级后，补丁会丢失，需要重新应用：

```bash
cp deploy/gunicorn-patch/gthread.py \
   /opt/WGDashboard/src/venv/lib/python3.10/site-packages/gunicorn/workers/gthread.py
systemctl restart wg-dashboard
```

（115 服务器上的完整魔改 venv 还包含 `workers/base.py`、
`workers/workertmp.py`、`arbiter.py` 的改动；本目录目前只存档
gthread.py 中承载请求超时修复的版本。如整体重建 venv，优先从
115 现有 venv 整体备份，再叠加本目录的修复。）

## 本目录相对上游/此前版本的关键改动

1. `handle()`：读请求前 `conn.sock.settimeout(self.cfg.timeout)`
   —— 客户端 I/O（请求行/头/body/响应）全部带上限。半开连接（公网
   NAT 转发、客户端掉线）最多卡住一个请求线程 30 秒后自动断开释放，
   不再永久卡死线程池（workers=1 threads=2 时两个半开连接即全站冻结）。
   注意：必须在 `conn.init()` 之后设置——init 内的 `setblocking(True)`
   会把超时清掉。
2. 优雅关闭循环（收到 SIGABRT/退出路径）：补 `self.notify()` 心跳，
   并将单次 select 上限设为 1s——否则 arbiter 在关闭期间判心跳 stale，
   1 秒内把 SIGABRT 升级成 SIGKILL，中断正常优雅关闭。

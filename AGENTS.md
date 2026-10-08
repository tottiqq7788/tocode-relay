# 中转服务工作约定

本目录是 Tocode 的公网中转服务，独立 git 仓库，无界面。治理不在本仓。

## 权威入口

- 治理清单：`../governance/architecture/governance.json`
- 语义地图：`../governance/architecture/traceability/semantic-map.json`
- 架构合同：`../governance/architecture/contracts/`
- 工作包：`../governance/architecture/work-packages/`
- 证据：`../governance/architecture/evidence/`

## 开发前准入

任何可能改变业务语义、权限、生命周期、数据归属、跨模块写入、Agent 上下文或持久化执行的任务，都必须声明以下结论之一：

1. 不影响 L0；
2. 修改已有 L0；
3. 新增 L0。

影响 L0 时，必须先有已批准工作包，再改代码。

## 实现协议

- 只修改任务信封与工作包声明的范围；
- 中转只保存路由和短期配对码；
- 不得保存角色提示词、模型密钥、微信凭据或完整会话档案。

## 常用命令

```text
python3 -m unittest discover -s tests
python3 ../governance/architecture/tools/audit_project.py --target ../governance
```

## 部署

2026-10-08 已部署到 `39.107.140.16`。配对流程不变。文字和不超过 20MB 的单个文件按关联转发，文件字节只在内存中经过，不写入路由文件。进程、数据和配置与 `/srv/totticom`、`/srv/zhouhuocom` 分开。

- 代码：`/srv/relay/server.py`
- 路由文件：`/srv/relay/data/routes.json`（进程写成 `0600`，只含设备和关联）
- 服务：`relay.service`，用户 `ecs-user`，监听 `127.0.0.1:8787`
- 公网：`https://totti.xin/v1/`、`wss://totti.xin/v1/ws`、`https://totti.xin/health`
- nginx：`/etc/nginx/snippets/relay.conf`，由 `/etc/nginx/conf.d/totticom.conf` 的 443 站点引入
- `/v1/ws` 关闭访问日志，避免查询串里的令牌落盘
- 不单独监听公网端口。`http://totti.xin/` 整站跳到 HTTPS

推送与重启：

```text
rsync -az server.py ecs-user@39.107.140.16:/srv/relay/server.py
ssh ecs-user@39.107.140.16 sudo systemctl restart relay.service
```

检查：`systemctl is-active relay.service`，以及 `https://totti.xin/health` 返回 `{"ok": true}`。官网首页和 `https://zhouhuo.totti.xin/` 应仍为 200。

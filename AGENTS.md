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

# 越权事件通报与处置服务

本项目提供人工智能治理协作的服务端基础能力，包含两个层面：

1. **基础协作层**：登记主体、任务、权限、场所和结构化证据，通过角色权限、请求幂等、SQLite 事务与哈希审计链保持业务状态一致。
2. **事件登记与处置层**：接收智能体访问外部系统等安全事件，按严重级别自动生成处置阶段、动作清单与通报对象，支持重复上报合并、升级、撤回误报、信息缺失先行隔离、责任人分派、结案与重开，并以持久化 outbox 保证服务重启后未完成的通报继续推进。

## 处置模型

- **严重级别**：`low` / `medium` / `high` / `critical`，级别越高阶段与通报对象越多（见 `policy.py`）。
- **生命周期状态**：`active`（信息完整，正常处置）与 `quarantined`（信息缺失先行隔离）为活跃状态；误报进入 `false_positive`，处置完成进入 `closed`；结案事件可被重开。
- **处置阶段**：分诊确认、隔离遏制、调查取证、法务/合规复核、修复处置、验证与结论（按级别裁剪）。当前阶段的阻断动作全部完成后自动进入下一阶段。
- **先行隔离**：上报缺少影响范围或证据摘要时事件不被退回，而是进入隔离状态，仅允许执行隔离遏制动作；信息补齐（含重复上报合并补齐）后自动解除隔离。
- **合并与升级**：同组织、同来源事件号（或显式 `dedup_key`）的未结案上报自动合并，取最高严重级别，合并影响范围与证据，并自动补齐新级别新增的动作与通报对象。
- **不可混淆的时间线**：每次状态变化在同一 SQLite 事务内同时写入业务版本号、事件内单调序号和全局哈希审计链；时间线条目通过审计事件哈希与全局链一一绑定。
- **通报续推**：通报记录持久化在 `incident_notifications` 中，状态为 `pending/delivered/canceled`；通道失败保留 pending 并记录尝试次数，后台派发线程在服务重启后继续推进，采用条件更新保证不重复送达。结案前所有通报必须送达。

## API

除健康检查外，请求需携带 `X-Actor-Id` 头，写操作需在 JSON 体中提供幂等的 `request_id`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/incidents` | 登记事件（可能返回新建或合并结果） |
| GET | `/incidents` | 列出本组织事件，可按 `status` 过滤 |
| GET | `/incidents/{id}` | 当前责任人、未完成动作、通报、结论与完整时间线 |
| POST | `/incidents/{id}/supplement` | 补充影响范围/证据，解除先行隔离 |
| POST | `/incidents/{id}/escalate` | 升级严重级别（reviewer/admin） |
| POST | `/incidents/{id}/withdraw` | 撤回误报（reviewer/admin） |
| POST | `/incidents/{id}/actions/complete` | 完成处置动作，自动推进阶段 |
| POST | `/incidents/{id}/owner` | 指定当前责任人 |
| POST | `/incidents/{id}/close` | 给出最终结论并结案 |
| POST | `/incidents/{id}/reopen` | 重新打开已结案事件 |
| POST | `/incident-notifications/deliver` | 手动推进一次未送达通报 |
| GET | `/incident-notifications/pending` | 查看未送达通报数量 |

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

验收脚本演练：信息缺失先行隔离 → 补充解除隔离 → 法务重复上报合并并升级 → 通报派发 → 完成全部处置动作 → 结案 → 重新打开服务后状态、时间线与审计链完整可校验。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求；后台派发线程每 5 秒推进一次未送达通报。重启后 SQLite 中的事件状态、处置动作、通报队列与审计历史继续保留。

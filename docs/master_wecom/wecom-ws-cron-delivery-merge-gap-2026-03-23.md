# `wecom_ws` cron delivery merge gap 记录（`2026-03-23`）

更新时间：`2026-03-23`

## 1. 目的

记录一次 `master_wecom` 分支上的实际 merge gap：

- `wecom_ws` 的 cron announcement delivery 在调度执行层已经支持。
- 但上游后续新增的 delivery 前置校验没有同步纳入 `wecom_ws`。
- 结果是 `cron_add` 创建阶段报错 `unsupported delivery channel: wecom_ws`。

本文只用于 `master_wecom` 分支维护，不作为上游通用文档。

## 2. 现象

在 `master_wecom` 上使用 `cron_add` 或 `add_agent_job()` 创建带 delivery 的任务时：

- `delivery.channel = "wecom_ws"` 会在创建阶段失败。
- 报错为：`unsupported delivery channel: wecom_ws`。

但同一分支的调度器执行层已经存在 `wecom_ws` 分支：

- `src/cron/scheduler.rs` 已支持把 announcement 投递到 live `wecom_ws` channel。

## 3. 时间线

### 3.1 本地能力先存在

`c743215d` `feat(channel): add wecom_ws AI bot channel`

- 该提交先把 `wecom_ws` channel 引入 `master_wecom`。
- 同时把 cron announcement delivery 接到了 `src/cron/scheduler.rs`。

### 3.2 上游后来新增了统一校验

`8bb61fe3` `fix(cron): persist delivery for api-created cron jobs (#4087)`

- 上游新增了 `validate_delivery_config()`。
- `cron_add` / `add_agent_job()` / `add_shell_job()` 在持久化前都会先走这层校验。

### 3.3 白名单后续又被上游改过一次

`48270fbb` `fix(cron): add qq to supported delivery channel whitelist (#4120)`

- 上游在 `validate_delivery_config()` 白名单里补了 `qq`。
- 但没有补 `wecom_ws`，因为 `wecom_ws` 不是上游 `master` 的公共 channel。

## 4. 根因判断

这不是“`wecom_ws` 调度执行代码被删掉了”，而是：

- 执行层保留了 `wecom_ws`。
- 创建层新增了更严格的 delivery 白名单。
- merge / sync 时没有把 `master_wecom` 私有 channel `wecom_ws` 接回新白名单。

因此本次问题应归类为：

- `master_wecom` 分支定制与上游公共层更新之间的 merge gap。

## 5. 本次修复边界

对应代码修复提交：

- `d9aec714` `fix(cron): allow wecom_ws delivery validation`

修复策略保持最小化：

- 只在 `src/cron/mod.rs` 的 `validate_delivery_config()` 中补上 `wecom_ws`。
- 增加一个 store 层回归测试，验证 agent cron job 可以接受 `wecom_ws` announcement delivery。

本次明确不做：

- 不改上游公共文档。
- 不把 `wecom_ws` 语境带进上游 issue / PR 描述。
- 不扩展其他 branch-private channel 的额外抽象。

## 6. 提交拆分要求

按 `master_wecom` 规则，本次工作应拆成两个提交：

- 代码修复提交：只包含 `src/cron/mod.rs` 和测试改动。
- `docs/master_wecom/` 文档提交：只记录本次分支维护背景与 merge gap。

准备向上游提 PR 时：

- 默认只挑选公共层代码提交。
- 不携带本文档提交。

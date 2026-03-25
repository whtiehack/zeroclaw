# `full` 模式下保留 `non_cli_excluded_tools` 的本地记录（`2026-03-23`）

更新时间：`2026-03-23`

## 1. 目的

记录 `master_wecom` 分支上的一个本地定制决策：

- 保持 `autonomy.level = "full"`，不引入 `supervised` 审批语义。
- 同时让非 CLI channel 在发给模型的工具列表里继续应用 `non_cli_excluded_tools`。
- 主要目标是减少 channel 场景下不需要工具的暴露与 token 开销。

## 2. 背景

当前 upstream 语义里，`full` 模式会在若干路径上跳过 `non_cli_excluded_tools`。

这对“完全自治”是合理的，但对 `master_wecom` 的实际使用场景不完全合适：

- 本地更关心 channel 场景的 token 成本。
- 本地希望继续使用 `full`，避免把工具可见性控制和审批语义绑在一起。
- 本地只需要让模型少看到不打算给它用的工具，不要求同步重塑所有 prompt / loop 路径语义。

## 3. 本次采用的最小方案

本次仅做最小补丁：

- 只调整 `src/channels/mod.rs` 中 channel 执行路径传给 `agent_turn()` 的 `excluded_tools` 参数。
- 行为改为：只有 `cli` 仍传空排除列表；非 CLI channel 即使在 `full` 模式下，也继续传入 `ctx.non_cli_excluded_tools`。

本次明确 **不** 做的事情：

- 不修改 `ApprovalManager` 的 `full` 语义。
- 不修改 `src/agent/loop_.rs` 里的其他 `full` 分支。
- 不新增配置项。
- 不追求“所有路径下 `full` 都完整 obey `non_cli_excluded_tools`”。

## 4. 预期效果

在当前 `channels/mod.rs` 这条消息 channel 路径里：

- `full` 模式下，非 CLI channel 发给模型的工具 specs 会继续应用 `non_cli_excluded_tools`。
- 这能减少无关工具带来的 token 消耗。
- `full` 模式的审批绕过行为保持不变。

## 5. 风险与边界

这是一个有意保持局部作用域的本地定制，因此边界需要明确：

- 该补丁不承诺覆盖所有非 CLI 入口。
- 某些 prompt 构建或其他调用路径，仍可能保留 upstream 的 `full` 语义。
- 如果后续目标从“省 token”变成“系统性隐藏工具”，需要重新评估并扩展改动范围。

## 6. 合并与回滚说明

为什么采用这个最小方案：

- 只改一处，降低 `master_wecom` 后续合并 `master` 时的冲突面。
- 不动 schema / docs / approval / agent 公共语义，方便后续单独重放或直接回退。

回滚方式：

- 恢复 `src/channels/mod.rs` 中该条件分支，让 `AutonomyLevel::Full` 再次和 `cli` 一样传入空的排除列表。

## 7. 提交边界

按 `master_wecom` 规则：

- 本文档必须单独提交。
- 不与代码改动混在同一个 commit。
- 不作为上游通用文档直接带入上游 PR。

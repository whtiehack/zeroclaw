# `master_wecom` 同步 `master` 记录（`2026-03-22`）

更新时间：`2026-03-22`

## 1. 目的

记录本次 `master_wecom` 合并 `master` 的结果，方便后续回看：

- 本次 merge commit 是哪个提交。
- 这次实际吸收了哪个 `master` 基线。
- 冲突主要落在哪些文件。
- 为了让 merge 后分支重新通过验证，额外调整了哪些测试或断言。

## 2. 同步结果

| 项目 | 值 |
| --- | --- |
| 当前工作分支 | `master_wecom` |
| 记录时间 | `2026-03-22` |
| 同步前 `master_wecom` HEAD | `83b271c9` |
| 同步前 `master_wecom` HEAD 主题 | `Merge branch 'master' into master_wecom` |
| 本次合入的 `master` HEAD | `70e7910c` |
| 本次合入的 `master` HEAD 主题 | `fix(web): remove unused import blocking release pipeline (#4234)` |
| 本次 merge commit | `be3245d8` |
| 本次 merge commit 主题 | `Merge branch 'master' into master_wecom` |
| 上次合入的 `master` 基线 | `b4a2afb0` |
| 本次新增吸收的上游提交数 | `140` |

说明：

- 本次同步把 `v0.5.3` 到 `v0.5.7` 之间的上游主线更新一起带入了 `master_wecom`。
- 合并完成后，本地 `master_wecom` 位于 `be3245d8`。

## 3. 冲突与处理

本次实际冲突文件：

- `Cargo.lock`
- `src/agent/loop_.rs`
- `src/channels/mod.rs`
- `src/cron/scheduler.rs`

处理原则：

- 保留 `master_wecom` 已存在的 `wecom_ws` 分支定制。
- 吸收 upstream 新增的公共能力，不因为本地分支定制把上游更新整块回退。
- 对 `channels` / `agent` / `cron` 只做最小冲突解，不顺手重构。

这次明确保留并吸收的点：

- `src/channels/mod.rs`
  - 保留 `wecom_ws` 的 channel delivery instructions。
  - 保留 `wecom_ws` group sender identity 注入逻辑。
  - 吸收 upstream 的 `qq` delivery instructions、memory recall 日志、reaction handle 初始化。
- `src/cron/scheduler.rs`
  - 同时保留 `wecom_ws` announcement delivery。
  - 同时吸收 upstream 新增的 `qq` announcement delivery。
- `src/agent/loop_.rs`
  - 同时保留 `TOOL_SUCCESS_LOG_OUTPUT_MAX_CHARS`。
  - 同时吸收 upstream 的 `TOOL_CHOICE_OVERRIDE` task-local。
- `Cargo.lock`
  - 合并后保留 `aardvark-sys` 与 `aes` 等依赖项，和当前 `Cargo.toml` 对齐。

## 4. Merge 后额外修正

本次 merge 完成后，第一次 `cargo test` 不是直接全绿，还补了几处收口修正：

- `src/config/schema.rs`
  - 补了 active workspace marker 相关测试的目录初始化，避免测试自身没有先创建默认目录导致 marker 没写进去。
- `src/security/policy.rs`
  - 把一条依赖当前 `HOME` 环境的测试改成固定绝对路径，避免环境变量污染造成误判。
- `src/tools/delegate.rs`
  - 更新 datetime section 断言，跟当前 prompt 里使用的 `## Current Date` 标题保持一致。
- `src/channels/mod.rs`
  - 更新 memory 注入相关测试断言，接受当前分支“用户 turn 带时间戳”的既有语义。

这些调整的目的不是引入新行为，而是让测试与 merge 后的实际代码语义重新一致。

## 5. 验证结果

本次 merge 后已执行：

- `cargo fmt --all -- --check`
- `cargo test`

结果：

- `cargo fmt --all -- --check` 通过。
- `cargo test` 通过。

## 6. 后续注意事项

- 本次同步把上游 `memory`、`tools`、`gateway`、`channels`、`hardware` 的大批更新一起带入；后续如果继续改 `wecom_ws` 相关逻辑，优先先确认公共层行为有没有已经变化。
- 这次 merge 之后，`docs/master_wecom/` 的记录应保持单独提交，不要和后续功能修复混在一起。

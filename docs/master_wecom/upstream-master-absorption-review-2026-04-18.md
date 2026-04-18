---
name: upstream-master-absorption-review-2026-04-18
description: 2026-04-18 吸收评审 — 4b3046e..upstream/master 43 条新增 commit 的分析与落地结果
type: docs/master_wecom/sync
---

# `master_wecom` 上游修复吸收评审（`2026-04-18`）

更新时间：`2026-04-18`

## 1. 基线与评审边界

| 项目 | 值 |
| --- | --- |
| 当前工作分支 | `master_wecom` |
| 对比上游分支 | `upstream/master` |
| 共同祖先 | `15616063596de025801efdfe6a4680167a5814a5` |
| 分叉计数 | `master_wecom` ahead `141`，`upstream/master` ahead `462` |
| 本轮评审窗口 | `4b3046e..upstream/master`（43 个新增 commit） |
| 上次吸收评审 | [`upstream-master-absorption-review-2026-04-13.md`](./upstream-master-absorption-review-2026-04-13.md) 已全部落地 |

### 结构性前提（最关键）

- 上游在 `15616063` 之后完成 **workspace 拆分**：单 crate `src/...` → 15 个 `crates/zeroclaw-*/src/...`
- `master_wecom` 至今仍是单 crate 布局
- 因此本批所有 commit 的路径都错位，**全部不能 cherry-pick**，必须手工 port
- 同时上游做过 `channels_config → channels` 字段重命名，本地仍是 `config.channels_config.*`

### 硬约束

- 不冲 `wecom_ws` 本地语义（req_id 分桶、sender/timestamp 注入、draft 体感、`channel_delivery_instructions`）
- 公共层改动最小化、分开提交、一条修复一个 commit
- 本地磁盘 8G，不够 `cargo test`，所有编译/测试都去 wecom 服务器

## 2. 部署偏好约束（影响本轮判定）

- **只用 native tool calling 的 LLM**：MiniMax / MoonShot / 某些 prompt-guided 模型相关的修复**对我们永远 no-op**
- **不用 MQTT**：`rumqttc` 本地 Cargo.toml / Cargo.lock 均无；`src/channels/mqtt.rs` 文件存在但未在 `mod.rs` 声明（死文件）
- **不用 OTLP 当前运行态**，但保留 `otel_headers` 配置面以备将来
- **全权限跑在 docker 里**：shell policy 已通过 feat #19 `disable_shell_policy` 绕过

## 3. 43 条 commit 的落地判定

### 已吸收（6 条）

| 顺序 | 上游 commit | 本地 commit | 主题 |
|---|---|---|---|
| 1 | `1da35dbc` #5806 | `b9ab3f52` | Z.AI tool_stream 门控 |
| 2 | `9f0de18b` #5746 | `3a78deb2` | TurnEvent::ToolCall 去重 |
| 3 | `fbb5ae9a` #5565 | `3cd61f2c` | 空 tool output 归一化 |
| 4 | `fe3ec584` #5799 | `b0d978cc` | daemon/onboard webhook 纳入 |
| 5 | `a916dd10` | `2ba68f04` | cron_run 手工触发补 delivery |
| 6 | `325835e8` #5700 | `09780acf` | otel_headers 配置 |

每条 commit body 都带 `Ports upstream <sha>` + `Co-authored-by:` trailer。

### 待 wecom 服务器执行（1 条，lockfile-only）

- `1f24cbd1` #5786 — RUSTSEC-2026-0098/0099（rustls-webpki URI name constraint bypass）
  - 本地 `rustls-webpki 0.103.10` 被 `reqwest / lettre / tokio-tungstenite → rustls` 传递拉入
  - 影响所有 LLM HTTPS 调用、`wecom_ws` WebSocket TLS 握手、邮件
  - 上游 patch 主体（rumqttc 0.24→0.25、audit.toml 0.102.x ignore）**对我们无关**
  - 只需 lockfile 一条命令：`cargo update -p rustls-webpki --precise 0.103.12`

### 明确跳过（6 条，各有不同原因）

| commit | 主题 | 跳过理由 |
|---|---|---|
| `1077e4d1` #5802 | CLI channel factory | 修上游 OnceLock 重构遗留，本地无 OnceLock 工厂 |
| `bf5873c0` #5729 | Arc<Provider> 转发 | 修上游 blanket impl，本地无 blanket `impl<T> Provider for Arc<T>` |
| `9753bc77` | observability-prometheus 级联 | 修 workspace 子 crate feature 转发，本地单 crate |
| `9ca90b1b` #5762 | strip_native_tool_messages | 仅在 `native_tool_calling=false` 生效；我们只用 native tool provider，永远 no-op |
| `054c867d` #5717 | OpenRouter 流式 | 未使用 OpenRouter |
| `9d6308e0` / `25115c80` | Claude Code skills | 文档/skill，非代码 |

### 明确跳过（上游专有通道，本地不相关）

- `ca9d9cea` #5790 — Telegram inline_keyboard 审批（`wecom_ws` 无此机制）
- `34dc66c9` #5166 — Matrix mention_only + 媒体
- `b2b8d960` #5727 — Matrix 加密媒体下载
- `017a91c8` — LINE setup docs

### 明确跳过（安全策略重叠）

- `9edbfbfe` #5702 — 拦截 python/node/npm/pip/cargo 危险参数
- `90528782` #5160 — 放行 heredoc + 安全重定向
  - 本地 feat #19 `disable_shell_policy` 整体绕过 shell policy，这两条对我们是"死代码改死代码"

### 明确跳过（重量级重构，回滚收益远小于风险）

- `1ec9c14c` #5167 — session integrity / streaming refactor / history pruning
  - DraftEvent → StreamDelta 重构，影响 1285 行
  - 与本地 feat #10 / #22 / #26 / #29 的 draft / reasoning / SSE 链路正面冲突
  - 本地已有等价 orphan 保护（2026-04-15 确认）
  - MultiMessage 首字符截断等孤立 bug 如需解决，**单拆 cherry**

### 其余 CI/docs/web/workflow 琐碎 commit

- `30395e90 04074790 84b50794 223914b5 93289463 d0d83198 64a813b5 237b6367 f960f8df 1f24cbd1`(除 RUSTSEC 部分)`160a1c50 4259f27c 1b4315ad b2716679 c86a16c7 cf12d7ea 341423ff 00c94e2c 3f565161 caf24127`
- 均无 `wecom_ws` 相关价值

## 4. trait / 公共接口变动

### 直接 trait 签名变化（本地无 blanket impl，无需同步）

- `crates/zeroclaw-api/src/channel.rs` 新增 `Channel::request_approval` 默认实现
- `crates/zeroclaw-api/src/provider.rs` 的 `impl<T: Provider + ?Sized> Provider for Arc<T>` 补齐 `supports_native_tools` / `supports_vision`

本地只有测试里的 per-mock `impl Provider for Arc<MockProvider>`，无 blanket。若将来引入 blanket，记得同时实现这两个方法。

### 隐性契约变化

- 非 native tool provider 现在期望 request pre-send 清除 tool-role 消息（`9ca90b1b`），我们不用这类 provider，无影响。
- `channels()` 与 `channels_except_webhook()` 语义差异：前者包含 webhook，`has_supervised_channels / has_launchable_channels` 本批改为 `channels()`，与"webhook 是否算一个可监管 channel"的上游新规对齐。

## 5. 对 `wecom_ws` 的影响

### 兼容性

- 零硬破坏。6 条已落地 commit 都是通用层 bug 修复或向下兼容的配置面扩展。

### 语义

- `cron_run` 手工触发现在会补 delivery：当 agent 在 wecom_ws 会话里调 `cron_run` 触发一个 `delivery.channel = wecom_ws` 的 job，用户先收到 announce，再收到 agent 的 LLM 结尾文本。这是**与定时触发一致性**，不是 bug，但要提醒运维。

### merge 热点

- `src/agent/loop_.rs` / `src/agent/history.rs` / `src/agent/history_pruner.rs`：上游 #5167 重写，本地保持不动（跳过）。日后若需上游那边 bugfix，**单拆 patch**。

## 6. 回归检查清单（wecom 服务器）

### 编译

按 [`../../zeroclaw.md`](../../../zeroclaw.md) 文档里的 flags 编译，不要直接 `cargo build --release`。

### 必跑测试

```bash
cargo test conversation_history_key_wecom_ws_ignores_req_id_thread_ts
cargo test process_channel_message_restores_wecom_ws_history_across_req_ids
cargo test parse_runtime_command_allows_new_session_and_models_for_wecom_ws
cargo test wecom_ws --lib
cargo test non_zai_provider_omits_tool_stream
cargo test webhook_only_config
```

### 常规

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

### 手工

- 群聊不同 `req_id` 消息落同一历史桶
- `wecom_ws` draft `<think>` 不泄露
- tool progress 在 draft 里可见
- `/new`、`/models`、`/model` 可用
- `interrupt_on_new_message` 体感不变
- 在 wecom_ws 会话里触发一个 announce 配置的 cron_run，验证不掉 delivery

## 7. wecom 服务器执行序列

```bash
# 1. 拉取 6 条 commit
cd ~/path/to/zeroclaw  # wecom 服务器上的仓库路径
git checkout master_wecom
git pull

# 2. 打 rustls-webpki 安全补丁
cargo update -p rustls-webpki --precise 0.103.12

# 3. 提交 lockfile 改动（本地层 commit，单独一条）
git add Cargo.lock
git commit -m "deps: bump rustls-webpki to 0.103.12 for RUSTSEC-2026-0098/0099

URI name constraint bypass — affects every HTTPS client in the tree
(LLM providers via reqwest, wecom_ws WebSocket via tokio-tungstenite,
email via lettre). Lockfile-only bump; no Cargo.toml change.

Related upstream: 1f24cbd1 (zeroclaw-labs/zeroclaw#5786) — we skip the
rumqttc bump and audit.toml edits since master_wecom has no MQTT.
"
git push

# 4. 按 zeroclaw.md 文档编译
#   （具体 flags 以 zeroclaw.md 为准，不要直接 cargo build --release）

# 5. 跑回归测试（见第 6 节清单）

# 6. 部署到 wecom-test / wecom-dev
#   （参考 zeroclaw-wecom.md）
```

临时切分支编译完记得切回 master_wecom（见 `feedback_wecom_restore_branch.md`）。

## 8. 结语

- 本批 43 条里真正对 `master_wecom` 有价值的是 7 条（6 代码 + 1 lockfile）
- 大头 `1ec9c14c` session 重构 pending，日后若 MultiMessage 截断等具体 bug 出现，再按上游对应 sub-commit 单拆
- 下次评审窗口：`<下次起点 sha>..upstream/master`，起点取本轮最新上游头 `30395e90`

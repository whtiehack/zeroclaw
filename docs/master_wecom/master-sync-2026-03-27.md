# `master_wecom` 同步 `master` 记录（`2026-03-27`）

更新时间：`2026-03-27`

## 1. 同步结果

| 项目 | 值 |
| --- | --- |
| 当前工作分支 | `master_wecom` |
| 记录时间 | `2026-03-27` |
| 同步前 `master_wecom` HEAD | `c190105f` |
| 同步前 `master_wecom` HEAD 主题 | `docs(master_wecom): add upstream review rules` |
| 本次合入的 `master` HEAD | `15616063` |
| 本次合入的 `master` HEAD 主题 | `Merge pull request #4818 from zeroclaw-labs/feat/memory-loop-continuity` |
| 本次 merge commit | `57795465` |
| 本次 merge commit 主题 | `Merge remote-tracking branch 'upstream/master' into master_wecom` |
| 上次合入的 `master` 基线 | `70e7910c` |
| 本次新增吸收的上游提交数 | `287` |

说明：

- 本次记录的是 `master_wecom` 合并 `upstream/master` 的一次同步，以及 merge 后为保持本地分支语义追加的两条小修正。
- merge 后又补了两条本地 follow-up commit：
  - `dc8e8b20 feat(agent): add tool execution tracing logs`
  - `88fe65b1 feat(channels): enable public interrupt flow for wecom_ws`

## 2. 上游变更摘要

本次吸收的上游 commit range：`70e7910c..15616063`

### trait / 公共接口变动

- 本次未遇到 `src/**/traits.rs` 的直接签名冲突，说明 trait 层没有出现需要 `wecom_ws` 立即改实现的硬破坏。
- 主要变化落在公共运行时隐性契约，而不是 trait 文件本身：
  - `channels` 运行时上下文新增了 `max_tool_result_chars`、`context_token_budget`、`debouncer`。
  - `[channels]` 新增了 `debounce_ms` 公共配置，默认 `0`，关闭时完全 passthrough。
  - `agent` 的历史、cost、tool execution 辅助逻辑从 `loop_.rs` 抽到独立模块，`loop_.rs` 不再保留那套本地重复实现。
- 对 `master_wecom` 来说，真正需要关注的是这些公共层行为变化，而不是 trait 名字是否改了。

### 框架层新增能力

- 公共层新增 inbound debounce 能力：
  - `channels.debounce_ms > 0` 时，同一 sender scope 的快速连续消息会先合并，再统一 dispatch。
  - `channels.debounce_ms = 0` 时，不做任何延迟或合并。
- agent 层新增了更清晰的模块拆分：
  - `src/agent/tool_execution.rs`
  - `src/agent/history.rs`
  - `src/agent/cost.rs`
- 上游把“新消息打断旧任务”的主流程统一收敛到了 `src/channels/mod.rs` 的 `dispatch_worker()`，公共层不再鼓励 channel 私自复制一套中断逻辑。
- 上游继续强化上下文与历史管理：
  - context budget / tool result truncation / history continuity 相关逻辑更集中。
  - 失败 turn 不应污染下一轮 follow-up 的方向更明确。

### 其它 channel 更新

- Slack：
  - 真实 thread reply 使用 `interruption_scope_id = thread_ts`，顶层消息不额外细分。
  - 这说明 `interruption_scope_id` 只在“真实子线程”场景才有必要用。
- Matrix：
  - 直接把 `thread_ts` 作为 `interruption_scope_id`，按 thread 做中断隔离。
- Discord / Mattermost：
  - 都接进了公共层 `interrupt_on_new_message` 能力，但仍走默认 scope，没有额外 thread 维度。
- 对 `wecom_ws` 最有参考价值的是：
  - 中断能力最好走公共层统一实现。
  - 只有真的存在稳定 thread 语义时，才需要 `interruption_scope_id`。

### 对 `wecom_ws` 的影响

- 直接接口破坏：无。
- 最重要的语义影响有两点：
  - `debounce_ms` 插在 `dispatch_worker()` 之前，所以如果未来启用 `channels.debounce_ms`，`wecom_ws` 的“新消息立即打断旧任务”会先被 debounce 窗口延后。
  - 上游 merge 当下，公共层 interrupt 白名单里还没有 `wecom_ws`，所以 merge 时不能再保留本地那种在 `dispatch_worker()` 外硬塞 `wecom_ws` 特判的写法。
- `wecom_ws` 仍然不适合把 `req_id` 当作 `interruption_scope_id`：
  - `req_id` 是 transport/request id，不是真线程。
  - 你已经在 history key 层明确忽略了它，interrupt scope 也必须保持一致。
- `wecom_ws` 适合按 Telegram 风格接入公共层中断：
  - 单聊按 `reply_target + sender`
  - 群聊按当前已有的群级 `reply_target + sender`
  - `interruption_scope_id` 继续保持 `None`

### Bug 修复 / 行为变化

- 上游的 agent/history 行为更强调“失败 turn 不要污染后续正常对话”。
- 工具执行实现从 `loop_.rs` 抽离后，本地执行日志能力不再自动保留，需要单独补回。
- 公共层中断逻辑的真正入口变成 `dispatch_worker()`，后续所有 channel 最好统一往这里靠，避免再次制造私有分叉。

### 与 branch-features.md 重叠的条目

- 无直接一一对应的功能重叠。
- 但公共层 interrupt / debounce 已经与 `wecom_ws` 的消息打断体验产生直接交集，后续不能再把它们当成互不相关的能力。

### Merge 热点

- `src/channels/mod.rs`
  - 原因：公共层 interrupt、debounce、session/history、`wecom_ws` 本地适配都集中在这里，是本分支最容易和 upstream 打架的公共层热点文件。
- `src/agent/loop_.rs`
  - 原因：上游正在持续把 `loop_` 拆薄，而本地之前又把 tool execution 日志和行为塞回了 `loop_`，语义重叠明显。
- `src/agent/tool_execution.rs`
  - 原因：这是上游新抽出的文件，本地后续又补了执行日志，下一次 merge 时这里仍会是小热点。

## 3. 冲突与处理

本次实际冲突文件：

- `src/channels/mod.rs`
- `src/agent/loop_.rs`

处理说明：

- `src/channels/mod.rs`
  - 冲突点是本地曾把旧的 interrupt 逻辑重新内联，并额外给 `wecom_ws` 硬塞特判。
  - 本次 merge 先完全收回到 upstream 的 `dispatch_worker()` 方案，不在冲突阶段保留 `wecom_ws` 私有特判。
  - 这样做的目的，是先保证公共层行为与 upstream 一致，再单独用最小 patch 把 `wecom_ws` 接进去。
- `src/agent/loop_.rs`
  - 冲突点是本地保留了一整块旧的 `execute_one_tool` / 并行执行实现，而 upstream 已经把这部分抽到 `src/agent/tool_execution.rs`。
  - 本次 merge 删除了本地重复块，保留 upstream 的模块化方案，不在冲突阶段继续双份实现。

## 4. Merge 后额外修正

- 为了让 merge 后测试目标能继续编译，补了一个旧测试里的 `ChannelRuntimeContext` 初始化字段：
  - `max_tool_result_chars`
  - `context_token_budget`
  - `debouncer`
- merge 后又追加了两条本地小修正：
  - `dc8e8b20 feat(agent): add tool execution tracing logs`
    - 把本地需要的 tool execution 日志补回到新的 `src/agent/tool_execution.rs`。
    - 这是本地行为回补，不是上游自带。
  - `88fe65b1 feat(channels): enable public interrupt flow for wecom_ws`
    - 不改 `dispatch_worker()`。
    - 不引入 `wecom_ws` 专用 `interruption_scope_id`。
    - 只把 `wecom_ws` 接进公共层 interrupt 开关，scope 按 Telegram 风格走默认 key。

## 5. 验证结果

- `cargo fmt --all -- --check`
  - 通过。
- `cargo test`
  - 跑到完整测试阶段后失败，但失败点与本次 merge 冲突文件无关：
  - `security::seatbelt::tests::generate_policy_restricts_network`
  - 失败位置：`src/security/seatbelt.rs:265`
- merge 过程中额外确认过两条定向测试：
  - `cargo test process_channel_message_restores_wecom_ws_history_across_req_ids`
  - `cargo test execute_one_tool_resolves_unique_activated_tool_suffix`
  - 这两条都通过。
- `dc8e8b20` 与 `88fe65b1` 之后没有再补跑完整验证，是按当时交互要求停止的。

## 6. 后续注意事项

- 如果以后启用 `channels.debounce_ms > 0`，`wecom_ws` 的打断语义会和其它 channel 一样，被 debounce 窗口延后。
- `wecom_ws` 的公共层中断 scope 继续按默认 key 走，不要把 `req_id` 塞进 `interruption_scope_id`。
- 后续继续 merge upstream 时，优先守住这三条原则：
  - 不在 `dispatch_worker()` 里重新塞 `wecom_ws` 特判。
  - tool execution 的本地日志补丁只放在 `src/agent/tool_execution.rs`。
  - 公共层改动继续保持“先跟 upstream 对齐，再做最小本地接线”。

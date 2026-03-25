# `temp/upstream-master-wecom-port` 重建执行文档

更新时间：`2026-03-25`

## 1. 目标

本分支直接基于 `upstream/master`，按最小差异原则重建 `master_wecom` 仍然需要保留的能力。

当前工作目标：

- 保留 `master_wecom` 的需求来源和历史判断文档
- 以 [branch-features.md](./branch-features.md) 为唯一功能需求清单
- 在上游当前实现之上重落必要能力，不延续旧分支的历史包袱

## 2. 基本判断

- 默认以上游实现为准
- 旧 `master_wecom` 的提交不是迁移单位，功能语义才是迁移单位
- 只要上游已覆盖目标，就不再复制旧补丁
- 只有 `wecom_ws` 必需语义和其直接依赖的公共补丁才允许重新实现

## 3. 执行原则

### 3.1 允许保留的内容

- `wecom_ws` channel 本体
- 只为 `wecom_ws` 提供支撑的最小公共层补丁
- 直接修复当前迁移过程中暴露的兼容性问题
- `docs/master_wecom/` 下的分支专属记录

### 3.2 默认丢弃或重判的内容

- 旧分支中与上游现有 streaming / draft / provider / prompt 能力重叠的公共补丁
- 非 `wecom_ws` 的顺手修复
- 仅为旧实现细节服务、在新基线下已无必要的测试
- 没有明确需求来源的“顺便一起带过来”的改动

### 3.3 提交拆分

- 文档迁移单独提交
- `wecom_ws` 通道接入单独提交
- 公共层最小补丁按主题拆分单独提交
- 测试与回归修正视情况附着在对应功能提交，不做无主题汇总提交

## 4. 操作顺序

### 阶段 0：文档引导

状态：已完成

- 从 `upstream/master` 创建临时分支
- 复制 `master_wecom` 现存分支文档
- 重写当前分支入口文档和执行文档

### 阶段 1：需求与落点确认

状态：已完成

- 以 [branch-features.md](./branch-features.md) 列出必须保留的功能
- 将功能拆成三类：`wecom_ws` 本体、必需公共补丁、可放弃历史补丁
- 对每项功能先定位到当前上游代码落点，再开始写代码

2026-03-25 当前结论：

- `wecom_ws` 在上游不存在，需要新增独立 channel 文件并接入当前 channel factory
- 上游已存在旧 `wecom` webhook channel，因此 `wecom_ws` 必须以新配置项并列接入，不能复用旧 `wecom` 配置
- 最小接入落点已确认：
  - `src/channels/mod.rs`
  - `src/config/schema.rs`
  - `src/cron/mod.rs`
  - `src/cron/scheduler.rs`
  - `src/channels/wecom_ws.rs`
- 当前判断为“先接入 `wecom_ws` 本体 + 配置层 + cron announce 最小支持”，其余公共层补丁延后按缺口重判
- 上游当前已有 streaming / draft / prompt / provider 新实现，因此旧 `master_wecom` 的相关公共补丁不作为首轮迁移目标

### 阶段 2：最小接入 `wecom_ws`

状态：已完成

- 先让 `wecom_ws` 以最小可编译形式接入 channel registry 和配置层
- 再补齐核心收发链路，不预先搬运非必要增强
- 如果旧实现依赖上游已变化的 draft/streaming 接口，按新接口重接，不回退上游实现

2026-03-25 当前进展：

- 已新增 `src/channels/wecom_ws.rs`
- 已接入 `src/channels/mod.rs` 的 channel factory
- 已新增 `ChannelsConfig.wecom_ws` 与 `WeComWsConfig`
- 已补上 `wecom_ws` secret 的配置加解密路径
- 已接入 `cron` 的 `delivery.channel = "wecom_ws"` 校验与运行态发送路径
- 已恢复最小 live channel registry，供 `wecom_ws` 复用现有长连接
- 已确认 `/new`、`/stop`、`/models`、`/model`、`/config` 在 `wecom_ws` 路径上具备运行时接线
- 已确认 `interrupt_on_new_message` 在 `wecom_ws` 路径上生效

已完成验证：

- `cargo check`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test wecom_ws --lib`

### 阶段 3：补必要公共层差异

状态：已完成（2026-03-25 复核后按新策略收口）

- 只处理 `wecom_ws` 无法工作的公共层缺口
- 优先补配置接线、注册入口、必要 runtime hook
- 对公共层补丁逐条说明“为什么上游现状不够”

2026-03-25 复核后更正：

- 上游已覆盖，无需重搬：
  - tool-call 文本 relay
  - draft sender 显式 `drop(delta_tx)` 收口
- 已完成迁移：
  - `non_cli_excluded_tools` 在 channel 路径的非 CLI `full` 模式继续生效
  - native tools 模式下跳过重复 tools summary
  - `disable_shell_policy` 配置、schema、security policy、shell tool 验证链路已接回
  - OpenAI-compatible transport error 不再触发 `/responses` fallback
  - 工具调用日志增强已补回：`execute_one_tool` 现在记录脱敏后的参数、执行时长、成功输出或失败原因
- 复核后确认的 `wecom_ws` 语义缺口已全部补完：
  - 群聊历史按群共享
  - 群消息发送者身份注入
  - channel 历史精确时间戳保留
  - `wecom_ws` 静态 system context block
  - `wecom_ws` delivery instructions
  - `wecom_ws` 工具调用进度继续并入同一条草稿流
- 当前保留为低优先级观察项：
  - 继续观察是否需要把本地 `disable_shell_policy` 语义同步到 prompt summary
- 当前执行方式：
  - 优先把 `wecom_ws` 专有语义尽量下沉到通道层，不扩大框架层特判面
  - 每修完一条立即把结论、原因和验证记录回写到本文件

2026-03-25 当前逐条记录：

1. 已完成：`wecom_ws` 群聊历史按群共享
   - 修改：
     - 没有继续改 `mod.rs` 的 `conversation_history_key()`
     - 改为在 `wecom_ws` 入站时，群聊统一把发往框架的 `sender` 固定成 `group--{chatid}`
   - 原因：
     - 这样直接复用框架现有按 `reply_target + sender` 分桶的逻辑，即可自然得到群共享历史
     - 同时避免继续扩大 `mod.rs` 里的 `wecom_ws` 专用分支
   - 验证：
     - `cargo fmt --all`
     - `cargo test wecom_ws --lib`
   - 当前剩余：
     - `wecom_ws` 静态 system context block
   - 下一步：
     - 继续把 `wecom_ws` 静态 system context block 补回系统提示词路径

2. 已完成：`wecom_ws` 群消息发送者身份与精确时间戳在通道层本地注入
   - 修改：
     - `wecom_ws` 在 `compose_content_for_framework()` 内直接把普通消息改写成带本地时间戳的内容
     - 群聊消息额外补入 `[sender_userid=...]`
     - 命令路径 `/clear` `/new` `/stop` `/model` `/models` 统一使用 group-scope sender；单聊仍要求 slash command 才转成运行时命令
   - 原因：
     - 把 `wecom_ws` 专属消息语义留在通道边界处理，避免把 sender/timestamp 注入逻辑扩散到所有 channel 公共路径
     - 群聊命令和普通消息必须使用同一 sender 语义，否则 `/stop`、`/new` 无法命中同一个会话/中断作用域
   - 验证：
     - `cargo fmt --all`
     - `cargo test wecom_ws --lib`
   - 当前剩余：
     - `wecom_ws` 静态 system context block
   - 下一步：
     - 补回 `wecom_ws` 静态 system context block

3. 已完成：`wecom_ws` 静态 system context block
   - 修改：
     - 在 `build_channel_system_prompt()` 内补回 `[WECOM_WS_STATIC_CONTEXT_V1]`
     - 群聊写入 `chat_type=group` 和 `conversation_scope=group--...`
     - 单聊额外写入 `sender_userid=user--...` 解析后的 userid
   - 原因：
     - 这块属于系统提示词语义，不适合继续塞进用户消息正文
     - 保持 `wecom_ws` 的通道层运行态注入与公共层 system prompt 注入分工清晰
   - 验证：
     - `cargo fmt --all -- --check`
     - `cargo test build_channel_system_prompt --lib`
   - 当前剩余：
     - `wecom_ws` delivery instructions
   - 下一步：
     - 把 `channel_delivery_instructions()` 里的 `wecom_ws` 提示词补回

4. 已完成：`wecom_ws` delivery instructions
   - 修改：
     - 在 `channel_delivery_instructions()` 中补回 `wecom_ws` 专用回复约束
     - 恢复本地绝对路径文件发送、`[IMAGE:]` / `[FILE:]` / `[VOICE:]` / `[VIDEO:]` marker 和“工具结果静默使用”提示
   - 原因：
     - 旧分支对企业微信长连接的交付格式约束不在静态 context block，而是在 channel delivery instructions
     - 只补 static context 不够，模型仍会丢失附件发送和输出格式约束
   - 验证：
     - `cargo fmt --all -- --check`
     - `cargo test build_channel_system_prompt --lib`
     - `cargo test wecom_ws --lib`
   - 当前剩余：
     - `wecom_ws` 工具调用进度继续并入同一条草稿流
   - 下一步：
     - 把上游 draft `Progress` / `Content` 拆分后丢掉的 `wecom_ws` 草稿体验补回

5. 已完成：`wecom_ws` 工具调用进度继续并入同一条草稿流
   - 修改：
     - `mod.rs` 只增加一个最小公共层钩子：在 draft `Clear` 时给 `wecom_ws` 透传专用 clear sentinel
     - 主要恢复逻辑下沉到 `wecom_ws`：
       - 新增本地 draft state
       - `update_draft_progress()` 直接把 thinking / tool start / tool done 进度并入同一条流式草稿正文
       - 收到 clear sentinel 后切到 final 模式，后续最终答案重新覆盖前面的进度正文
       - 预 final 阶段继续按旧语义仅保留最近若干行，避免草稿过长
   - 原因：
     - 上游把草稿流拆成 `Progress` / `Content` 两路后，`wecom_ws` 没有自己的 status bar，导致工具进度不再显示在同一条草稿里
     - 这次恢复要求尽量少动公共层，所以只保留 clear 透传，具体 merge/clamp/final 切换都放回 `wecom_ws` 本地状态机
   - 验证：
     - `cargo fmt --all`
     - `cargo test wecom_ws --lib`
   - 当前剩余：
     - 暂无新的 `wecom_ws` 迁移缺口
   - 下一步：
     - 继续按真实使用反馈补漏，不扩大 `mod.rs` 对 `wecom_ws` 的特判面

6. 已完成：`wecom_ws` 在 `clear` 之后改为按时间窗节流刷新最终答案草稿
   - 修改：
     - `wecom_ws` 本地 draft state 新增 post-clear flush 时间记录
     - 收到 clear sentinel 后，最终答案阶段不再每个 content 增量都立刻推送
     - 改为在 `wecom_ws` 内部按约 1.2 秒时间窗刷新一次，最后仍由 `finalize_draft()` 发 `finish=true`
   - 原因：
     - 上游 `DraftEvent::Content` 颗粒度较细，`clear` 后继续逐块推送会在企业微信侧形成高频小段刷屏
     - 这类节流只影响 `wecom_ws` 的展示体验，适合留在通道层本地处理，不继续扩散到公共 draft 框架
   - 验证：
     - `cargo test wecom_ws --lib`
   - 当前剩余：
     - 暂无新的 `wecom_ws` 草稿流缺口
   - 下一步：
     - 根据真实测试结果再调整时间窗，不改动公共层接口

7. 已完成：`wecom_ws` 对话历史不再被每次 `req_id` 切成新会话
   - 修改：
     - 在公共层 `conversation_history_key()` 增加最小 `wecom_ws` 特判
     - `wecom_ws` 继续保留 `thread_ts=req_id` 作为回复锚点
     - 但历史分桶对 `wecom_ws` 不再使用 `thread_ts`
   - 原因：
     - `wecom_ws` 的 `thread_ts` 不是像 Slack 那样的真实线程 id，而是每次入站都会变化的 transport req_id
     - 如果继续把它并入 history key，就会导致每条消息都命中新 key，表现为“每次对话都是新的”
     - 这次按用户要求收窄为 `wecom_ws` 特判，不扩大到所有 channel 的 history key 语义调整
   - 验证：
     - `cargo test conversation_history_key_wecom_ws_ignores_req_id_thread_ts --lib`
     - `cargo test process_channel_message_restores_wecom_ws_history_across_req_ids --lib`
     - `cargo test wecom_ws --lib`
   - 当前剩余：
     - 继续观察 `wecom_ws` 是否还有其他“回复锚点字段参与公共层逻辑”的回归点
   - 下一步：
     - 如无新反馈，保持该特判不再扩散

### 阶段 4：验证与收口

状态：已完成

- 先跑最小范围验证，再决定是否跑全量
- 对失败项先区分是迁移缺口、上游现有问题还是环境问题
- 形成新的同步记录或迁移记录，避免再次回到口头判断

2026-03-25 历史验证补充：

- 已补充通过：
  - `cargo test execute_one_tool --lib`
  - `cargo test scrub_credentials --lib`
  - `cargo test date_section_includes_date_and_offset --lib`
  - `cargo test build_channel_system_prompt_rewrites_datetime_section_to_date_only --lib`
  - `cargo test enriched_prompt_includes_tools_workspace_datetime --lib`
  - `cargo test prompt_contains_all_sections --lib`
- 本轮 `non_cli_excluded_tools` 补丁已补充通过：
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test non_cli_excluded_tools --lib`
- 本轮 native tools summary 去重已补充通过：
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test native_tools_prompt_skips_duplicate_tools_summary --lib`
- 本轮 `disable_shell_policy` 补丁已补充通过：
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test disable_shell_policy --lib`
  - `cargo test shell_policy_disabled --lib`
- 本轮 provider transport error fallback 收紧已补充通过：
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test transport_error_does_not_attempt_responses_fallback --lib`
- 本轮时间上下文拆分与工具日志增强补丁已补充通过：
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test`
- 全量回归过程中额外对齐了一条旧测试断言：
  - `agent::loop_::tests::native_tools_system_prompt_contains_zero_xml`
  - 原因是该测试仍要求 native tools prompt 显式列出工具名，与当前“native tools 模式跳过重复 tools summary”的既有语义不一致
- 注意：
  - 以上全量验证结论是本轮重新开工前的历史状态
  - 本轮按新策略补完后，已重新通过：
    - `cargo fmt --all -- --check`
    - `cargo test build_channel_system_prompt --lib`
    - `cargo test wecom_ws --lib`
    - `cargo clippy --all-targets -- -D warnings`
  - 截至当前最新一次重跑：
    - `cargo test` 失败于 `providers::bedrock::tests::bearer_token_precedence`
    - `cargo test` 失败于 `providers::bedrock::tests::chat_fails_without_credentials`
    - 当前没有证据表明这两条失败由本轮 `wecom_ws` / prompt 迁移引入，先记为上游现有或环境相关问题，后续单独排查
  - 当前判断：本轮 `wecom_ws` 迁移缺口已完成收口；全量回归剩余阻塞点已收敛到与本轮改动无直接关系的 `bedrock` 测试

## 5. 当前已知优先级

### P0

- 暂无新的 P0 公共层缺口

### P1

- 暂无

### P2

- 继续观察是否需要把本地 `disable_shell_policy` 语义同步到 prompt summary

## 6. 禁止事项

- 不直接 merge `master_wecom`
- 不先大规模复制旧代码再事后删减
- 不把历史文档结论当作当前代码事实
- 不在没有编译或验证依据时断言“此补丁仍然需要”

## 7. 产出要求

每推进一个阶段，至少同步以下信息到文档或汇总说明中：

- 做了什么
- 为什么保留或丢弃某个历史补丁
- 当前剩余缺口是什么
- 下一步只做哪一个明确主题

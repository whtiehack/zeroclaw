# `master_wecom` 功能清单

更新时间：`2026-04-17`（2nd）

维护规则：

- 新增功能时同步更新本清单，并在 `docs/master_wecom/` 下新建对应文档后链接
- 合并上游时，如上游新增了类似功能，对比分析后报告用户再决定
- 功能被上游覆盖并决定移除时，从清单中删除并记录原因

---

## wecom_ws 通道

| # | 功能 | 说明 | 文档 |
|---|------|------|------|
| 1 | WebSocket 长连接 | bot_id + secret 接入，订阅、心跳保活、断线退避重连 | - |
| 2 | 权限控制 | allowed_users / allowed_groups 白名单 | - |
| 3 | 入站多模态 | 文本、语音转写、图片、文件、图文混合、引用消息 | - |
| 4 | 出站流式草稿 | 处理中草稿 → clear 哨兵 → 正文累积 → 收口，长文本自动切块 | - |
| 5 | 出站附件标记 | `[IMAGE:]` `[FILE:]` `[VOICE:]` `[VIDEO:]` 自动上传发送 | - |
| 6 | 会话控制命令 | /new、/stop、/models 等运行时命令 | - |
| 7 | interrupt_on_new_message | 新消息中断旧生成，保留上下文 | - |
| 8 | 流式过期兜底 | 草稿过期停刷、收口过期退回普通消息 | - |
| 9 | 心跳 ACK 静默 | 心跳响应不打日志噪音 | - |
| 10 | 正文流式回复 | 工具执行完后正文也逐步流式推送，基于 content reset 检测 | [详细文档](./stream-final-answer-2026-03-29.md) |
| 11 | draft 限流 | `draft_update_interval_ms` 控制 WS 帧发送频率，默认 300ms | [详细文档](./stream-final-answer-2026-03-29.md) |

## 通用层改动

合并上游时冲突风险较高，需重点关注。

| # | 功能 | 说明 | 文档 |
|---|------|------|------|
| 12 | cron 投递 wecom_ws | `delivery.channel = "wecom_ws"` 接入校验和持久化 | [merge gap 记录](./wecom-ws-cron-delivery-merge-gap-2026-03-23.md) |
| 13 | tool-call 文本 relay | 工具调用前后解释文本实时推送到草稿 | - |
| 14 | draft sender 显式关闭 | tool loop 结束后 drop(delta_tx) 再 await | - |
| 15 | non_cli_excluded_tools in full | 非 CLI 通道在 full 模式下仍排除指定工具 | [决策记录](./full-non-cli-excluded-tools-2026-03-23.md) |
| 16 | native tools 去重 summary | 原生工具调用时跳过重复 tools summary | - |
| 17 | 时间上下文拆分 | 系统提示只保留日期+时区，渠道消息补精确时间戳 | - |
| 18 | 工具调用日志增强 | 脱敏参数、执行时长、输出结果（tracing::info） | - |
| 19 | disable_shell_policy | 跳过 shell 白名单/危险命令/路径黑名单，保留限流 | - |
| 20 | OpenAI fallback 收紧 | 仅 404 尝试 /responses fallback，传输层错误直接返回 | - |
| 21 | heartbeat 投递 wecom_ws | validate + auto-detect 支持 wecom_ws 作为 heartbeat target | - |
| 22 | draft_update_interval_ms 配置 | `WeComWsConfig` 新增字段，默认 300ms | [详细文档](./stream-final-answer-2026-03-29.md) |
| 23 | stale local image history 自愈 | 历史中的失效本地 `[IMAGE:]` marker 自动剥离，当前坏图失败回滚，避免后续文本继续报错 | [详细文档](./stale-local-image-history-self-heal-2026-03-30.md) |
| 24 | history image truncation | 历史轮 user 消息 `[IMAGE:]` 替换为文本占位，仅当前轮发真实图片，节省 token。**仅处理 user 角色**，tool/assistant 的 JSON content 不动（避免破坏 tool_call_id） | - |
| 25 | channel context compression | `prior_turns` token 达 `max_context_tokens` 90% 时，LLM 摘要压缩旧消息，更新内存+磁盘 JSONL，timeout 300s | - |
| 26 | reasoning 流式转发 + 切换清屏 | provider 的 `reasoning_content` 流式推到草稿显示，不进 `response_text`；reasoning → 正文过渡时自动翻转 `forwarded_live_deltas` 触发 Clear，避免 draft 出现"思考+正文"拼接 | - |
| 27 | memory recall session_id 对齐 | `is_group_chat` 补 `"group--"` 前缀（wecom_ws 群聊），recall session 从 `msg.sender` 改为 `history_key`（与 autosave 一致），删除死路的 sender scope | - |
| 28 | memory context 放 user + 放行全局条目 | `sqlite.rs` vector_search/recall post-filter 改成 `session_id=? OR session_id IS NULL`，让 memory_store 全局条目进入 channel 自动注入；同时把 `[Memory context]` 从 system prompt 末尾挪到最新 user 消息前缀，避免 memory 变化破坏 system+history 的 prompt cache prefix。持久化历史保持纯净（memory 只在 per-request clone 里） | - |
| 29 | SSE 流 reasoning/content 分离 | `sse_bytes_to_events` 原先用 `extract_sse_text_delta` 把 `reasoning_content` 回落到 content 字段包装成 `StreamChunk::delta`，导致 `chunk.reasoning` 永远 None，feat 26 的过渡 Clear 永不触发。改为显式分发：content → `delta`，reasoning_content → `reasoning`，与 `parse_sse_line` 对齐。非流式 `effective_content` fallback 不变 | - |
| 30 | autosave embedding 用 stripped 文本 | `SqliteMemory::store` 对 content 先 strip wecom 前缀 (`[sender_userid=...]` / `[timestamp]` / `[WECOM_QUOTE]`) 再算 embedding，与 channel 层 recall_query 的 strip 对齐。**stored content 保持原文**（LLM 看记忆仍有 sender/time 上下文）。效果：embedding_cache 命中，每轮省一次上游 embedding API；向量不再被 timestamp 噪声污染 | - |
| 31 | recall 噪声治理：关 BM25 + strip 边缘 @mention | 问题：群聊每条消息都含 `@owl`，FTS5 `unicode61` 对中文不切词，BM25 实际只在 `@owl` 上打分，所有 @mention 条目 `kw_norm ≈ 1.0`，最终分里恒加 0.3 噪声地板，min_relevance_score=0.4 形同虚设。治理两路并进：(1) config `[memory] search_mode = "embedding"` 完全关 BM25，回归纯向量打分；(2) `channels/mod.rs` recall_query 在 `strip_wecom_ws_autosave_prefixes` 之后再调 `wecom_ws::strip_edge_mentions`（改 `pub(crate)`）去掉前后缘 @bot / @user，消除 bge-m3 里的共现 token 吸引力。stored content 不动（asymmetric strip，bge-m3 稳健） | - |
| 32 | 短 query 跳过自动召回 + cron recall 可关 + 阈值收紧 | bge-m3 对极短输入（如 `"1"`、`"ok"`）产出低质量向量，跟一堆短 core 条目 0.4-0.55 都能过阈值。三件套治理：(1) `[memory] min_query_chars = 8`（按 `chars().count()` 计，默认 8），recall_query 短于此值 channels 层直接 skip `build_memory_context`，不调 embedding 不做向量搜；(2) `[cron] auto_recall_memory = false`（默认关），`cron/scheduler.rs` 的前置 memory_context 块用此 flag gate，agent job 需要回忆可用 `memory_recall` 工具；(3) `min_relevance_score` 默认从 0.4 提到 0.55，基线更贴合 bge-m3 真实分布 | - |
| 33 | strip_think_tags_inline 保留尾部 `\n` | 上游 `c70e86cc`（#5505）在 `strip_think_tags_inline` 末尾 `.trim()`，把 Progress 事件 `"⏳ tool\n"` 的尾 `\n` 吃掉。wecom_ws `note_progress_update` 直接 `push_str` 累积到 work_log，于是连续工具进度被拼成一行无换行。改法：末尾 `trim_start` + `trim_end` 后，如果原文尾部有 `\n` 就重新加回。其他 channel（Telegram/Slack 等）同样受益。抵消上游 `0d2b57ee`(#4394) "ensure newline" 被回归 | - |
| 34 | agent::run `suppress_memory_recall` 参数 | 本 fork 第 32 条的 cron 门控只在 scheduler 层，下游 `agent::run::build_context` 仍会无条件 recall + 贴 `[Memory context]`，cron/heartbeat 任然中招。修法：`agent::run` 末位加 `suppress_memory_recall: bool`，scheduler / daemon heartbeat 两路传 `true`（build_context 短路返回空字符串），CLI 交互/channel 分发传 `false`。附带吸收上游 #5817 部分：`cron_config.memory.auto_save = false`，防 cron 模板 prompt 污染 memories 表 | - |

## 运维参考

| # | 主题 | 说明 | 文档 |
|---|------|------|------|
| 1 | vision_provider 路由与 custom: provider | 主模型不支持视觉时，`custom:` 硬编码 vision=true 导致路由失效，用 `openai` provider 替代的 workaround | [详细文档](./vision-provider-routing-custom-workaround-2026-04-13.md) |

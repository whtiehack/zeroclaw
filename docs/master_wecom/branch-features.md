# `master_wecom` 功能清单

更新时间：`2026-04-15`

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

## 运维参考

| # | 主题 | 说明 | 文档 |
|---|------|------|------|
| 1 | vision_provider 路由与 custom: provider | 主模型不支持视觉时，`custom:` 硬编码 vision=true 导致路由失效，用 `openai` provider 替代的 workaround | [详细文档](./vision-provider-routing-custom-workaround-2026-04-13.md) |

# `master_wecom` 分支独有功能清单

更新时间：`2026-03-24`

本文件记录 `master_wecom` 分支相对于上游 `master` 的所有独有功能。

维护规则：

- 新增独有功能时，必须同步更新本清单。
- 合并上游时，如上游新增了类似功能，必须对比分析后报告用户再决定。
- 如果某功能已被上游覆盖并决定移除本地实现，从清单中删除对应条目并记录原因。

---

## 一、wecom_ws 企业微信 AI Bot 通道

1. **WebSocket 长连接通道** — 通过 bot_id + secret 接入企业微信 AI Bot WebSocket 接口，支持订阅、心跳保活、断线指数退避重连。单聊映射为 user--userid，群聊映射为 group--chatid；群聊历史按群共享，每条消息自动补入发送者 userid。

2. **权限控制** — 支持 allowed_users 和 allowed_groups 两套白名单；未授权用户/群收到解释性拒绝消息，而非静默丢弃。

3. **入站多模态** — 接收文本、语音转写、图片、文件和图文混合消息；图片/文件按企业微信 AES 规则解密下载到本地缓存，转为框架附件标记；被引用消息整理为结构化引用上下文。

4. **出站流式草稿** — 先发"处理中"草稿，通过长连接持续更新内容；过程态草稿只保留最近 10 行，收到最终回复阶段的 clear 哨兵后改为完整累积展示正文，最终收口为正式回复。长文本自动按企业微信 markdown 限制切块发送。

5. **出站附件标记** — 回复中支持 `[IMAGE:/path]`、`[FILE:/path]`、`[VOICE:/path]`、`[VIDEO:/path]`，运行时自动识别本地文件、校验大小、分块上传媒体，发送为企业微信原生消息。纯附件回复自动补一条文本，避免标记原样泄露。

6. **会话控制命令** — 支持 /new、/stop、/models 等运行时命令；/stop 作为 ChannelRuntimeCommand::StopCurrent 可中断当前生成。（如果上游加了新斜杠命令，可以考虑支持情况）

7. **interrupt_on_new_message** — 同一用户在同一会话中发新消息时，可中断正在生成的旧回复并保留上下文，直接开始新一轮回答。

8. **流式过期兜底** — 草稿更新过期时停止继续刷流；最终收口过期时自动退回普通消息发送；取消过期时安静退出。

9. **心跳 ACK 静默处理** — 心跳响应单独消费，不再作为普通命令回包打日志噪音。

## 二、通用层改动

以下改动修改了上游公共模块，合并时冲突风险较高，需重点关注。

10. **cron 投递到 wecom_ws** — `delivery.channel = "wecom_ws"` 接入 cron 校验和持久化层，定时任务可投递到企业微信会话。

11. **tool-call 文本 relay** — 模型在调用工具前后的解释文本通过 on_delta 实时推送到草稿更新器，最终回复前清除进度行。

12. **draft sender 显式关闭** — tool loop 结束后 `drop(delta_tx)` 再 await draft updater，避免草稿通道未关闭导致最终消息收口异常。

13. **non_cli_excluded_tools 在 full 模式生效** — 去掉了 `AutonomyLevel::Full` 的短路判断，非 CLI 通道在 full 模式下仍能排除指定工具。

14. **native tool 模式不重复注入 tools summary** — 使用原生工具调用时跳过系统提示中的重复工具说明。

15. **时间上下文拆分** — 系统提示只保留当前日期和时区（减少缓存 prompt 时间漂移）；每条渠道消息进入历史前打上精确本地时间戳 `[{now}]`。

16. **工具调用日志增强** — 记录脱敏后的工具参数、执行时长、输出结果或错误原因（tracing::info 级别）。

17. **disable_shell_policy 开关** — `autonomy.disable_shell_policy = true` 时跳过 shell 命令白名单、危险命令风险门、路径黑名单校验，但总量限流仍保留。

18. **OpenAI-compatible fallback 收紧** — 仅在 `/chat/completions` 返回 404 时尝试 `/responses` fallback；传输层错误（连接失败、超时、TLS）直接返回原始错误，不再多打一轮 fallback。

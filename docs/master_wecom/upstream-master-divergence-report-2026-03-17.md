# `master_wecom` 与 `upstream/master` 分叉后上游更新报告

更新时间：`2026-03-17`

## 1. 报告目的

这份文档用于回答一个具体问题：

自 `master_wecom` 与 `upstream/master` 分叉以来，上游到底更新了什么，变化规模有多大，哪些更新会直接影响 `master_wecom` 后续同步。

本文面向 `master_wecom` 分支维护者，重点关注三件事：

- 上游新增了哪些功能与修复。
- 这些变化集中落在哪些模块。
- 哪些文件已经与 `master_wecom` 形成直接冲突面。

## 2. 对比基线

| 项目 | 值 |
| --- | --- |
| 本地主开发分支 | `master_wecom` |
| 上游对比分支 | `upstream/master` |
| `master_wecom` 当前 HEAD | `54edd80b` |
| `master_wecom` HEAD 主题 | `fix(wecom_ws): suppress heartbeat ack debug noise` |
| `upstream/master` 当前 HEAD | `a9a61130` |
| `upstream/master` HEAD 主题 | `fix(docs): revert unauthorized CLAUDE.md additions from #3604 (#3761)` |
| 最近共同祖先 | `d6e5907b6581bc2ff0e8a8ce07df72b3b7ed2c24` |
| 共同祖先主题 | `feat(tools): add cloud transformation accelerator tools (#3663)` |
| 共同祖先提交日期 | `2026-03-16` |
| 分叉后 `master_wecom` 独有提交数 | `14` |
| 分叉后 `upstream/master` 独有提交数 | `79` |

说明：

- 本文的“上游更新”指 `d6e5907b..upstream/master` 这一段历史。
- 下文涉及的“日期”使用 Git 提交记录中的日期显示，不保证与提交拓扑顺序完全一致。
- 因为上游有 topic branch 合并，所以你会看到少量 `2026-03-15` 的提交出现在共同祖先之后；这不代表分叉点判断有误。

## 3. 一页摘要

这不是一次“小修小补”级别的漂移，而是一次已经明显跨过多个功能主题的上游演进。

关键数字如下：

| 指标 | 数值 |
| --- | --- |
| 上游新增总提交数 | `79` |
| 其中非 merge 提交 | `70` |
| 其中 merge 提交 | `9` |
| 上游改动文件数 | `153` |
| 上游代码行变化 | `+17106 / -6985` |

按非 merge 提交类型统计：

| 类型 | 数量 |
| --- | --- |
| `fix` | `37` |
| `feat` | `17` |
| `chore` | `7` |
| `ci` | `4` |
| `docs` | `3` |
| `test` | `1` |
| 其他 | `1` |

按提交日期分布：

| 日期 | 非 merge 提交数 |
| --- | --- |
| `2026-03-15` | `3` |
| `2026-03-16` | `50` |
| `2026-03-17` | `17` |

按变更文件数看，改动最集中的目录是：

| 目录 | 变更文件数 | 说明 |
| --- | --- | --- |
| `docs/i18n` | `43` | 以清理和移除重复/孤儿文档为主，不是运行时主风险 |
| `src/providers` | `16` | Provider 能力扩展和兼容性修复明显 |
| `src/channels` | `16` | 新 channel 与多项渠道修复，和 `master_wecom` 最接近 |
| `src/tools` | `15` | 工具面扩展显著，且属于高风险目录 |
| `.github/workflows` | `8` | 发布链和包管理同步持续调整 |
| `src/observability` | `6` | 增加 Hands dashboard 相关指标事件 |
| `src/memory` | `5` | session、knowledge graph、cache 相关增强 |
| `src/agent` | `5` | 调度、工具 schema、视觉历史处理有修复 |

一句话判断：

`master_wecom` 当前与上游的差异已经不是“补几个 fix 就行”，而是上游已经推进了一轮包含 channel、provider、tools、memory、security、release engineering 的功能期。

## 4. 上游更新全景

### 4.1 新增能力

上游新增能力主要集中在下面几个主题：

- `feat(heartbeat)`：加入健康指标、自适应心跳间隔、任务历史。
- `feat(sessions)`：引入 `SQLite + FTS5` 的 session backend、trait abstraction 和 migration。
- `feat(cache)`：接入两级响应缓存、多 provider token 统计与 cache analytics。
- `feat(knowledge)`：引入知识图谱，用于能力沉淀和复用。
- `feat(security)`：加入 Merkle hash-chain 审计链。
- `feat(tools)`：新增 browser delegation tool。
- `feat(tools)`：新增 Google Workspace CLI (`gws`) 集成。
- `feat(multi)`：新增 LinkedIn tool，并补 WhatsApp voice notes 与 Anthropic OAuth。
- `feat(stt)`：引入 `TranscriptionProvider` trait，支持多 provider STT。
- `feat(providers)`：新增 `Claude Code`、`Gemini CLI`、`KiloCLI` 子进程 provider。
- `feat(providers)`：为 VolcEngine/ByteDance gateway 新增 `VOLCENGINE_API_KEY`。
- `feat(channels)`：新增 `X/Twitter`、`Mochat`、`Reddit`、`Bluesky` 和通用 `Webhook` channel。
- `feat(whatsapp-web)`：新增语音消息转写支持。
- `feat(observability)`：增加 Hands dashboard metrics/events。

### 4.2 重要修复

上游修复中，对运行时行为影响比较大的包括：

- `fix(agent)`：移除 GLM 风格工具调用解析中的“裸 URL -> curl fallback”。
- `fix(agent)`：防止 XML dispatcher 重复注入 tool schema。
- `fix(agent)`：为非视觉 provider 清理历史中的 vision markers。
- `fix(memory)`：按 session 过滤 autosave 噪音，限制 recall/store 范围。
- `fix(memory)`：`MemoryCategory` 序列化改成 plain string，并修复 dashboard 渲染崩溃。
- `fix(channel)`：修复多房间回复路由回归。
- `fix(channel)`：Discord DM 不再受 `mention_only` 错误拦截。
- `fix(slack)`：runtime channel wiring 正确尊重 `mention_only`。
- `fix(telegram)`：避免重复发送 `finalize_draft`。
- `fix(qq)`：改为发送 markdown 而不是 plain text。
- `fix(openai-codex)`：跨流分块安全解码 UTF-8。
- `fix(gateway)`：dashboard WebSocket auth 通过 subprotocol 传 bearer token。
- `fix(security)`：`cron once` 在 rate-limit 前先校验命令。
- `fix(config)`：补齐多个 `#[serde(default)]`，减少配置兼容性问题。
- `fix(config)`：支持 Clash Verge 使用的 `socks` proxy scheme。
- `fix(web)`：确保 fresh clone 时 `web/dist` 存在。

### 4.3 发布、安装与工程化

这轮上游同时推进了较多工程化更新：

- 版本连续推进到 `0.4.1`、`0.4.2`、`0.4.3`。
- 恢复 `Homebrew core` formula 发布。
- 新增 `Scoop` manifest 模板和发布工作流。
- 新增 `AUR` `PKGBUILD` 模板和发布工作流。
- 为稳定版发布增加 Scoop/AUR 自动同步。
- 修复 release tweet、Docker push、crates.io publish 之间的耦合与幂等问题。
- 修复 release workflow 的 rust cache 作用域。
- 安装脚本修复版本显示、pairing code 展示，并补上 Debian/Ubuntu 缺失的 `libssl-dev`。
- Docker 构建链连续修了 dummy binary、cache 失效、旧 fingerprint 污染等问题。

### 4.4 文档与仓库整理

文档层面的显著变化包括：

- 清理重复的越南语文档。
- 移除孤儿希腊语 locale。
- 新增 Docker/Podman stop/restart 说明。
- 将 Scoop/AUR 纳入 CI map 和 release process 文档。
- 回滚了来自 `#3604` 的未授权 `CLAUDE.md` 增补。

## 5. 按模块拆解

### 5.1 Channels

上游在 `src/channels/` 里做了两类事：一类是新增 channel，另一类是修现有 channel 的路由和消息行为。

新增部分：

- `src/channels/twitter.rs`
- `src/channels/mochat.rs`
- `src/channels/reddit.rs`
- `src/channels/bluesky.rs`
- `src/channels/webhook.rs`
- `src/channels/session_backend.rs`
- `src/channels/session_sqlite.rs`
- `src/channels/session_store.rs`

修复与增强部分：

- `src/channels/whatsapp_web.rs` 增加语音消息转写。
- `src/channels/nextcloud_talk.rs` 支持 Activity Streams 2.0 webhook。
- `src/channels/telegram.rs` 修复 `finalize_draft` 重复消息。
- `src/channels/qq.rs` 切换到 markdown 消息。
- `src/channels/discord.rs` 修复 DM 下的 `mention_only` 行为。
- `src/channels/mod.rs` 增量非常大，说明 channel registry / wiring 本身有实质变化。

对 `master_wecom` 的意义：

- `master_wecom` 的核心增量本身就是 `wecom_ws` channel，所以 `src/channels/mod.rs` 是最可能出现手工冲突的位置之一。
- 上游已经在 channel 层引入更多统一 wiring、session backend 和 mention 行为修复，后续同步时不应只看 `wecom_ws` 注册点，还要检查 channel 生命周期与 session 行为是否被新的公共逻辑影响。

### 5.2 Providers

`src/providers/` 在这段时间属于明显扩张状态。

主要新增：

- `src/providers/claude_code.rs`
- `src/providers/gemini_cli.rs`
- `src/providers/kilocli.rs`

主要修复与兼容性补洞：

- 补齐 AiHubMix、SiliconFlow、Codex OAuth provider gap。
- 为 VolcEngine/ByteDance gateway 增加 `VOLCENGINE_API_KEY`。
- 调整 OpenAI reasoning models 的 temperature 处理。
- `src/providers/openai_codex.rs` 修复 UTF-8 跨 chunk 解码。

对 `master_wecom` 的意义：

- 本地分支已有 `fix(providers): skip responses fallback on transport errors`，而上游同一时期也在 provider 兼容层持续变动。
- `src/providers/compatible.rs` 已经进入双方共同修改文件列表，后续合并时要重点确认 transport error、responses fallback、Codex/OAuth provider 路径是否出现语义叠加或回退。

### 5.3 Tools 与 Integrations

这一轮 `src/tools/` 的变化不只是补参数，而是新增了新的工具能力面。

新增：

- `src/tools/browser_delegate.rs`
- `src/tools/google_workspace.rs`
- `src/tools/knowledge_tool.rs`
- `src/tools/linkedin.rs`
- `src/tools/linkedin_client.rs`

修复与接线：

- `fix(tool)` 扩展 `cron_add` 与 `cron_update` 的参数 schema。
- `fix(tools)` 将 activated toolset 正式接进 dispatch。
- `fix(tool+channel)` 回滚 `model_routing_config` 造成的 invalid model 设置。
- `fix(integrations)` 将 Cron 和 Browser status 接回配置字段。

对 `master_wecom` 的意义：

- 仓库自带风险分级里，`src/tools/**` 属于高风险区域；而这次上游确实在这里持续新增和修复。
- `master_wecom` 目前也改了日志输出、shell policy、native tools summary 等与工具可见性和调度体验相关的行为，同步时要把“工具实际执行逻辑”和“工具展示/摘要逻辑”一起回归验证。

### 5.4 Agent、Memory、Sessions、Knowledge

上游在 agent loop 和 memory 子系统里推进了一批“看起来分散，实际上相互耦合”的更新。

核心点：

- `src/agent/loop_.rs` 有持续修改。
- `src/agent/dispatcher.rs` 修 XML tool schema 注入。
- `src/memory/response_cache.rs` 加强缓存能力。
- `src/memory/knowledge_graph.rs` 新增知识图谱。
- `src/memory/mod.rs`、`src/memory/traits.rs` 随之扩展。
- `src/channels/transcription.rs` 明显放大，和 STT provider 抽象直接相关。

对 `master_wecom` 的意义：

- 本地分支已在 `src/agent/loop_.rs` 中做过 `on_delta` 文本转发、native tools summary 跳过等调整。
- 上游同一文件区间又叠加了 agent 相关修复，因此这里属于高概率手工冲突点。
- 由于上游把 session、cache、knowledge 都推起来了，后续同步后需要额外回归“channel 上下文隔离”和“工具输出在历史中的可见性”。

### 5.5 Security、Gateway、Daemon、Observability

这部分上游更新虽然数量不如 channel 多，但按仓库自己的风险定义，权重更高。

关键变更：

- `src/security/audit.rs` 增加 Merkle hash-chain 审计链。
- `fix(security)` 在 `cron once` 场景下先做命令校验再 rate-limit。
- `src/gateway/` 为 dashboard WebSocket auth 增加 bearer token subprotocol 透传。
- `src/daemon/mod.rs` 忽略 `SIGHUP`，保证断开终端或 SSH 后继续运行。
- `src/observability/` 新增 Prometheus、OTel、verbose/noop 相关增强。

对 `master_wecom` 的意义：

- 仓库风险分级里，`src/security/**`、`src/gateway/**`、`src/tools/**`、`.github/workflows/**` 都在高风险区。
- 这意味着后续同步应按“高风险变更引入”处理，而不是按普通 bugfix 批量拉平。

### 5.6 Config、Install、Web、CI

配置与工程侧的变化，为后续同步增加了一个现实问题：`schema` 合并会比较重。

主要变化：

- `feat(config)` 为 transcription 增加 `initial_prompt`。
- `fix(config)` 给 `Config` 和 `ChannelsConfig.cli` 补 `serde(default)`。
- `fix(config)` 支持 `socks` proxy scheme。
- `fix(install)` 修安装脚本版本显示、pairing code 输出、Debian/Ubuntu 的 `libssl-dev`。
- `fix(web)` 保证 `web/dist` 目录存在。
- `.github/workflows/` 持续调整发布链、cache、包管理同步。

对 `master_wecom` 的意义：

- 本地分支已经在 `src/config/schema.rs` 里新增了 `wecom_ws`、stop/interrupt 配置、`disable_shell_policy` 等字段。
- 上游同一文件又在推进 transcription、session、tool/browser status、serde default 等结构性修改。
- `src/config/schema.rs` 是当前最需要谨慎手工对齐的文件之一。

## 6. 时间线概览

### 6.1 `2026-03-15`

这一日的提交量不大，但埋下了后面几天功能扩展的基础：

- `41b46f23` `docs(setup): add Docker/Podman stop/restart instructions`
- `37d76f7c` `feat(config): support initial_prompt in transcription config for proper noun recognition`
- `2539bcaf` `fix(gateway): pass bearer token in WebSocket subprotocol for dashboard auth`

### 6.2 `2026-03-16`

这是本轮上游变化最密集的一天，`50` 个非 merge 提交几乎覆盖所有核心层：

- heartbeat、sessions、cache 三件套一起落地。
- release engineering 连续修正，并恢复/新增 Homebrew、Scoop、AUR。
- providers 侧补网关、OAuth、reasoning model 兼容。
- channels 侧新增 `X/Twitter` 和 `Mochat`，并修 Telegram、QQ、Discord、Matrix、多房间路由。
- tools 侧新增 browser delegation，并修 Cron schema 与 activated toolset wiring。
- security 与 daemon 侧也有行为级修复。

### 6.3 `2026-03-17`

这一天继续向能力扩张推进，但更偏向新功能和定向修复：

- 新增 `knowledge graph`。
- 新增多 provider STT。
- 新增 `Google Workspace CLI`。
- 新增 `Claude Code`、`Gemini CLI`、`KiloCLI` provider。
- 新增 `Reddit`、`Bluesky`、generic `Webhook` channel。
- 新增 LinkedIn tool，并补 WhatsApp voice notes 与 Anthropic OAuth。
- 修 `Slack mention_only`、`OpenAI Codex UTF-8`、`Nextcloud Talk webhook`。
- 回滚未授权的 `CLAUDE.md` 文档增补。

## 7. 与 `master_wecom` 的直接关系

### 7.1 已确认被上游等价吸收的本地补丁

通过 `git cherry -v upstream/master master_wecom` 检查，当前只有一条本地提交已经被上游以等价 patch 吸收：

| 本地提交 | 上游等价提交 | 说明 |
| --- | --- | --- |
| `acc97487` `fix(telegram): avoid duplicate finalize_draft messages` | `595b81be` `fix(telegram): avoid duplicate finalize_draft messages (#3259)` | rebase 时大概率会自动跳过或需要手工确认丢弃 |

其余本地提交目前仍然是 `master_wecom` 独有主题。

### 7.2 双方共同修改文件清单

下面这些文件同时出现在 `base..master_wecom` 和 `base..upstream/master` 两边的修改列表中：

| 文件 | 风险判断 | 备注 |
| --- | --- | --- |
| `.gitignore` | 低 | 规则可手工并存 |
| `Cargo.lock` | 低到中 | 依赖版本需以最终构建结果为准 |
| `Cargo.toml` | 低到中 | provider/tool 新增可能导致依赖变化 |
| `src/agent/loop_.rs` | 高 | 双方都改了 agent loop 行为 |
| `src/channels/mod.rs` | 高 | 本地加 `wecom_ws`，上游扩 channels/wiring |
| `src/channels/telegram.rs` | 中 | 存在已被上游吸收的重复补丁 |
| `src/config/schema.rs` | 高 | 本地和上游都在持续扩 schema |
| `src/providers/compatible.rs` | 中到高 | provider 兼容逻辑两边都动过 |
| `tests/integration/mod.rs` | 低 | 主要是测试入口接线 |
| `tests/integration/telegram_finalize_draft.rs` | 低到中 | 和已吸收的 Telegram 修复对应 |

### 7.3 需要优先关注的冲突点

最值得优先人工处理的，不是文件数量最多的地方，而是这些“语义最容易踩空”的点：

- `src/channels/mod.rs`
  本地需要保住 `wecom_ws` 注册和行为；上游则新增多个 channel 和 session wiring。

- `src/config/schema.rs`
  本地有 `wecom_ws`、stop/interrupt、`disable_shell_policy`；上游有 transcription、browser/cron 状态接线、更多 `serde(default)` 和新增 provider/tool 配置。

- `src/agent/loop_.rs`
  本地关心 tool-call 文本转发、native tools summary；上游则修工具 schema 注入、视觉历史处理、memory/session 相关行为交互。

- `src/providers/compatible.rs`
  本地是 transport error / responses fallback；上游是 provider gap、兼容分支与 Codex/OpenAI 相关修复。

- `src/channels/telegram.rs`
  这里更像“重复修同一问题”，但如果不注意，容易把上游版本回退到本地旧实现。

## 8. 同步建议

### 8.1 建议把这次同步视为高风险同步

原因不是提交数本身，而是上游确实触达了仓库定义里的高风险目录：

- `src/security/**`
- `src/gateway/**`
- `src/tools/**`
- `.github/workflows/**`

因此，这次同步不建议当成普通“拉点 fix”处理。

### 8.2 建议的处理顺序

建议顺序如下：

1. 先保留一个当前 `master_wecom` 的安全快照分支。
2. 再尝试基于 `upstream/master` 做 rebase 或临时整合分支。
3. 优先处理 `src/channels/mod.rs`、`src/config/schema.rs`、`src/agent/loop_.rs`、`src/providers/compatible.rs`。
4. 对 `Telegram finalize_draft` 那组补丁，优先接受上游等价版本，避免重复保留。
5. 再处理 `Cargo.toml`、`Cargo.lock`、测试入口之类的机械冲突。
6. 合并完成后完整跑校验，而不是只跑定向测试。

### 8.3 合并后至少应回归的内容

建议至少跑下面三类验证：

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

如果这次同步真的落地为一个较完整的整合工作，建议直接跑：

- `./dev/ci.sh all`

建议额外做的定向回归：

- `wecom_ws` channel 注册、收发消息、停止/中断配置。
- tool-call 文本在流式输出中的展示。
- native tools summary 跳过逻辑。
- Telegram `finalize_draft` 去重行为。
- provider transport error 下的 fallback 行为。
- dashboard / gateway 鉴权和 observability 暴露面。

## 9. 值得优先阅读的上游提交

如果不准备一次性通读 `79` 个上游提交，建议优先读这几组：

| 提交 / 主题 | 原因 |
| --- | --- |
| `318ed8e9` `feat(heartbeat)` | 开始引入新的运行时健康状态与任务历史 |
| `9ba5ba56` `feat(sessions)` | session 存储能力升级，可能影响 channel 上下文管理 |
| `98688c61` `feat(cache)` | 响应缓存与 token tracking 会改变请求生命周期 |
| `3ea99a76` `feat(tools): add browser delegation tool` | 工具面重大扩展 |
| `675a5c9a` `feat(tools): add Google Workspace CLI (gws) integration` | 工具面新增外部集成 |
| `61de3d56` `feat(knowledge)` | memory/knowledge 侧的结构性扩展 |
| `e4ef25e9` `feat(security): add Merkle hash-chain audit trail` | 高风险安全域变更 |
| `058dbc87` `feat(channels): add X/Twitter and Mochat channel integrations` | channel registry 扩展开始点之一 |
| `220745e2` `feat(channels): add Reddit, Bluesky, and generic Webhook adapters` | channel registry 扩展继续放大 |
| `5e3308ea` `feat(providers): add Claude Code, Gemini CLI, and KiloCLI subprocess providers` | provider 族谱扩大明显 |
| `dcb182cd` `fix(agent): remove bare URL → curl fallback in GLM-style tool call parser` | agent/tool 行为语义变更 |
| `83803cef` `fix(memory): filter autosave noise and scope recall/store by session` | 对上下文边界影响直接 |
| `9a073fae` `fix(tools) Wire activated toolset into dispatch` | 工具启用态与 dispatch 正式接线 |
| `f0db63e5` `fix(integrations): wire Cron and Browser status to config fields` | schema 和集成状态字段联动 |

## 10. 附录 A：上游非 merge 提交清单

### `2026-03-15`

- `41b46f23` `docs(setup): add Docker/Podman stop/restart instructions`
- `37d76f7c` `feat(config): support initial_prompt in transcription config for proper noun recognition`
- `2539bcaf` `fix(gateway): pass bearer token in WebSocket subprotocol for dashboard auth`

### `2026-03-16`

- `794d87d9` `fix(config): add missing #[serde(default)] to Config struct fields (#3700)`
- `813ae17f` `fix(install): correct version display, show pairing code, bump to 0.4.0 (#3669)`
- `85271441` `docs: remove duplicate Vietnamese docs and orphan Greek locale (#3701)`
- `a2b18bdb` `chore: gitignore stale target-* build cache dirs (#3707)`
- `5ddea827` `fix(ci): scope rust-cache by OS image and target in release beta workflow (#3708)`
- `318ed8e9` `feat(heartbeat): add health metrics, adaptive intervals, and task history`
- `9ba5ba56` `feat(sessions): add SQLite backend with FTS5, trait abstraction, and migration`
- `98688c61` `feat(cache): wire two-tier response cache, multi-provider token tracking, and cache analytics`
- `8153992a` `fix(ci): scope rust-cache by OS image in stable release workflow (#3711)`
- `d642b0f3` `fix(ci): decouple tweet from crates.io and fix duplicate publish handling (#3716)`
- `45abd27e` `chore: bump version to 0.4.1`
- `cfba0098` `chore: regenerate Cargo.lock for v0.4.1`
- `6e4b1ede` `ci(homebrew): restore Homebrew core formula publishing workflow`
- `cd40051f` `ci(scoop): add Scoop manifest template and publishing workflow`
- `f349de78` `ci(aur): add AUR PKGBUILD template and publishing workflow`
- `3d007f6b` `docs: add Scoop and AUR workflows to CI map and release process`
- `c2133e6e` `fix(docker): prevent dummy binary from being shipped in container (#3687) (#3718)`
- `46378cf8` `fix(security): validate command before rate-limiting in cron once (#3699) (#3719)`
- `7a9e8159` `fix(config): add serde default for cli field in ChannelsConfig (#3720)`
- `a5f844d7` `fix(daemon): ignore SIGHUP to survive terminal/SSH disconnect (#3721)`
- `85429b36` `fix(ci): ensure tweet posts for stable releases and fix beta concurrency`
- `d593b6b1` `fix(ci): make crates.io publish idempotent across all workflows`
- `fc8ed583` `feat(providers): add VOLCENGINE_API_KEY env var for VolcEngine/ByteDance gateway (#3725)`
- `f210b439` `fix(ci): decouple tweet from Docker push in release workflows`
- `c7731707` `feat(providers): close AiHubMix, SiliconFlow, and Codex OAuth provider gaps (#3730)`
- `74a5ff78` `fix(qq): send markdown messages instead of plain text (#3732)`
- `8a890be0` `chore: bump version to 0.4.2 (#3733)`
- `84470a2d` `fix(agent): strip vision markers from history for non-vision providers (#3734)`
- `058dbc87` `feat(channels): add X/Twitter and Mochat channel integrations (#3735)`
- `7c36a403` `chore: sync Scoop and AUR templates to v0.4.1 (#3736)`
- `806f8b40` `fix(docker): purge stale zeroclawlabs fingerprints before build (#3741)`
- `d4d3e03e` `fix: add dummy src/lib.rs in Dockerfile.debian for dep caching stage (#3553)`
- `1ccfe643` `fix(channel): bypass mention_only gate for Discord DMs (#2983)`
- `4f9d817d` `fix(memory): serialize MemoryCategory as plain string and guard dashboard render crashes (#3051)`
- `2deb9145` `feat(observability): add Hands dashboard metrics and events (#3595)`
- `0ae515b6` `fix(channel): correct Matrix image marker casing to match canonical format (#3519)`
- `5db883b4` `fix(providers): adjust temperature for OpenAI reasoning models (#2936)`
- `b833eb19` `chore(deps): bump rust in the docker-all group (#3692)`
- `14f58c77` `fix(tool+channel): revert invalid model set via model_routing_config (#3497)`
- `3ea99a76` `feat(tools): add browser delegation tool (#3610)`
- `85bf6494` `fix(channel): resolve multi-room reply routing regression (#3224) (#3378)`
- `2eaa8c45` `feat(whatsapp-web): add voice message transcription support (#3617)`
- `c3a3cfc9` `fix(agent): prevent duplicate tool schema injection in XML dispatcher (#3744)`
- `e4ef25e9` `feat(security): add Merkle hash-chain audit trail (#3601)`
- `df4dfeaf` `chore: bump version to 0.4.3 (#3749)`
- `f0db63e5` `fix(integrations): wire Cron and Browser status to config fields (#3750)`
- `9a073fae` `fix(tools) Wire activated toolset into dispatch (#3747)`
- `fec81d8e` `ci: auto-sync Scoop and AUR on stable release (#3743)`
- `ec255ad7` `fix(tool): expand cron_add and cron_update parameter schemas (#3671)`
- `1ca2092c` `test(channel): add QQ markdown msg_type regression test (#3752)`

### `2026-03-17`

- `a9a61130` `fix(docs): revert unauthorized CLAUDE.md additions from #3604 (#3761)`
- `906951a5` `feat(multi): LinkedIn tool, WhatsApp voice notes, and Anthropic OAuth fix (#3604)`
- `220745e2` `feat(channels): add Reddit, Bluesky, and generic Webhook adapters (#3598)`
- `61de3d56` `feat(knowledge): add knowledge graph for expertise capture and reuse (#3596)`
- `675a5c9a` `feat(tools): add Google Workspace CLI (gws) integration (#3616)`
- `b099728c` `feat(stt): multi-provider STT with TranscriptionProvider trait (#3614)`
- `5e3308ea` `feat(providers): add Claude Code, Gemini CLI, and KiloCLI subprocess providers (#3615)`
- `7182f659` `fix(slack): honor mention_only in runtime channel wiring (#3715)`
- `ae768120` `fix(openai-codex): decode utf-8 safely across stream chunks (#3723)`
- `ee3469e9` `Fix: Support Nextcloud Talk Activity Streams 2.0 webhook format (#3737)`
- `013fca6a` `fix(config): support socks proxy scheme for Clash Verge (#3001)`
- `23a0f25b` `fix(web): ensure web/dist exists in fresh clones (#3114)`
- `d13f5500` `fix(install): add missing libssl-dev for Debian/Ubuntu (#3285)`
- `83803cef` `fix(memory): filter autosave noise and scope recall/store by session (#3695)`
- `dcb182cd` `fix(agent): remove bare URL → curl fallback in GLM-style tool call parser (#3694)`
- `595b81be` `fix(telegram): avoid duplicate finalize_draft messages (#3259)`
- `aa0f11b0` `fix(docker): copy build.rs into builder stage to invalidate dummy binary cache (#3570)`

## 11. 附录 B：`master_wecom` 分叉后本地提交清单

这部分不是“上游更新”，但保留在这里有助于理解哪些地方最容易冲突。

- `c743215d` `feat(channel): add wecom_ws AI bot channel`
- `d2d44cf4` `fix(providers): skip responses fallback on transport errors`
- `acc97487` `fix(telegram): avoid duplicate finalize_draft messages`
- `f2951cae` `fix(agent): relay tool-call text via on_delta`
- `17c868cd` `fix(channels): skip tools summary for native tools`
- `a370b3f3` `fix(prompt): timestamp channel turns and use date-only prompts`
- `79a6eaaf` `chore(gitignore): ignore ace-tool workspace`
- `84c92249` `docs(workflow): add master_wecom commit rules`
- `967d064c` `feat(security): add disable_shell_policy toggle`
- `1ea9c87b` `test(channels): align wecom_ws history test context`
- `396ddb85` `feat(log): show tool call arguments and outcomes`
- `03228a18` `docs(master_wecom): clarify wecom naming`
- `a2b9bc47` `feat(wecom_ws): support stop and interrupt config`
- `54edd80b` `fix(wecom_ws): suppress heartbeat ack debug noise`

## 12. 附录 C：复现本文统计的命令

```bash
git fetch upstream
git fetch origin

BASE=$(git merge-base master_wecom upstream/master)

git rev-list --left-right --count master_wecom...upstream/master
git rev-list --count "$BASE"..upstream/master
git rev-list --no-merges --count "$BASE"..upstream/master
git diff --shortstat "$BASE"..upstream/master
git log --no-merges --date=short --pretty=format:'%ad %h %s' "$BASE"..upstream/master
git cherry -v upstream/master master_wecom
```

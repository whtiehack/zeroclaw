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

状态：进行中

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

状态：进行中

- 只处理 `wecom_ws` 无法工作的公共层缺口
- 优先补配置接线、注册入口、必要 runtime hook
- 对公共层补丁逐条说明“为什么上游现状不够”

2026-03-25 当前判定：

- 上游已覆盖，无需重搬：
  - tool-call 文本 relay
  - draft sender 显式 `drop(delta_tx)` 收口
- 已完成迁移：
  - `non_cli_excluded_tools` 在 channel 路径的非 CLI `full` 模式继续生效
- 当前仍缺且值得继续做的公共层差异：
  - native tools 模式下跳过重复 tools summary
  - `disable_shell_policy` 配置开关
  - OpenAI-compatible transport error 不应触发 `/responses` fallback
- 当前保留为低优先级观察项：
  - prompt 时间上下文拆分
  - 工具调用日志增强
- 当前判断：阶段 3 下一步先做 native tools 模式下的重复 tools summary 去重，继续收窄 `wecom_ws` 等非 CLI channel 在新基线下的无效 prompt 噪音

### 阶段 4：验证与收口

状态：进行中

- 先跑最小范围验证，再决定是否跑全量
- 对失败项先区分是迁移缺口、上游现有问题还是环境问题
- 形成新的同步记录或迁移记录，避免再次回到口头判断

2026-03-25 当前验证补充：

- 已跑 `cargo test`
- 当前失败项与本轮 `wecom_ws` 迁移无直接关系：
  - `providers::bedrock::tests::bearer_token_precedence`
  - `providers::bedrock::tests::chat_fails_without_credentials`
- 当前分支相对 `upstream/master` 未修改 `src/providers/bedrock.rs`
- 因此当前进入后续迁移时，应把 `bedrock` 失败视为上游基线问题或独立问题，不阻塞 `wecom_ws` 后续公共层补丁判断
- 本轮 `non_cli_excluded_tools` 补丁已补充通过：
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test non_cli_excluded_tools --lib`

## 5. 当前已知优先级

### P0

- native tools 模式去掉重复 tools summary

### P1

- `disable_shell_policy` 开关
- OpenAI-compatible transport error fallback 收紧

### P2

- prompt 时间上下文拆分
- 工具调用日志增强

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

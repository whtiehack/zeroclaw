# `master_wecom` 上游更新分析规则

更新时间：`2026-03-27`

## 目的

本规则用于固定 `master_wecom` 分支在分析 `upstream/master` 更新时的默认关注点与输出结构。

后续凡是出现以下语境，默认按本文执行，不需要用户重复强调：

- “上游又有更新了，帮我 review 一下”
- “上游更新了啥”
- “帮我看下这次 sync 要注意什么”
- “分析一下上游改动对 `wecom_ws` 的影响”

## 默认分析范围

分析上游更新时，默认至少覆盖以下 5 项：

1. 上游整体更新了什么
2. trait / 公共接口有没有变动
3. 框架层新增了什么能力
4. 其它 channel 新增了什么功能或修复
5. 对 `wecom_ws` 有什么影响

如果用户没有额外指定范围，上述 5 项都必须给出。

## 分析顺序

### 1. 先定基线

- 先确认当前分支、共同祖先、上游 commit range
- 明确“这次分析的是哪一段上游新增历史”，避免把本地分支提交误算成上游更新
- 如存在 `master_wecom` 自身改动，需同时识别潜在冲突文件

### 2. 先看接口，再看行为

- 先检查 `src/**/traits.rs` 是否有直接签名变化
- 即使 trait 文件没改，也要继续检查公共层“事实上的接口/契约变化”
- 重点包括：
  - config schema
  - channel runtime 行为
  - agent loop / tool loop
  - session persistence / state
  - gateway / web API

结论要区分：

- 直接 trait 变更
- 无 trait 变更，但有公共行为契约变化

### 3. 框架层按能力归类，不按文件堆砌

框架层汇总时，优先按能力输出，不要只罗列改过哪些文件。

优先归类到这些主题：

- `agent`
- `channels` 公共层
- `memory`
- `tools`
- `gateway`
- `config`
- `session / persistence`

每项都要回答两个问题：

- 新增了什么能力
- 这项能力是 `wecom_ws` 可以直接受益，还是需要手工接线

### 4. 其它 channel 单独看

分析其它 channel 时，重点看：

- Slack / Matrix / Telegram / QQ / Lark / Feishu / Nextcloud Talk / WhatsApp 等已有 channel
- 是否新增用户可见能力
- 是否新增配置项
- 是否修复了与 `wecom_ws` 可能相似的问题

不要把“其它 channel 的普通小修”与“对 `wecom_ws` 有参考价值的更新”混在一起写。

### 5. `wecom_ws` 影响必须单列

`wecom_ws` 影响分析必须至少回答：

1. 有没有直接接口破坏
2. 有没有公共层 merge 热点
3. 上游新增能力里哪些可以直接复用
4. 哪些会被 `wecom_ws` 当前自定义实现绕开
5. 哪些本地补丁可能被上游覆盖、弱化或变成冗余
6. 哪些本地配置项或语义会与上游新配置/新语义冲突

## 默认输出结构

后续默认按以下顺序汇报：

### 1. trait / 公共接口变动

- 是否有直接 trait 签名变化
- 是否有隐性契约变化
- 哪些变化会影响本地接线

### 2. 框架层新增能力

- 按能力主题归纳
- 明确哪些属于“白拿”，哪些需要适配

### 3. 其它 channel 更新

- 只列用户可感知或对 `wecom_ws` 有参考价值的更新
- 不做无差别 changelog 式堆砌

### 4. 对 `wecom_ws` 的影响

- 兼容性影响
- 语义影响
- merge 冲突热点
- 建议保留 / 吸收 / 放弃的本地补丁

### 5. 风险与后续动作

- 是否建议立即同步
- 建议先处理哪些冲突点
- 是否需要补文档、补测试、删冗余配置

## `wecom_ws` 专项判断规则

分析 `wecom_ws` 时，默认特别检查以下点：

- 历史分桶是否被 `thread_ts` / transport id 重新切碎
- 群聊共享历史语义是否被公共层新逻辑覆盖
- `interrupt_on_new_message` 是否被上游排队、debounce、session 串行化等新机制改变体感
- 如上游新增或修改 `channels.debounce_ms` 一类入站聚合机制，必须明确判断：
  - `wecom_ws` 新消息是否仍会立即打断旧任务
  - 是否会先等待 debounce 窗口再触发取消
  - 当前默认值是否只是“暂时安全”，而不是语义上天然兼容
- 草稿流、tool progress、finalize/cancel 语义是否被上游 draft 机制改写
- `channel_delivery_instructions` 是否仍保留 `wecom_ws` 专用约束
- `wecom_ws` 私有配置是否仍真实生效，而不是只留 schema 未接线

## 文档落地要求

如果本次分析是为了同步上游或做长期记录，应同步更新：

- `docs/master_wecom/TEMPLATE-master-sync.md`
- 必要时新增 `master-sync-YYYY-MM-DD-HHMMSS.md`

如果本次发现了新的长期规则，而不是一次性结论，应优先写回本文，而不是只留在聊天记录里。

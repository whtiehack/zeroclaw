# stale local image history self-heal

更新时间：`2026-03-30`

## 背景

`wecom_ws` 入站图片会先落到 `workspace_dir/wecom_ws_files/`，再以 `[IMAGE:/absolute/path]` marker 进入会话历史。

当图片文件后续被清理、迁移、卷未挂载或实例切换后，历史中的旧本地路径可能失效。若当前 provider 支持 vision，后续任意文本追问都会在 multimodal 预处理阶段再次尝试读取这些旧路径，并报：

```text
multimodal image source not found or unreadable
```

结果是：

- 当前并不是图片问题的文本追问也会失败
- 同一会话会持续被旧 `[IMAGE:]` marker 污染
- 用户需要手工 `/clear` 才能恢复

## 目标

- 让旧历史中的失效本地图片 marker 自动自愈
- 保留“当前新发坏图要明确报错”的语义
- 不把图片永久保存在 workspace
- 不把 base64 图像内容写入 session history

## 实现

公共层最小修复，落在 `src/channels/mod.rs`：

### 1. 旧历史本地图片 marker 自愈

- 在 `process_channel_message()` 中，当前 user turn 入历史后、构造 provider history 前：
  - 只扫描“旧历史 turn”，不碰最后一条当前消息
  - 对 `[IMAGE:]` marker：
    - `data:` 保留
    - `http(s)` 保留
    - 本地路径仅在文件仍存在且可读时保留
    - 失效本地路径直接剥掉
  - 若 turn 去掉 marker 后为空，则从缓存 history 删除

这样可以覆盖：

- `wecom_ws`
- Telegram / Matrix / 其他会把本地绝对路径写进 `[IMAGE:]` 的 channel

### 2. 当前坏图回滚

把以下错误纳入 `should_rollback_failed_user_turn()`：

- `MultimodalError::ImageSourceNotFound`
- `MultimodalError::LocalReadFailed`

这样“当前这轮”引用坏图时仍然会报错，但不会把坏 turn 留在 history / session store 里继续污染后续文本消息。

## 行为变化

修复后：

- 历史中的旧失效本地图片不会再导致后续纯文本消息报错
- 当前消息若引用坏图，仍然返回明确错误
- 下一条文本消息可直接继续，不需要 `/clear`

未改变：

- 新图片消息仍然按原来的 multimodal 流程处理
- 非本地图片引用（`data:` / `http(s)`）不受此修复影响
- `wecom_ws_files` 清理策略不变

## 验证

本次补了 3 类回归覆盖：

1. helper 级别：只删除失效本地 marker，保留存在的本地文件和远程 URL
2. e2e：旧历史 stale `[IMAGE:/path]` 在 vision provider 下会被自动清洗，后续文本追问可成功
3. e2e：当前消息引用不存在图片时会报错，但后续文本追问不再被污染

本地执行结果：

- `cargo fmt --all -- --check` 通过
- `cargo check --lib --tests` 通过
- `cargo test ...` 在当前 macOS x86_64 环境链接测试二进制时失败，属于现有环境链接问题，不是本改动的类型检查失败

## 取舍

没有采用以下方案：

- 仅增大 `file_retention_days`
  - 只能延后问题，不能解决 stale history
- 禁止清理 `wecom_ws_files`
  - 会导致 workspace 持续增长
- 把图片转成 data URI 持久化进 history
  - session 体积和上下文成本过高

最终保留“文件缓存可清理，历史可自愈”的策略。

# vision_provider 路由：问题分析与改进方案

更新时间：`2026-04-13`

## 需求

主模型（`mimo-v2-pro`）不支持图片输入，另一个模型（`mimo-v2-omni`）支持视觉能力。期望行为：

- 纯文本消息走主模型（mimo-v2-pro）
- **仅当前消息**含图片时路由到视觉模型（mimo-v2-omni）
- 后续纯文本追问立即回到主模型，不因历史中残留图片标记而继续走视觉模型

---

## 问题一：`custom:` provider 硬编码 vision=true，vision_provider 路由永远不触发

### 根因

vision_provider 路由的触发条件（`src/agent/loop_.rs:2413-2414`）：

```rust
let vision_provider_box = if image_marker_count > 0
    && !provider.supports_vision()   // ← 仅当主 provider 不支持 vision 时触发
{
    // 创建 vision_provider 处理图片
}
```

`custom:` provider 在创建时硬编码了 `supports_vision = true`（`src/providers/mod.rs:1573`）：

```rust
name if name.starts_with("custom:") => {
    Ok(compat(OpenAiCompatibleProvider::new_with_vision(
        "Custom", &base_url, key, AuthStyle::Bearer,
        true,   // ← 无条件声明支持 vision
    )))
}
```

系统认为 `custom:` 本身就能处理图片，永远不会路由到 vision_provider。

### 各 provider 的 vision 声明

| Provider | vision | 原因 |
|---|---|---|
| `anthropic` | `true` | `capabilities()` 显式返回 |
| `ollama` | `true` | `capabilities()` 显式返回 |
| `openrouter` | `true` | `capabilities()` 显式返回 |
| `custom:` | `true` | `new_with_vision(..., true)` 硬编码 |
| `openai` | **`false`** | 未覆写 `capabilities()`，使用 `Default`（vision=false） |
| 多数 OpenAI-compatible（groq, deepseek, venice 等） | `false` | 使用 `::new()` 默认 vision=false |

### 配置层 workaround（已否决）

曾考虑用 `openai` provider 替代 `custom:` 作为主 provider，因为 `openai` 的 vision=false 可以触发路由。但经对比分析，`openai` 与 `custom:` 存在关键差异，**不可行**。详见下文"openai 与 custom: 的差异"一节。

---

## 问题二：vision 路由按全部历史判断，且整轮替换主模型

### 现象

即使只改 1 行条件修复了问题一，vision 路由仍有两个设计层面的问题：

**（a）检测范围是全部会话历史**（`src/multimodal.rs:88-94`）：

```rust
pub fn count_image_markers(messages: &[ChatMessage]) -> usize {
    messages.iter()
        .filter(|m| m.role == "user")    // 扫描所有 user 消息，不只是当前
        .map(|m| parse_image_markers(&m.content).1.len())
        .sum()
}
```

**（b）路由是整轮替换**（`src/agent/loop_.rs:2444-2454`）：

```rust
let (active_provider, active_provider_name, active_model) =
    if let Some(ref vp_box) = vision_provider_box {
        // vision model 接管一切：上下文理解、工具调用、回复生成
        (vp_box.as_ref(), vp_name, vm)
    } else {
        (provider, provider_name, model)
    };
```

且在 tool loop 的每次迭代中都重新判断（`loop_.rs:2313, 2407`），只要历史中还有图片标记，每次迭代都走 vision model。

### 实际行为

| 步骤 | 用户消息 | 历史中有图片? | 实际使用的模型 |
|---|---|---|---|
| 1 | "描述这张图" + `[IMAGE:xxx]` | 有 | mimo-v2-omni |
| 2 | "继续分析"（纯文本） | **有**（步骤1的图还在历史中） | **mimo-v2-omni** |
| 3 | "写段代码"（纯文本） | **有**（图还在） | **mimo-v2-omni** |
| 4 | 图片文件被清理/过期 | 无（stale image 自愈剥离标记） | mimo-v2-pro |

一旦发了图片，在图片标记从历史中消失之前，主模型完全不会被使用。

---

## openai 与 custom: (OpenAiCompatibleProvider) 的差异

配置层 workaround 曾考虑用 `openai` 替代 `custom:` 作为主 provider（`openai` 的 vision=false 可触发路由）。但两者差异导致该方案不可行：

| 维度 | `openai` (OpenAiProvider) | `custom:` (OpenAiCompatibleProvider) |
|---|---|---|
| **流式输出** | **不支持**（`supports_streaming()` → `false`，trait 默认值，无任何 streaming 实现） | **支持**（`supports_streaming()` → `true`，完整 SSE 实现） |
| **流式工具事件** | 不支持 | 支持 |
| **消息体图片** | `content` 只能是 `String` | `content` 支持 `MessageContent::Parts`（含 `ImageUrl`） |
| **temperature 覆写** | gpt-5/o1/o3/o4 等模型名强制 temperature=1.0 | 原样透传 |
| **Responses API 回退** | 无 | 404 时可回退到 `/v1/responses` |
| **extra_headers** | 不支持 | 支持 |
| **reasoning_effort** | 不支持 | 支持 |
| **User-Agent** | 不可配置 | 可配置 |
| **超时** | 硬编码 120s | 可通过 `provider_timeout_secs` 配置 |
| **system 消息合并** | 始终独立发送 | 可选合并到 user 消息 |

**流式输出是否决原因。** wecom_ws 通道依赖 streaming 实现草稿预览和逐步内容推送。用 `openai` 做主 provider 后，agent loop 判断 `supports_streaming() == false` 直接走非流式路径（`src/agent/loop_.rs:2515-2516`），用户体验退化为：发消息后一片沉默，直到模型完整生成后才一次性收到回复。

---

## 改进方案

需要代码改动，涉及两处修改。

### 改动一：显式配置 vision_provider 时无条件触发路由

**目标**：解决 `custom:` 硬编码 vision=true 导致路由失效的问题。

**修改位置**：`src/agent/loop_.rs:2413-2414`

```rust
// 改前：
let vision_provider_box: Option<Box<dyn Provider>> = if image_marker_count > 0
    && !provider.supports_vision()

// 改后：
let vision_provider_box: Option<Box<dyn Provider>> = if image_marker_count > 0
    && (!provider.supports_vision() || multimodal_config.vision_provider.is_some())
```

**语义**：用户显式配置了 `vision_provider` = 明确要求图片走独立路由，不需要再检查主 provider 的 vision 声明。未配置 `vision_provider` 时行为完全不变。

### 改动二：仅对当前消息含图片时路由

**目标**：后续纯文本追问立即回到主模型，不因历史中残留图片标记而持续走视觉模型。

**方案 A：改检测范围为仅当前消息**

修改 `src/agent/loop_.rs:2407` 处的 image marker 计数逻辑，仅统计最新 user 消息而非全部历史：

```rust
// 改前：
let image_marker_count = multimodal::count_image_markers(history);

// 改后：只统计最后一条 user 消息
let image_marker_count = history.iter()
    .rfind(|m| m.role == "user")
    .map(|m| multimodal::parse_image_markers(&m.content).1.len())
    .unwrap_or(0);
```

需要评估的影响：
- 历史中的旧图片仍在 `prepared_messages` 中，vision model 处理当前消息时仍能看到它们作为上下文
- 但路由决策只看当前轮，纯文本追问回到主模型
- 主模型收到含 `[IMAGE:]` 标记的历史消息时是否会报错？需要确认 `prepare_messages_for_provider()` 对非 vision provider 的行为

**方案 B：vision 处理后清除历史中的图片标记**

在 vision_provider 处理完成后，将历史中的 `[IMAGE:xxx]` 标记替换为文本描述（如 `[图片已由视觉模型处理]`）或直接剥离。这样下次迭代/下条消息时 `count_image_markers` 返回 0，自然回到主模型。

需要评估的影响：
- 如果用户追问"再看看那张图"，图片信息已丢失
- 需要决定替换策略：完全剥离 vs 留占位文本

**推荐**：方案 A 更简单且保留完整上下文。方案 B 可作为补充优化。

### 期望行为（改动一 + 改动二后）

| 步骤 | 用户消息 | 当前消息有图片? | 使用的模型 |
|---|---|---|---|
| 1 | "描述这张图" + `[IMAGE:xxx]` | 有 | mimo-v2-omni |
| 2 | "继续分析"（纯文本） | 无 | **mimo-v2-pro** |
| 3 | 再发一张图 + `[IMAGE:yyy]` | 有 | mimo-v2-omni |
| 4 | "总结一下"（纯文本） | 无 | **mimo-v2-pro** |

---

## 相关代码位置

| 组件 | 文件 | 行号 |
|---|---|---|
| vision 路由触发条件 | `src/agent/loop_.rs` | 2413-2414 |
| vision provider 创建与替换 | `src/agent/loop_.rs` | 2416-2454 |
| image marker 计数 | `src/multimodal.rs` | 88-94 |
| image marker 解析 | `src/multimodal.rs` | 53-86 |
| `custom:` provider 创建（vision=true） | `src/providers/mod.rs` | 1567-1579 |
| `OpenAiCompatibleProvider` 构造 | `src/providers/compatible.rs` | 64-189 |
| `OpenAiProvider` 构造 | `src/providers/openai.rs` | 178-193 |
| `ProviderCapabilities` 默认值 | `src/providers/traits.rs` | 272-284, 313-314 |
| 流式输出判断 | `src/agent/loop_.rs` | 2515-2517 |
| multimodal 消息预处理 | `src/multimodal.rs` | `prepare_messages_for_provider()` |
| stale image 自愈 | `src/channels/mod.rs` | 1403-1504 |
| config schema（MultimodalConfig） | `src/config/schema.rs` | 1628-1676 |

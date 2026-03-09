# ScopedMemory 待办事项

v1 已实现 `ScopedMemory` wrapper（`src/memory/scope.rs`），通过 storage_key 编码实现跨 scope 隔离。以下是 v1 未覆盖的已知问题。

## 未覆盖的场景

### CLI 交互模式

`Agent::from_config()` 构造时无 `session_id`，CLI 模式下 memory 未包装 ScopedMemory。

待办：启动时生成会话 scope，`/new` 指令时换新 scope。

### GitHub channel

GitHub webhook 场景缺少 scope_id 来源设计，保持原行为。

### BlueBubbles channel

同 GitHub，需设计 scope_id 来源。

## 已知限制

- `count()` 返回全局计数，非当前 scope 计数（因 `list()` 有 1000 条上限无法精确统计）
- `pushurl` 等非语义状态仍走 memory，后续应迁移到专用存储
- 不支持的后端（markdown / lucid / cortex-mem）降级为 warn + unscoped，不会阻断服务

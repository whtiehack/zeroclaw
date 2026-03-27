## 合并记录模板

> 复制本文件为 `master-sync-YYYY-MM-DD-HHMMSS.md`，填写后提交到 `docs/master_wecom/`。

# `master_wecom` 同步 `master` 记录（`YYYY-MM-DD-HHMMSS`）

更新时间：`YYYY-MM-DD`

## 1. 同步结果

| 项目 | 值 |
| --- | --- |
| 当前工作分支 | `master_wecom` |
| 记录时间 | `YYYY-MM-DD` |
| 同步前 `master_wecom` HEAD | `commit_hash` |
| 同步前 `master_wecom` HEAD 主题 | `subject` |
| 本次合入的 `master` HEAD | `commit_hash` |
| 本次合入的 `master` HEAD 主题 | `subject` |
| 本次 merge commit | `commit_hash` |
| 上次合入的 `master` 基线 | `commit_hash` |
| 本次新增吸收的上游提交数 | `N` |

## 2. 上游变更摘要

本次吸收的上游 commit range：`上次基线..本次master HEAD`

### trait / 公共接口变动

- （检查 `src/**/traits.rs` 是否有直接签名变化）
- （如无直接 trait 变化，也要写明是否存在 config / session / gateway / channel runtime 等隐性契约变化）

### 框架层新增能力

- （按 `agent` / `channels` / `memory` / `tools` / `gateway` / `session` 等主题归纳）
- （说明哪些能力可直接复用，哪些需要 `master_wecom` 手工适配）

### 其它 channel 更新

- （列出其它 channel 新增的用户可见功能或重要修复）
- （优先记录对 `wecom_ws` 有参考价值的改动）

### 对 `wecom_ws` 的影响

- （是否有直接接口破坏）
- （哪些公共层变化会影响现有 `wecom_ws` 语义）
- （哪些本地补丁可能被上游覆盖、弱化或变成冗余）
- （哪些配置项或行为存在冲突风险）

### Bug 修复 / 行为变化

- （列出与本分支实际相关的修复和行为变化）

### 与 branch-features.md 重叠的条目

- （如果上游新增了与分支独有功能类似的实现，在此标注并说明区别）
- （无重叠则写"无"）

### Merge 热点

- （列出本次最可能冲突的公共层文件）
- （说明原因：语义重叠、同文件热点、配置重名、行为覆盖等）

## 3. 冲突与处理

本次实际冲突文件：

- （列出冲突文件）

处理说明：

- （每个冲突文件的处理方式和原因）

## 4. Merge 后额外修正

- （如需额外修正才能通过测试，在此记录）
- （无则写"无"）

## 5. 验证结果

- `cargo fmt --all -- --check`：
- `cargo test`：

## 6. 后续注意事项

- （本次合并后需要注意的事项）

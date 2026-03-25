# 合并记录模板

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

### 新增功能

- （列出上游新增的功能，每条简要说明）

### Bug 修复

- （列出上游修复的 Bug）

### 破坏性变更 / 行为变化

- （列出可能影响现有行为的改动）

### 重构

- （列出重大重构）

### 依赖更新

- （列出重要的依赖变化）

### 与 branch-features.md 重叠的条目

- （如果上游新增了与分支独有功能类似的实现，在此标注并说明区别）
- （无重叠则写"无"）

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

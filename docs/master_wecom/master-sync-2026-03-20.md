# `master_wecom` 同步 `master` 记录（`2026-03-20`）

更新时间：`2026-03-20`

## 1. 目的

记录一次 `master_wecom` 合并 `master` 前的分支状态，方便后续回看：

- 本次同步前 `master_wecom` 自身位于哪个提交。
- 本次准备合入的 `master` 基线是哪个提交。
- 这次同步前，`master_wecom` 最近新增了什么本地改动。

## 2. 同步基线

| 项目 | 值 |
| --- | --- |
| 当前工作分支 | `master_wecom` |
| 记录时间 | `2026-03-20` |
| 同步前 `master_wecom` HEAD | `cfb24f57` |
| 同步前 `master_wecom` HEAD 主题 | `fix(wecom_ws): fallback after expired stream updates` |
| 目标 `master` HEAD | `b4a2afb0` |
| 目标 `master` HEAD 主题 | `feat(tools): add text browser tool for headless environments (#4031)` |
| `master_wecom` 与 `master` 当前共同祖先 | `2e48cbf7c309` |

说明：

- 本地 `master` 当前跟随 `upstream/master`。
- 本次同步语境里的“合并 `master`”指把当前 `master` 的最新状态合入 `master_wecom`。

## 3. 同步前本地分支最新增量

本次同步前，`master_wecom` 最新的分支侧提交是：

- `2026-03-20` `cfb24f57` `fix(wecom_ws): fallback after expired stream updates`

该提交解决的问题是：

- 当 WeCom 服务端返回 `errcode=846608`，表明同一流式消息已超过约 6 分钟更新窗口时，`wecom_ws` 不再继续对旧流反复发 `aibot_respond_msg`。
- `wecom_ws` 会在本地记住该 `req_id` 已过期，后续同 `req_id` 的草稿更新、收口消息和线程消息都会退回普通消息发送。

## 4. 同步注意事项

- `docs/master_wecom/` 下的记录只服务 `master_wecom` 分支维护，不作为上游通用文档。
- 本文档必须单独提交，不能和代码修复或 merge commit 混在一起。
- 如果本次合并后出现冲突，优先保留 `master_wecom` 上已经验证通过的 `wecom_ws` 行为，再逐项吸收 `master` 的公共层更新。

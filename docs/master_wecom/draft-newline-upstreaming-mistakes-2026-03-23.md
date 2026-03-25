# 2026-03-23 draft newline 问题处理失误记录

## 背景

本次处理的是一个公共 draft 流问题，最终以上游 issue `#4348` 和 PR `#4349` 的形式提交，公开表述统一使用 `telegram` 作为示例对象。

这次虽然最终把代码、验证、提单和 PR 都处理完了，但过程中有几处操作不够稳，应该记录下来，避免再次重复。

## 失误 1：把多个 `cargo` 任务并行跑，制造了无意义的锁等待

### 发生了什么

- 在同一工作树里并行启动了多个 `cargo test` / `cargo fmt`。
- 结果大量时间消耗在 package cache / artifact directory 锁等待上，而不是实际验证。

### 为什么不对

- `cargo` 在同一 target/cache 上天然会争锁。
- 这种并行不会提升吞吐，反而会让日志变乱，增加误判和等待时间。

### 这次如何收口

- 中断了并行思路，改成顺序执行验证命令。

### 下次规则

- 同一工作树里的 `cargo fmt`、`cargo clippy`、`cargo test` 默认顺序执行。
- 只有在明确拆分了 target dir 或 worktree，且确认不会互相争锁时，才允许并行。

## 失误 2：写 channel 级回归测试时，先入为主地假设会进入 `⏳` 状态

### 发生了什么

- 一开始给 Telegram draft 路径补回归测试时，断言写成了中间说明文本后面会紧跟 `⏳ mock_price`。
- 实际测试环境是 non-interactive approval，工具在该路径下先被自动拒绝，收到的是 `❌ mock_price: Denied by user.`。

### 为什么不对

- 测试先假设了“工具一定开始执行”，没有先确认当前夹具下 approval 行为。
- 这让断言验证的是错误的细节，而不是问题本身。

### 这次如何收口

- 重新收敛问题定义，只验证“说明文本和后续 tool status 行必须分开”，不把断言绑定到某一种 status emoji。
- 最终上游 PR 没带这段 channel 级测试，只保留了更贴近上游当前逻辑的公共层修复与测试。

### 下次规则

- 先确认测试夹具里的 approval / runtime 行为，再写 status 相关断言。
- 优先断言“用户可见的不变量”，少断言容易被测试环境细节改变的中间状态。

## 失误 3：`git cherry-pick --continue` 没有提前强制非交互，导致 git 进程挂住

### 发生了什么

- 在 PR 分支处理 cherry-pick 冲突后，直接执行了 `git cherry-pick --continue`。
- git 打开编辑器流程，但当前执行环境不适合交互，最终留下一个挂住的 git 进程。

### 为什么不对

- 本仓库工作流已经明确应优先使用非交互 git 命令。
- 这类步骤本该提前用 `GIT_EDITOR=true` 或等价方式规避。

### 这次如何收口

- 先杀掉挂住的 git 进程，再用 `GIT_EDITOR=true git cherry-pick --continue` 完成提交。

### 下次规则

- 所有 `git commit`、`git cherry-pick --continue`、`git rebase --continue` 一类命令，默认都要先考虑非交互形式。
- 只要命令存在打开编辑器的可能，就不要直接裸跑。

## 失误 4：对 PR 分支全量测试失败的归因，先说得太快

### 发生了什么

- PR 分支 `cargo test` 首次全量运行时，失败了两个测试：
  - `config::schema::tests::load_or_init_uses_persisted_active_workspace_marker`
  - `security::policy::tests::workspace_only_false_allows_resolved_outside_workspace`
- 当时我先把它们都笼统归为“与本次改动无关的上游噪声”。

### 为什么不对

- “无关”不等于“同样能在纯 upstream/master 复现”。
- 在没有做 isolated rerun 和 baseline 对照前，不应该把两个失败混成一个结论。

### 这次如何收口

- 额外建了纯 `upstream/master` worktree 做对照。
- 结果确认：
  - `config::schema::tests::load_or_init_uses_persisted_active_workspace_marker` 在纯 `upstream/master` 也会失败。
  - `security::policy::tests::workspace_only_false_allows_resolved_outside_workspace` 在纯 `upstream/master` 单测隔离下是通过的，在 PR 分支单测隔离下也通过。

### 下次规则

- 遇到“全量测试里有与当前 diff 无关的失败”时，必须拆成三步：
  1. 先看失败模块是否在当前 diff 里。
  2. 再做 isolated rerun。
  3. 必要时用纯 upstream/master worktree 做 baseline 对照。
- 在这三步做完前，不要提前下统一归因结论。

## 后续固定做法

- `cargo` 系列命令默认顺序跑。
- 带编辑器风险的 git 命令默认非交互。
- 测试断言先围绕问题本体写，不先绑定某个环境特定中间状态。
- 对全量测试失败，先隔离、再对照、最后归因。

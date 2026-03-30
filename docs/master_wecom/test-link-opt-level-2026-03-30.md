# macOS x86_64 test link / opt-level 记录

更新时间：`2026-03-30`

## 现象

在当前机器：

- `macOS 12.7.4`
- `x86_64`
- Rust test 二进制

执行：

```bash
cargo test providers::reliable::tests --lib --no-run
```

会在链接阶段失败，报一组 `Undefined symbols for architecture x86_64`，并带有 Rust 匿名符号 `_anon...llvm...` / `serde_spanned` 相关栈迹。

## 一开始的误判

一开始把问题过早归因为：

- Xcode / Command Line Tools 太旧
- 当前机器整体已经无法正常链接 Rust test 二进制

这个判断不严谨，后续排查证明它不成立。

## 实际排查结果

先做最小化验证：

1. 空白最小 crate：
   - `cargo test --no-run` 可以正常链接
2. 只带 `serde_spanned` 的最小 crate：
   - `cargo test --no-run` 也可以正常链接
3. 带 `opt-level = 1` 的最小 crate：
   - 仍然可以正常链接

说明：

- 当前机器不是“所有 Rust test 链接都坏了”
- 当前工具链也不是完全不可用

继续对本仓库做 A/B：

1. 默认配置下：
   - test 构建会吃到 `dev` 的 `opt-level = 1`
   - `cargo test ... --no-run` 链接失败
2. 临时改成：

```bash
CARGO_PROFILE_TEST_OPT_LEVEL=0 cargo test providers::reliable::tests --lib --no-run
```

结果：

- test 二进制能正常链接通过

因此当前结论是：

- 这个问题是“本仓库 test 构建 + 当前环境 + `opt-level = 1`”的组合问题
- 不是“当前机器完全不能编 Rust”

## 本次修复

在 [`Cargo.toml`](../../Cargo.toml) 中显式加：

```toml
[profile.test]
opt-level = 0
```

目的：

- 保持普通 `dev` 构建不变
- 只让 test 二进制回到未优化构建
- 避免再次出现链接阶段的不稳定行为

## 验证

修复后执行：

```bash
cargo test providers::reliable::tests --lib --no-run
```

结果：

- 链接通过
- 输出 `Finished 'test' profile [unoptimized + debuginfo]`

## 下次排查规则

以后再遇到类似“Rust test 链接失败”时，先按下面顺序排：

1. 先验证空白最小 crate 能不能 `cargo test --no-run`
2. 再验证项目问题能不能被 `CARGO_PROFILE_TEST_OPT_LEVEL=0` 消掉
3. 只有在最小 crate 也失败时，才把问题归因为系统级 Xcode / linker 故障

禁止再直接把这类问题先判断成“当前机器整体不能 link Rust”。

# unidbg-br-deobfuscator

用 **Unidbg** 做轻量“模拟执行”，自动解析 **CSEL-BR**（`br xN` 间接跳转）并批量替换为直跳，恢复可读 CFG / 伪代码。

## 特性

- 自动发现 `br xN` 与上游 `csel/cmp` 相关块
- 运行时取寄存器真实落点，生成 `b`/`bl` 补丁
- 一键批量 Patch（导出 IDA/IDAPython/JSON 方案）

## 原理

用 Unidbg 驱动真假分支到 `br` 点，读出 `xN` 真实目标，静态回写直跳，清理跳板块。




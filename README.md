# cvby-venus-zyprobe

venus（小米 11 / Android 16 / kernel 5.4.302）上的**内核辅助 ptrace 注入**验证模块。

## 它做什么

只做一件事：在 `security_ptrace_access_check()` 被 LSM（SELinux）拒绝时，
对「调用者 uid==0 且 目标 pid==target_pid」的调用强制放行。

目的：验证「注入器的权限与隐瞒下沉到内核、注入逻辑留在用户态（ZygiskNext）」这条路线是否成立。

## 设计约束

- 不做任何隐藏（TracerPid / maps 过滤留给 hide.ko）
- 不改 su、不动 hook 链
- 卸载后无残留（kretprobe 单点，unregister 干净）
- 默认最小权限：只对 uid 0 放行，`allow_any_uid=0`

## 编译

必须与**设备实际运行的内核**同源同工具链，否则 CONFIG_MODVERSIONS 拒绝加载：

```bash
make -C <kernel-src> O=<out> M=$PWD/modules/zyprobe modules
```

产物：`modules/zyprobe/zyprobe.ko`

## 测试

```bash
insmod zyprobe.ko target_pid=$(pidof zygote64)
dmesg | grep zyprobe
rmmod zyprobe
```

## 已知风险

- `security_ptrace_access_check` 若被 LTO inline，`register_kretprobe` 会失败（-EINVAL），需换 hook 点
- 这是**安全后门级**原语：放行后任何 uid 0 进程可 ptrace 目标，必须严格限定 target_pid
- 仅用于研究验证，不要在生产环境长驻

## 路线背景

- 1 内核辅助 ptrace（本仓库，验证中）
- 2 uprobes 注入（CONFIG_UPROBES=y，研究阶段）
- 3 从零写注入引擎（不做）
- 4 纯 syscall hook（不兼容 LSPosed）

License: GPL-2.0-only

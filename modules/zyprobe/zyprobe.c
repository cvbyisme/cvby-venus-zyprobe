// SPDX-License-Identifier: GPL-2.0-only
/*
 * zyprobe.c - 最小验证模块
 *
 * 目的：验证「内核辅助 ptrace」路线是否可行。
 * 只做一件事：在 security_ptrace_access_check() 返回非 0（被 LSM 拒绝）时，
 * 对「调用者 uid==0 且 目标 pid==target_pid」的调用强制放行。
 *
 * 不做任何隐藏、不改 su、不动 hook 链，卸载后无残留。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

#define TAG "zyprobe: "

/* 只对指定 pid 放行；-1 = 不限目标（仅用于测试） */
static int target_pid = -1;
module_param(target_pid, int, 0444);
MODULE_PARM_DESC(target_pid, "Only bypass when child pid == this (-1 = any)");

/* 是否允许非 root 调用者（默认 false，保持最小权限） */
static bool allow_any_uid;
module_param(allow_any_uid, bool, 0444);
MODULE_PARM_DESC(allow_any_uid, "Also bypass for non-root callers (dangerous)");

struct probe_data {
	pid_t child_pid;
	kuid_t caller_uid;
};

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *d = (struct probe_data *)ri->data;
	struct task_struct *child = (struct task_struct *)regs->regs[0];

	d->child_pid = child ? child->pid : -1;
	d->caller_uid = current_uid();
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct probe_data *d = (struct probe_data *)ri->data;
	long ret = regs_return_value(regs);

	if (ret == 0)
		return 0;

	if (!allow_any_uid && d->caller_uid.val != 0)
		return 0;

	if (target_pid >= 0 && d->child_pid != target_pid)
		return 0;

	regs_set_return_value(regs, 0);

	if (printk_ratelimited())
		pr_info(TAG "bypass uid=%d -> pid=%d (was %ld)\n",
			d->caller_uid.val, d->child_pid, ret);

	return 0;
}

static struct kretprobe kp = {
	.kp.symbol_name = "security_ptrace_access_check",
	.entry_handler = entry_handler,
	.ret_handler = ret_handler,
	.data_size = sizeof(struct probe_data),
	.maxactive = 64,
};

static int __init zyprobe_init(void)
{
	int ret;

	ret = register_kretprobe(&kp);
	if (ret < 0) {
		pr_err(TAG "register_kretprobe failed: %d\n", ret);
		return ret;
	}

	pr_info(TAG "loaded target_pid=%d allow_any_uid=%d\n",
		target_pid, allow_any_uid);
	return 0;
}

static void __exit zyprobe_exit(void)
{
	unregister_kretprobe(&kp);
	pr_info(TAG "unloaded\n");
}

module_init(zyprobe_init);
module_exit(zyprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Minimal ptrace-SELinux bypass kretprobe (verification only)");
MODULE_VERSION("0.1.0");

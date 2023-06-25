// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch-sample.c - Kernel Live Patching Sample Module
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

/*
 * This (dumb) live patch overrides the function that prints the
 * kernel boot cmdline when /proc/cmdline is read.
 *
 * Example:
 *
 * $ cat /proc/cmdline
 * <your cmdline>
 *
 * $ insmod livepatch-sample.ko
 * $ cat /proc/cmdline
 * this has been live patched
 *
 * $ echo 0 > /sys/kernel/livepatch/livepatch_sample/enabled
 * $ cat /proc/cmdline
 * <your cmdline>
 */
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/bpf_trace.h>
#include <linux/bpf_lirc.h>
#include <linux/bpf_verifier.h>
#include <linux/bsearch.h>
#include <linux/btf.h>
#include <linux/syscalls.h>

BPF_CALL_4(bpf_kallsyms_lookup_name, const char *, name, int, name_sz, int, flags, u64 *, res)
{
	if (flags)
		return -EINVAL;

	if (name_sz <= 1 || name[name_sz - 1])
		return -EINVAL;

	if (!bpf_dump_raw_ok(current_cred()))
		return -EPERM;

	*res = kallsyms_lookup_name(name);
	return *res ? 0 : -ENOENT;
}

static const struct bpf_func_proto bpf_kallsyms_lookup_name_proto = {
	.func		= bpf_kallsyms_lookup_name,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_LONG,
};

static const struct bpf_func_proto *
sysctl_func_proto_new(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	const struct bpf_func_proto *func_proto;

	func_proto = cgroup_common_func_proto(func_id, prog);
	if (func_proto)
		return func_proto;

	func_proto = cgroup_current_func_proto(func_id, prog);
	if (func_proto)
		return func_proto;

	switch (func_id) {
	case BPF_FUNC_kallsyms_lookup_name:
		return &bpf_kallsyms_lookup_name_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static struct klp_func funcs[] = {
	{
		.old_name = "sysctl_func_proto",
		.new_func = sysctl_func_proto_new,
	}
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int livepatch_init(void)
{
	return klp_enable_patch(&patch);
}

static void livepatch_exit(void)
{
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");

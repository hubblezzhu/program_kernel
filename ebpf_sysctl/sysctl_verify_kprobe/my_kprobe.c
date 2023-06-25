#include <linux/kprobes.h>
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


static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t my_kallsyms_lookup_name;
unsigned long addr;

#define KSYM_NAME "cg_sysctl_verifier_ops"

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


static int my_kprobes_init(void)
{
    printk("My kprobes is starting。。。\n");

    register_kprobe(&kp);
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    addr = my_kallsyms_lookup_name(KSYM_NAME);	/* 获取系统调用服务首地址 */
    printk("%s: %lx\n", KSYM_NAME, addr);

/*
const struct bpf_verifier_ops cg_sysctl_verifier_ops = {
	.get_func_proto		= sysctl_func_proto,
	.is_valid_access	= sysctl_is_valid_access,
	.convert_ctx_access	= sysctl_convert_ctx_access,
};
*/

    printk("Before set\n");

    struct bpf_verifier_ops *ops = (struct bpf_verifier_ops *)addr;
    ops->get_func_proto = sysctl_func_proto_new;

    printk("Update %s success\n", KSYM_NAME);

    return 0;
}

static void my_kprobes_exit(void)
{
    printk("My kprobes exit....\n");
}

module_init(my_kprobes_init);
module_exit(my_kprobes_exit);
MODULE_LICENSE("GPL");

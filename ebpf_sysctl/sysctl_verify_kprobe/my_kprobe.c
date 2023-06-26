#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf-cgroup.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/stringify.h>
#include <linux/bsearch.h>
#include <linux/sort.h>
#include <linux/perf_event.h>
#include <linux/ctype.h>
#include <linux/error-injection.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include <linux/poison.h>

#define CODESIZE 12

static unsigned char original_code[CODESIZE];
static unsigned char jump_code[CODESIZE] =
    "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00" /* movq $0, %rax */
    "\xff\xe0"                                          /* jump *%rax */
        ;


/* FILL THIS IN YOURSELF */
int (*real_printk)( char * fmt, ... ) = (int (*)(char *,...) )0xffffffff805e5f6e;

int hijack_start(void);
void hijack_stop(void);
void intercept_init(void);
void intercept_start(void);
void intercept_stop(void);
int fake_printk(char *, ... );


// const struct bpf_func_proto *
// cgroup_common_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
// {
// 	switch (func_id) {
// 	case BPF_FUNC_get_local_storage:
// 		return &bpf_get_local_storage_proto;
// 	case BPF_FUNC_get_retval:
// 		switch (prog->expected_attach_type) {
// 		case BPF_CGROUP_INET_INGRESS:
// 		case BPF_CGROUP_INET_EGRESS:
// 		case BPF_CGROUP_SOCK_OPS:
// 		case BPF_CGROUP_UDP4_RECVMSG:
// 		case BPF_CGROUP_UDP6_RECVMSG:
// 		case BPF_CGROUP_INET4_GETPEERNAME:
// 		case BPF_CGROUP_INET6_GETPEERNAME:
// 		case BPF_CGROUP_INET4_GETSOCKNAME:
// 		case BPF_CGROUP_INET6_GETSOCKNAME:
// 			return NULL;
// 		default:
// 			return &bpf_get_retval_proto;
// 		}
// 	case BPF_FUNC_set_retval:
// 		switch (prog->expected_attach_type) {
// 		case BPF_CGROUP_INET_INGRESS:
// 		case BPF_CGROUP_INET_EGRESS:
// 		case BPF_CGROUP_SOCK_OPS:
// 		case BPF_CGROUP_UDP4_RECVMSG:
// 		case BPF_CGROUP_UDP6_RECVMSG:
// 		case BPF_CGROUP_INET4_GETPEERNAME:
// 		case BPF_CGROUP_INET6_GETPEERNAME:
// 		case BPF_CGROUP_INET4_GETSOCKNAME:
// 		case BPF_CGROUP_INET6_GETSOCKNAME:
// 			return NULL;
// 		default:
// 			return &bpf_set_retval_proto;
// 		}
// 	default:
// 		return NULL;
// 	}
// }

// /* Common helpers for cgroup hooks with valid process context. */
// const struct bpf_func_proto *
// cgroup_current_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
// {
// 	switch (func_id) {
// 	case BPF_FUNC_get_current_uid_gid:
// 		return &bpf_get_current_uid_gid_proto;
// 	case BPF_FUNC_get_current_pid_tgid:
// 		return &bpf_get_current_pid_tgid_proto;
// 	case BPF_FUNC_get_current_comm:
// 		return &bpf_get_current_comm_proto;
// 	case BPF_FUNC_get_current_cgroup_id:
// 		return &bpf_get_current_cgroup_id_proto;
// 	case BPF_FUNC_get_current_ancestor_cgroup_id:
// 		return &bpf_get_current_ancestor_cgroup_id_proto;
// #ifdef CONFIG_CGROUP_NET_CLASSID
// 	case BPF_FUNC_get_cgroup_classid:
// 		return &bpf_get_cgroup_classid_curr_proto;
// #endif
// 	default:
// 		return NULL;
// 	}
// }

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

// long unsigned int *real_sysctl_func_proto = 0xffff800008391180;
const struct bpf_func_proto *
real_sysctl_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog) = \
(struct bpf_func_proto (*)(enum bpf_func_id, const struct bpf_prog *))0xffff800008441614;

const struct bpf_func_proto *
fake_sysctl_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	// struct bpf_func_proto *func_proto;

	// func_proto = cgroup_common_func_proto(func_id, prog);
	// if (func_proto)
	// 	return func_proto;

	// func_proto = cgroup_current_func_proto(func_id, prog);
	// if (func_proto)
	// 	return func_proto;

	switch (func_id) {
	// case BPF_FUNC_sysctl_get_name:
	// 	return &bpf_sysctl_get_name_proto;
	// case BPF_FUNC_sysctl_get_current_value:
	// 	return &bpf_sysctl_get_current_value_proto;
	// case BPF_FUNC_sysctl_get_new_value:
	// 	return &bpf_sysctl_get_new_value_proto;
	// case BPF_FUNC_sysctl_set_new_value:
	// 	return &bpf_sysctl_set_new_value_proto;
	// case BPF_FUNC_ktime_get_coarse_ns:
	// 	return &bpf_ktime_get_coarse_ns_proto;
	// case BPF_FUNC_perf_event_output:
	// 	return &bpf_event_output_data_proto;
	// case BPF_FUNC_kallsyms_lookup_name:
	case 178:
		return &bpf_kallsyms_lookup_name_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}



int hijack_start()
{
    printk("hijack start \n" );
    intercept_init();
    intercept_start();

    return 0;
}

void hijack_stop()
{
    printk("hijack stop \n" );
    intercept_stop();
    return;
}

void intercept_init()
{
    // *(long *)&jump_code[2] = (long)fake_printk;
    // memcpy( original_code, real_printk, CODESIZE );

    *(long *)&jump_code[2] = (long)fake_sysctl_func_proto;
    memcpy( original_code, real_sysctl_func_proto, CODESIZE );

    return;
}

void intercept_start()
{
    // memcpy( real_printk, jump_code, CODESIZE );
    memcpy( real_sysctl_func_proto, jump_code, CODESIZE );
}

void intercept_stop()
{
    // memcpy( real_printk, original_code, CODESIZE );
    memcpy( real_sysctl_func_proto, original_code, CODESIZE );
}

int fake_printk( char *fmt, ... )
{
    int ret;
    intercept_stop();
    ret = real_printk(KERN_INFO "Someone called printk\n");
    intercept_start();
    return ret;
}

module_init( hijack_start );
module_exit( hijack_stop );
MODULE_LICENSE("GPL");

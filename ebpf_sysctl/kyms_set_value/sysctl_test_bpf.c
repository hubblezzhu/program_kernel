// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <stdint.h>
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#ifndef memcpy
#define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

/* Max supported length of a string with unsigned long in base 10 (pow2 - 1). */
#define MAX_ULONG_STR_LEN 0xF

/* Max supported length of sysctl value string (pow2). */
#define MAX_VALUE_STR_LEN 0x40

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

const char symbol_name[] = "sysctl_tcp_mem111";

SEC("cgroup/sysctl")
int sysctl_test(struct bpf_sysctl *ctx)
{
    unsigned long target_tcp_mem[3] = {117015, 156022, 234031};
    volatile int ret;
    int name_size = 0;

    bpf_printk("Entering sysctl ebpf hook...\n");
    if (!ctx->write)
        return 0;

    // if (!is_tcp_mem(ctx))
    //     return 0;

//     ret = bpf_sysctl_get_current_value(ctx, value, MAX_VALUE_STR_LEN);
//     if (ret < 0 || ret >= MAX_VALUE_STR_LEN)
//         return 0;

// #pragma clang loop unroll(full)
//     for (i = 0; i < ARRAY_SIZE(tcp_mem); ++i) {
//         ret = bpf_strtoul(value + off, MAX_ULONG_STR_LEN, 0,
//                   tcp_mem + i);
//         if (ret <= 0 || ret > MAX_ULONG_STR_LEN)
//             return 0;
//         off += ret & MAX_ULONG_STR_LEN;
//     }

//     return tcp_mem[0] < tcp_mem[1] && tcp_mem[1] < tcp_mem[2];

    bpf_printk("start set ksyms value.\n");
    name_size = sizeof(symbol_name) / sizeof(char);
    ret = bpf_kyms_set_value(symbol_name, name_size, (char *)target_tcp_mem, sizeof(long) * 3);
    if (ret < 0) {
        bpf_printk("bpf_kyms_set_value failed. error %d\n", ret);
        return 0;
    }

    bpf_printk("ksyms value set down.\n");

    return 0;
}


char _license[] SEC("license") = "GPL";

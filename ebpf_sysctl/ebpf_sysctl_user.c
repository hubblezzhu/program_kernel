#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/filter.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf/bpf_endian.h>


struct sysctl_prog {
    const char *descr;
    const char *prog_file;
    enum bpf_attach_type attach_type;
    const char *sysctl;
};

struct sysctl_prog sysctl_simple =
{
    "C prog: read tcp_mem",
    .prog_file = "./ebpf_sysctl.o",
    .attach_type = BPF_CGROUP_SYSCTL,
    .sysctl = "net/ipv4/tcp_mem",
}

static int load_sysctl_prog_file(struct sysctl_prog *prog)
{
    static struct bpf_insn insns[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };
    size_t insns_cnt = ARRAY_SIZE(insns);

    LIBBPF_OPTS(bpf_prog_load_opts, opts,
        .log_buf = bpf_log_buf,
        .log_size = BPF_LOG_BUF_SIZE,
    );

    struct bpf_object *obj;
    int prog_fd;

    int ret = 0;
    ret = bpf_prog_load(BPF_PROG_TYPE_CGROUP_SYSCTL, prog->prog_file, "GPL",
                     insns, insns_cnt, &opts);
    if (ret != 0) {
        printf(">>> Loading program (%s) error.\n", test->prog_file);
    }

    return prog_fd;
}

int main()
{
    int ret;
    ret = load_sysctl_prog_file(&sysctl_simple);
    if (ret == 0) {
        printf("Load sysctl prog failed.\n");
    }

    return 0;
}
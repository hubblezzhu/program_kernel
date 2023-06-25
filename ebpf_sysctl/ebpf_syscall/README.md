

clang -g -O2 -target bpf  -I/usr/include/bpf -I. -c  ebpf_syscall.c -o  ebpf_syscall.o


bpftool prog load ebpf_syscall.o /sys/fs/bpf/ebpf_syscall type cgroup_sysctl

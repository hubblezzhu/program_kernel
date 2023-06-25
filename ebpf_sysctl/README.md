

clang -g -O2 -target bpf  -I/usr/include/bpf -I. -c  sysctl_test_bpf.c -o  sysctl_test_bpf.o


bpftool prog load sysctl_test_bpf.o /sys/fs/bpf/sysctl_test type cgroup_sysctl

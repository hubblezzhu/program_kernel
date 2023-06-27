

clang -g -Wall -O2 -Werror  --target=bpf -D__x86_64__ -fPIC -D_FORTIFY_SOURCE=2 -ftrapv -I/usr/include/bpf -I. -c  sysctl_test_bpf.c -o  sysctl_test_bpf.o

bpftool prog load sysctl_test_bpf.o /sys/fs/bpf/sysctl_test type cgroup/sysctl

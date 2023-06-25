



### compile

clang -g -O2 -target bpf  -I/usr/include/bpf -I. -c  sockmap_bpf.c -o  sockmap_bpf.o
clang -g -O2 -target bpf  -I/usr/include/bpf -I. -c  sockredir_bpf.c -o  sockredir_bpf.o

### install

bpftool prog load sockmap_bpf.o /sys/fs/bpf/sockops type sockops pinmaps /sys/fs/bpf
bpftool cgroup attach /sys/fs/cgroup/ sock_ops pinned /sys/fs/bpf/sockops

bpftool prog load sockredir_bpf.o /sys/fs/bpf/sockredir type sk_msg map name sock_ops_map pinned /sys/fs/bpf/sock_ops_map
bpftool prog attach pinned /sys/fs/bpf/sockredir msg_verdict pinned /sys/fs/bpf/sock_ops_map

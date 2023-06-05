#include <linux/bpf.h>

struct sock_key
{
    __u32 sip;    //源IP
    __u32 dip;    //目的IP
    __u32 sport;  //源端口
    __u32 dport;  //目的端口
    __u32 family; //协议
};


struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} sock_ops_map SEC(".maps");



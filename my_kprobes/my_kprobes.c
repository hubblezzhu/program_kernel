
#include <linux/kprobes.h>

#define KSYM_NAME "sysctl_tcp_mem"

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t my_kallsyms_lookup_name;
unsigned long addr;

long target_tcp_mem[3] = {33520, 44692, 67038};

long tmp_tcp_mem[3] = {0, 0, 0};


static int my_kprobes_init(void)
{
    printk("My kprobes is starting。。。\n");

    register_kprobe(&kp);
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    addr = my_kallsyms_lookup_name(KSYM_NAME);	/* 获取系统调用服务首地址 */
    printk("%s: %lx\n", KSYM_NAME, addr);

    printk("Before set\n");
    // read current value
    memcpy(tmp_tcp_mem, (char *)addr, sizeof(long) * 3);

    printk("tcp_mem 0: %ld\n", tmp_tcp_mem[0]);
    printk("tcp_mem 1: %ld\n", tmp_tcp_mem[1]);
    printk("tcp_mem 2: %ld\n", tmp_tcp_mem[2]);

    // write new value
    memcpy((char *)addr, (char *)target_tcp_mem, sizeof(long) * 3);

    printk("After set\n");
    // read new value
    memcpy(tmp_tcp_mem, (char *)addr, sizeof(long) * 3);

    printk("tcp_mem 0: %ld\n", tmp_tcp_mem[0]);
    printk("tcp_mem 1: %ld\n", tmp_tcp_mem[1]);
    printk("tcp_mem 2: %ld\n", tmp_tcp_mem[2]);

    return 0;
}

static void my_kprobes_exit(void)
{
    printk("My kprobes exit....\n");
}

module_init(my_kprobes_init);
module_exit(my_kprobes_exit);
MODULE_LICENSE("GPL");

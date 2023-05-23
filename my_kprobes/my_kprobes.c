// #include <linux/module.h>
// #include <linux/kernel.h>
// #include <linux/init.h>
// #include <linux/unistd.h>
#include <linux/kprobes.h>

#define KSYM_NAME "sys_call_table"

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t my_kallsyms_lookup_name;
unsigned long addr;

static int my_kprobes_init(void)
{
    printk("My kprobes is starting。。。\n");

    register_kprobe(&kp);
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    addr = my_kallsyms_lookup_name(KSYM_NAME);	/* 获取系统调用服务首地址 */
    printk("%s: %lx\n", KSYM_NAME, addr);

    return 0;

}

static void my_kprobes_exit(void)
{
    printk("My kprobes exit....\n");
}

module_init(my_kprobes_init);
module_exit(my_kprobes_exit);
MODULE_LICENSE("GPL");

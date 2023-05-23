#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>


#define KSYM_NAME "sys_call_table"

unsigned long addr;

static int my_kallsyms_init(void)
{
    printk("My kallsyms is starting。。。\n");
    addr = kallsyms_lookup_name(KSYM_NAME);
    printk("%s: %lx\n", KSYM_NAME, addr);

    return 0;
}

static void my_kallsyms_exit(void)
{
    printk("My kallsyms exit....\n");
}


module_init(my_kallsyms_init);
module_exit(my_kallsyms_exit);

MODULE_LICENSE("GPL");

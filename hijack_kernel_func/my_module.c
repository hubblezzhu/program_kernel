#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm/sysreg.h>

// 定义要替换的原始函数指针
asmlinkage long (*real_open)(const char __user *filename, int flags, umode_t mode);

asmlinkage long (*original_open)(const char __user *filename, int flags, umode_t mode);



// 替换的新函数实现
asmlinkage long my_open(const char __user *filename, int flags, umode_t mode)
{
    // 在此处添加您的新实现逻辑
    printk(KERN_INFO "My open function is called!\n");

    // 调用原始的内核 open 函数
    return original_open(filename, flags, mode);
}

static int __init my_module_init(void)
{
    // 替换原始的内核 open 函数为我们的新实现
    unsigned long cr;
    unsigned long val;

    // 使用 kallsyms_lookup_name 函数获取原始内核 open 函数的地址
    original_open = (void *)kallsyms_lookup_name("sys_open");
    real_open = (void *)kallsyms_lookup_name("sys_open");

    if (!original_open)
    {
        printk(KERN_ALERT "Failed to find the original open function.\n");
        return -1;
    }

    // 禁用内核函数只读保护
    cr = read_sysreg_s(SYS_VM_CR);
    val = cr & ~(1 << 0); // CR_EL1.WP
    write_sysreg_s(val, SYS_VM_CR);

    *((unsigned long *)original_open) = (unsigned long)my_open;

    // 启用内核函数只读保护
    write_sysreg_s(cr, SYS_VM_CR);

    printk(KERN_INFO "Module initialized successfully.\n");
    return 0;
}

static void __exit my_module_exit(void)
{
    // 恢复原始的内核 open 函数
    unsigned long cr;
    unsigned long val;

    // 禁用内核函数只读保护
    cr = read_sysreg_s(SYS_VM_CR);
    val = cr & ~(1 << 0); // CR_EL1.WP
    write_sysreg_s(val, SYS_VM_CR);

    *((unsigned long *)original_open) = (unsigned long)(*real_open);

    // 启用内核函数只读保护
    write_sysreg_s(cr, SYS_VM_CR);

    printk(KERN_INFO "Module exited.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");

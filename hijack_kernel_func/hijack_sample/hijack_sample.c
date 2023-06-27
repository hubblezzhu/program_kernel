// hijack.c
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/cpu.h>
char *stub;
char *addr = NULL;
// 可以用JMP模式，也可以用CALL模式
//#define JMP    1
// 和sample模块里同名的sample_read函数
static ssize_t sample_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    int n = 0;
    char kb[16];
    if (*ppos != 0) {
        return 0;
    }
    // 这里我们把1234的输出给fix成4321的输出
    n = sprintf(kb, "%d\n", 4321);
    memcpy(ubuf, kb, n);
    *ppos += n;
    return n;
}
// hijack_stub的作用就类似于ftrace kpatch里的ftrace_regs_caller
static ssize_t hijack_stub(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    // 用nop占位，加上C编译器自动生成的函数header代码，这么大的函数来容纳stub应该够了。
    asm ("nop; nop; nop; nop; nop; nop; nop; nop;");
    return 0;
}
#define FTRACE_SIZE       5
#define POKE_OFFSET        0
#define POKE_LENGTH        5
#define SKIP_LENGTH        8
static unsigned long *(*_mod_find_symname)(struct module *mod, const char *name);
static void *(*_text_poke_smp)(void *addr, const void *opcode, size_t len);
static struct mutex *_text_mutex;
unsigned char saved_inst[POKE_LENGTH];
struct module *mod;
static int __init hotfix_init(void)
{
    unsigned char jmp_call[POKE_LENGTH];
    unsigned char e8_skip_stack[SKIP_LENGTH];
    s32 offset, i = 5;
    mod = find_module("sample");
    if (!mod) {
        printk("没加载sample模块，你要patch个啥？\n");
        return -1;
    }
    _mod_find_symname = (void *)kallsyms_lookup_name("mod_find_symname");
    if (!_mod_find_symname) {
        printk("还没开始，就已经结束。");
        return -1;
    }
    addr = (void *)_mod_find_symname(mod, "sample_read");
    if (!addr) {
        printk("一切还没有准备好！请先加载sample模块。\n");
        return -1;
    }
    _text_poke_smp = (void *)kallsyms_lookup_name("text_poke_smp");
    _text_mutex = (void *)kallsyms_lookup_name("text_mutex");
    if (!_text_poke_smp || !_text_mutex) {
        printk("还没开始，就已经结束。");
        return -1;
    }
    stub = (void *)hijack_stub;
    offset = (s32)((long)sample_read - (long)stub - FTRACE_SIZE);
    // 下面的代码就是stub函数的最终填充，它类似于ftrace_regs_caller的作用！
    e8_skip_stack[0] = 0xe8;
    (*(s32 *)(&e8_skip_stack[1])) = offset;
#ifndef JMP    // 如果是call模式，则需要手工平衡堆栈，跳过原始函数的栈帧
    e8_skip_stack[i++] = 0x41; // pop %r11
    e8_skip_stack[i++] = 0x5b; // r11寄存器为临时使用寄存器，遵循调用者自行保护原则
#endif
    e8_skip_stack[i++] = 0xc3;
    _text_poke_smp(&stub[0], e8_skip_stack, SKIP_LENGTH);
    offset = (s32)((long)stub - (long)addr - FTRACE_SIZE);
    memcpy(&saved_inst[0], addr, POKE_LENGTH);
#ifndef JMP
    jmp_call[0] = 0xe8;
#else
    jmp_call[0] = 0xe9;
#endif
    (*(s32 *)(&jmp_call[1])) = offset;
    get_online_cpus();
    mutex_lock(_text_mutex);
    _text_poke_smp(&addr[POKE_OFFSET], jmp_call, POKE_LENGTH);
    mutex_unlock(_text_mutex);
    put_online_cpus();
    return 0;
}
static void __exit hotfix_exit(void)
{
    mod = find_module("sample");
    if (!mod) {
        printk("一切已经结束！\n");
        return;
    }
    addr = (void *)_mod_find_symname(mod, "sample_read");
    if (!addr) {
        printk("一切已经结束！\n");
        return;
    }
    get_online_cpus();
    mutex_lock(_text_mutex);
    _text_poke_smp(&addr[POKE_OFFSET], &saved_inst[0], POKE_LENGTH);
    mutex_unlock(_text_mutex);
    put_online_cpus();
}
module_init(hotfix_init);
module_exit(hotfix_exit);
MODULE_LICENSE("GPL");

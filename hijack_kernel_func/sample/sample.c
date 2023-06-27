#include <linux/module.h>
#include <linux/proc_fs.h>
// 下面的sample_read就是我将要patch的函数
static ssize_t sample_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    int n = 0;
    char kb[16];
    if (*ppos != 0) {
        return 0;
    }
    n = sprintf(kb, "%d\n", 1234);
    memcpy(ubuf, kb, n);
    *ppos += n;
    return n;
}
static struct proc_ops sample_ops = {
    // .owner = THIS_MODULE,
    .proc_read = sample_read,
};
static struct proc_dir_entry *ent;
static int __init sample_init(void)
{
    ent = proc_create("test", 0660, NULL, (struct proc_ops *)&sample_ops);
    if (!ent)
        return -1;
    return 0;
}
static void __exit sample_exit(void)
{
    proc_remove(ent);
}
module_init(sample_init);
module_exit(sample_exit);
MODULE_LICENSE("GPL");

#include "pcg.h"
#include <linux/ftrace.h>

MODULE_DESCRIPTION("Hook for getrandom()");
MODULE_LICENSE("GPL");

static asmlinkage long my_getrandom(struct pt_regs *regs) {
  long ret = regs->si;
  char *kbuf;

  if (!(kbuf = kmalloc(regs->si, GFP_KERNEL)))
    return 0;

  pcgn(kbuf, regs->si);

  if (copy_to_user((char *)regs->di, kbuf, regs->si))
    ret = 0;

  kfree(kbuf);
  return ret;
}

static void notrace callback_func(unsigned long ip, unsigned long parent_ip,
                                  struct ftrace_ops *op,
                                  struct ftrace_regs *r) {
  if (!within_module(parent_ip, THIS_MODULE)) {
    struct pt_regs *regs = ftrace_get_regs(r);
    regs->ip = (unsigned long)my_getrandom;
  }
}

static struct ftrace_ops ops = {
    .func = callback_func,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
             FTRACE_OPS_FL_IPMODIFY,
    .private = 0,
};

static int __init rk_init(void) {
  ftrace_set_filter(&ops, "__x64_sys_getrandom", 19, 0);
  return register_ftrace_function(&ops);
}

static void __exit rk_exit(void) { unregister_ftrace_function(&ops); }

module_init(rk_init);
module_exit(rk_exit);

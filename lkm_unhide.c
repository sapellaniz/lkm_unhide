#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/poison.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sergio Apellaniz");
MODULE_DESCRIPTION("Find hidden LKM Rootkits scanning memory regions between unhidden modules.");
MODULE_VERSION("1.0");

struct unhidden_modules {
  int count;
  unsigned long *address;
  int *size;
};

static struct unhidden_modules unhidden_modules = {
  .count   = 0,
  .address = NULL,
  .size    = NULL,
};

static void add_unhidden_module(unsigned long address, int size) {
  int i, pos;
  unsigned long *address_array;
  int *size_array;

  // Allocate memory for the new arrays
  address_array = kmalloc((unhidden_modules.count + 1) * sizeof(unsigned long), GFP_KERNEL);
  size_array = kmalloc((unhidden_modules.count + 1) * sizeof(int), GFP_KERNEL);

  if (!address_array || !size_array) {
    printk(KERN_ERR "[lkm_unhide] Memory allocation failed\n");
    return;
  }

  // Find the correct position to insert the new element
  for (pos = 0; pos < unhidden_modules.count; pos++) {
    if (unhidden_modules.address[pos] > address)
      break;
  }

  // Copy elements to the new arrays
  for (i = 0; i < pos; i++) {
    address_array[i] = unhidden_modules.address[i];
    size_array[i] = unhidden_modules.size[i];
  }

  address_array[pos] = address;
  size_array[pos] = size;

  for (i = pos; i < unhidden_modules.count; i++) {
    address_array[i + 1] = unhidden_modules.address[i];
    size_array[i + 1] = unhidden_modules.size[i];
  }

  // Free the old arrays
  kfree(unhidden_modules.address);
  kfree(unhidden_modules.size);

  // Update the struct with the new arrays
  unhidden_modules.address = address_array;
  unhidden_modules.size = size_array;
  unhidden_modules.count++;

  return;
}

static void scan_hidden_modules(unsigned long scan_base_addr, unsigned long scan_top_addr) {
    
  unsigned long addr;
  unsigned long value;
  struct module *target_mod = NULL;
  size_t address_size = sizeof(void *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  for (addr = scan_base_addr; addr < scan_top_addr; addr += address_size) {
    copy_from_kernel_nofault(&value, (void *)addr, sizeof(value));
    if (value == LIST_POISON1) {
      copy_from_kernel_nofault(&value, (void *) (addr + address_size), sizeof(value));
      if (value == LIST_POISON2) {
        target_mod = addr - address_size;
        pr_info("[lkm_unhide] Found hidden module: %s", target_mod->name);
        list_add(&target_mod->list, THIS_MODULE->list.prev);
        break;
      }
    }
  }
#else
  for (addr = scan_base_addr; addr < scan_top_addr; addr += address_size) {
    if (probe_kernel_read(&value, (void *)addr, sizeof(value)) == 0)
      if (value == LIST_POISON1)
        if (probe_kernel_read(&value, (void *)addr + address_size, sizeof(value)) == 0)
          if (value == LIST_POISON2) {
            target_mod = addr - address_size;
            pr_info("[lkm_unhide] Found hidden module: %s", target_mod->name);
            list_add(&target_mod->list, THIS_MODULE->list.prev);
            break;
          }
  }
#endif

  return;

}

static int __init lkm_unhide_init(void) {
  struct list_head *modules_list;
  struct module *mod;
  unsigned long last_try_base_address;
  int i;

  pr_info("[lkm_unhide] module loaded!");

  // Get sorted list of unhidden modules
  modules_list = THIS_MODULE->list.prev;
  list_for_each_entry(mod, modules_list, list) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    add_unhidden_module((unsigned long)mod->mem->base, (int)mod->mem->size);
#else
    add_unhidden_module((unsigned long)mod->core_layout.base, (int)mod->core_layout.size);
#endif
  }

  // Scan memory regions between unhidden modules
  for (i=0; i<unhidden_modules.count - 1; i++) {
    scan_hidden_modules(unhidden_modules.address[i] + unhidden_modules.size[i], unhidden_modules.address[i+1]);
  }

  // Last try
  last_try_base_address = unhidden_modules.address[i+1] + unhidden_modules.size[i+1];
  scan_hidden_modules(last_try_base_address, last_try_base_address + 0x10000);

  pr_info("[lkm_unhide] scan completed!");

  return 0;
}

static void __exit lkm_unhide_exit(void) {
  kfree(unhidden_modules.address);
  kfree(unhidden_modules.size);
  pr_info("[lkm_unhide] module unloaded!");
}

module_init(lkm_unhide_init);
module_exit(lkm_unhide_exit);

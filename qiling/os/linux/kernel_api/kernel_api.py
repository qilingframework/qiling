#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.const import *
from qiling.os.linux.fncc import linux_kernel_api


@linux_kernel_api(params={
    "format": STRING
})
def hook_printk(ql: Qiling, address: int, params):
    PRINTK_LEVEL = (
        'KERN_EMERGE',
        'KERN_ALERT',
        'KERN_CRIT',
        'KERN_ERR',
        'KERN_WARNING',
        'KERN_NOTICE',
        'KERN_INFO',
        'KERN_DEBUG',
        'KERN_DEFAULT',
        'KERN_CONT'
    )

    format = params['format']

    if format == 0:
        return 0

    level = PRINTK_LEVEL[int(format[1])]
    nargs = format.count("%")
    ptypes = (POINTER, ) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[1:]

    count = ql.os.utils.printf(f'{level} {format[2:]}', args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook___fentry__(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_mcount(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook___x86_indirect_thunk_rax(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook__copy_to_user(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook__copy_from_user(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook___x86_indirect_thunk_r14(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook___stack_chk_fail(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_mutex_lock_interruptible(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_mutex_unlock(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_kmalloc_caches(ql, address, params):
    pass


@linux_kernel_api(params={
    "size": SIZE_T,
    "flags": INT
})
def hook_kmalloc(ql, address, params):
    size = params['size']
    addr = ql.heap.alloc(size)
    return addr


@linux_kernel_api(params={
    "dest": POINTER,
    "c": INT,
    "count": SIZE_T
})
def hook_memset(ql, address, params):
    dest = params["dest"]
    c = params["c"]
    count = params["count"]
    ql.mem.write(dest, bytes(c) * count)
    return dest


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_kmem_cache_alloc_trace(ql, address, params):
    pass


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_get_by_key(ql, address, params):
    pass


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_kfree(ql, address, params):
    pass


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_misc_register(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_misc_deregister(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook___this_module(ql, address, params):
    pass


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_htable(ql, address, params):
    pass


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_strcpy(ql, address, params):
    pass


@linux_kernel_api(params={
    "major": INT,
    "baseminor": INT,
    "count": INT,
    "name": STRING,
    "fops": POINTER,
})
def hook___register_chrdev(ql, address, params):
    return 0


@linux_kernel_api(params={
    "major": INT,
    "name": STRING,
    "fops": POINTER,
})
def hook_register_chrdev(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook___class_create(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER,
    "name": STRING,
})
def hook___unregister_chrdev(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_device_create(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_class_destroy(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_device_destroy(ql, address, params):
    return 0


@linux_kernel_api(params={
    "Ptr": POINTER
})
def hook_class_unregister(ql, address, params):
    return 0


@linux_kernel_api(params={
    "dev": POINTER
})
def hook_dev_get_flags(ql, address, params):
    return 0


@linux_kernel_api(params={
    "buffer": POINTER,
    "format": STRING
})
def hook_sprintf(ql, address, params):
    return 0


@linux_kernel_api(params={
    "str1": STRING,
    "str2": STRING
})
def hook_strcmp(ql, address, params):
    return 0


@linux_kernel_api(params={
    "str1": STRING,
    "str2": STRING,
    "count": SIZE_T
})
def hook_strncmp(ql, address, params):
    s1 = params["str"]
    s2 = params["str2"]
    count = params["count"]
    string1 = s1[:count]
    string2 = s2[:count]

    if string1 == string2:
        result = 0
    elif string1 > string2:
        result = 1
    else:
        result = -1
    return result


@linux_kernel_api(params={
    "haystack": STRING,
    "needle": STRING
})
def hook_strstr(ql, address, params):
    _haystack = params["haystack"]
    _needle = params["needle"]
    index = _haystack.find(_needle)
    return 0 if index == -1 else index


@linux_kernel_api(params={
    "str": STRING,
})
def hook_strlen(ql, address, params):
    _str = params["str"]
    strlen = len(_str)
    return strlen


@linux_kernel_api(params={
    "s1": POINTER,
    "s2": POINTER,
    "size": SIZE_T
})
def hook_memcmp(ql, address, params):
    s1 = params['s1']
    s2 = params['s2']
    size = params['size']
    return ql.mem.read(s1, size) ==  ql.mem.read(s2, size)


@linux_kernel_api(params={
    "str1": POINTER,
    "str2": POINTER,
    "base": INT
})
def hook_simple_strtol(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_pv_cpu_ops(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_sock_create(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_sock_release(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_filp_open(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_filp_close(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_PDE_DATA(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook__kmalloc(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_raw_spin_lock_irqsave(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_raw_spin_unlock_irqrestore(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_current_task(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_prepare_kernel_cred(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_commit_creds(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_kallsyms_on_each_symbol(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_register_module_notifier(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_unregister_module_notifier(ql, address, params):
    return 0


@linux_kernel_api(params={
})
def hook_hook_kobject_del(ql, address, params):
    return 0

@linux_kernel_api(params={
})
def hook_proc_create(ql, address, params):
    # indicate that proc_create successed, and return (proc_dir_entry *)
    return 0x1000

@linux_kernel_api(params={
})
def hook_remove_proc_entry(ql, address, params):
    return 0

@linux_kernel_api(params={
    "fd": UINT,
    "buf": STRING,
    "count": SIZE_T,
})
def hook_sys_read(ql, address, params):
    return 0

@linux_kernel_api(params={
    "fd": UINT,
    "buf": STRING,
    "count": SIZE_T,
})
def hook_sys_write(ql, address, params):
    return 0

@linux_kernel_api(params={
    "pathname": STRING,
    "flags": UINT,
})
def hook_sys_open(ql, address, params):
    return 0

@linux_kernel_api(params={
})
def hook_make_kgid(ql, address, params):
    return 0

@linux_kernel_api(params={
})
def hook_make_kuid(ql, address, params):
    return 0

@linux_kernel_api(params={
})
def hook_prepare_creds(ql, address, params):
    # return non-NULL creds
    return 0x1000

@linux_kernel_api(params={
})
def hook_commit_creds(ql, address, params):
    return 0

@linux_kernel_api(params={
})
def hook_abort_creds(ql, address, params):
    return 0

@linux_kernel_api(params={
    "dest": POINTER,
    "src": POINTER,
    "size": SIZE_T
})
def hook_memcpy(ql, address, params):
    dest = params["dest"]
    src = params["src"]
    size = params["size"]
    ql.mem.write(dest, bytes(ql.mem.read(src, size)))
    return dest

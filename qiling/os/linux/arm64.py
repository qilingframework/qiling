#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm64_const import *

from qiling.loader.elf import *

from qiling.os.linux.arm64_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *

from qiling.os.utils import *
from qiling.os.linux.const import *
from qiling.os.linux.utils import *
from qiling.const import *

def hook_syscall(ql, intno):
    param0, param1, param2, param3, param4, param5 = ql.syscall_param

    while 1:
        LINUX_SYSCALL_FUNC = ql.dict_posix_syscall.get(ql.syscall, None)
        if LINUX_SYSCALL_FUNC != None:
            LINUX_SYSCALL_FUNC_NAME = LINUX_SYSCALL_FUNC.__name__
            break
        LINUX_SYSCALL_FUNC_NAME = dict_linux_syscall.get(ql.syscall, None)
        if LINUX_SYSCALL_FUNC_NAME != None:
            LINUX_SYSCALL_FUNC = eval(LINUX_SYSCALL_FUNC_NAME)
            break
        LINUX_SYSCALL_FUNC = None
        LINUX_SYSCALL_FUNC_NAME = None
        break

    if LINUX_SYSCALL_FUNC != None:
        try:
            LINUX_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            ql.nprint("[!] SYSCALL ERROR: %s\n[-] %s" % (LINUX_SYSCALL_FUNC_NAME, e))
            if ql.multithread == True:
                td = ql.thread_management.cur_thread
                td.stop()
                td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise
    else:
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(ql.pc, ql.syscall, ql.syscall))
        if ql.debug_stop:
            if ql.multithread == True:
                td = ql.thread_management.cur_thread
                td.stop()
                td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise QlErrorSyscallNotFound("[!] Syscall Not Found")    


def loader_file(ql):
    ql.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if (ql.stack_address == 0):
        ql.stack_address = QL_ARM64_LINUX_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0):  
        ql.stack_size = QL_ARM64_LINUX_PREDEFINE_STACKSIZE
    ql.mem.map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv,  env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))


def loader_shellcode(ql):
    ql.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024
    ql.mem.map(ql.stack_address, ql.stack_size)
    ql.stack_address =  ql.stack_address  + 0x200000 - 0x1000    
    ql.mem.write(ql.stack_address, ql.shellcoder) 


def runner(ql):
    ql.register(UC_ARM64_REG_SP, ql.stack_address)
    ql_setup_output(ql)
    ql.hook_intr(hook_syscall)
    ql.archfunc.enable_vfp()
    ql_os_run(ql)

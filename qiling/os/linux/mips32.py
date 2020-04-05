#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.mips_const import *

from qiling.loader.elf import *

from qiling.os.linux.mips32_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *

from qiling.os.linux.const import *
from qiling.os.linux.utils import *
from qiling.os.utils import *
from qiling.const import *



def hook_syscall(ql, intno):
    param0, param1, param2, param3, param4, param5 = ql.syscall_param

    if intno != 0x11:
        raise QlErrorExecutionStop("[!] got interrupt 0x%x ???" %intno)

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
    if ql.archendian == QL_ENDIAN_EB:
        ql.uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
    else:
        ql.uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    if (ql.stack_address == 0):
        ql.stack_address = QL_MIPS32_LINUX_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_MIPS32_LINUX_PREDEFINE_STACKSIZE
    ql.mem.map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv, env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))
    ql.register(UC_MIPS_REG_SP, ql.new_stack)
    ql_setup_output(ql)
    ql.hook_intr(hook_syscall)


def loader_shellcode(ql):
    if ql.archendian == QL_ENDIAN_EB:
        ql.uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
    else:
        ql.uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)    
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024
    ql.mem.map(ql.stack_address, ql.stack_size)
    ql.stack_address =  ql.stack_address  + 0x200000 - 0x1000
    ql.mem.write(ql.stack_address, ql.shellcoder) 
    ql.register(UC_MIPS_REG_SP, ql.new_stack)
    ql_setup_output(ql)
    ql.hook_intr(hook_syscall)


def runner(ql):
    ql_os_run(ql)


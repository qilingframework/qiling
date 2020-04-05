#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import traceback

from unicorn import *
from unicorn.arm64_const import *

from qiling.loader.macho import *
#from qiling.arch.x86 import *
from qiling.os.macos.arm64_syscall import *
from qiling.os.macos.syscall import *
from qiling.os.macos.utils import *
from qiling.os.macos.kernel_func import *
from qiling.os.macos.thread import *
from qiling.os.macos.subsystems import *
from qiling.os.macos.task import *
from qiling.os.macos.mach_port import *
from qiling.os.posix.syscall import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.const import *
from qiling.os.macos.const import *

def hook_syscall(ql, intno):
    param0, param1, param2, param3, param4, param5 = ql.syscall_param

    while 1:
        MACOS_SYSCALL_FUNC = ql.dict_posix_syscall.get(ql.syscall, None)
        if MACOS_SYSCALL_FUNC != None:
            MACOS_SYSCALL_FUNC_NAME = MACOS_SYSCALL_FUNC.__name__
            break
        MACOS_SYSCALL_FUNC_NAME = dict_macos_syscall.get(ql.syscall, None)
        if MACOS_SYSCALL_FUNC_NAME != None:
            MACOS_SYSCALL_FUNC = eval(MACOS_SYSCALL_FUNC_NAME)
            break
        MACOS_SYSCALL_FUNC = None
        MACOS_SYSCALL_FUNC_NAME = None
        break

    if MACOS_SYSCALL_FUNC != None:
        try:
            MACOS_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except KeyboardInterrupt:
            raise            
        except Exception:
            ql.nprint("[!] SYSCALL ERROR: ", MACOS_SYSCALL_FUNC_NAME)
            #td = ql.thread_management.cur_thread
            #td.stop()
            #td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise QlErrorSyscallError("[!] Syscall Implementation Error: %s" % (MACOS_SYSCALL_FUNC_NAME))
    else:
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(ql.pc, ql.syscall, ql.syscall))
        if ql.debug_stop:

            raise QlErrorSyscallNotFound("[!] Syscall Not Found")


def loader_file(ql):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ql.uc = uc
    ql.macho_task = MachoTask()
    ql.macho_fs = FileSystem(ql)
    ql.macho_mach_port = MachPort(2187)
    ql.macho_port_manager = MachPortManager(ql, ql.macho_mach_port)
    ql.macho_host_server = MachHostServer(ql)
    ql.macho_task_server = MachTaskServer(ql)
    if ql.mmap_start == 0:
        ql.mmap_start = QL_ARM64_MACOS_PREDEFINE_MMAPADDRESS
    ql.macho_vmmap_end = QL_ARM64_MACOS_PREDEFINE_VMMAP_TRAP_ADDRESS

    if (ql.stack_address == 0):
        ql.stack_address = QL_ARM64_MACOS_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_ARM64_MACOS_PREDEFINE_STACKSIZE
    
    ql.mem.map(ql.stack_address, ql.stack_size)
    stack_sp = QL_ARM64_MACOS_PREDEFINE_STACKADDRESS + QL_ARM64_MACOS_PREDEFINE_STACKSIZE
    envs = env_dict_to_array(ql.env)
    apples = ql_real_to_vm_abspath(ql, ql.path)
    loader = Macho(ql, ql.path, stack_sp, [ql.path], envs, apples, 1)
    loader.loadMacho()
    ql.macho_task.min_offset = page_align_end(loader.vm_end_addr, PAGE_SIZE)
    ql.stack_address = (int(ql.stack_sp))
    

def loader_shellcode(ql):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ql.uc = uc

    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024

    ql.mem.map(ql.stack_address, ql.stack_size)
    ql.stack_address =  ql.stack_address  + 0x200000 - 0x1000    
    ql.mem.write(ql.stack_address, ql.shellcoder)
    

def runner(ql):
    ql.nprint("[+] AARCH64 IOS Stackaddress start at: 0x%x" %(ql.stack_address))
    ql.register(UC_ARM64_REG_SP, ql.stack_address)
    ql_setup_output(ql)
    ql.hook_intr(hook_syscall)
    ql.archfunc.enable_vfp()
    vm_shared_region_enter(ql)
    map_commpage(ql)
    ql.macho_thread = MachoThread()
    load_shared_region(ql)
    ql_os_run(ql)

  



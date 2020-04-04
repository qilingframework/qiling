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

QL_ARM64_MACOS_PREDEFINE_STACKADDRESS       = 0x0000000160503000
QL_ARM64_MACOS_PREDEFINE_STACKSIZE          = 0x21000
QL_ARM64_MACOS_PREDEFINE_MMAPADDRESS        = 0x7ffbf0100000
QL_ARM64_MACOS_PREDEFINE_VMMAP_TRAP_ADDRESS = 0x4000000f4000
QL_ARM64_EMU_END                            = 0xffffffffffffffff

def hook_syscall(ql, intno):
    syscall_num  = ql.register(UC_ARM64_REG_X16)
    param0 = ql.register(UC_ARM64_REG_X0)
    param1 = ql.register(UC_ARM64_REG_X1)
    param2 = ql.register(UC_ARM64_REG_X2)
    param3 = ql.register(UC_ARM64_REG_X3)
    param4 = ql.register(UC_ARM64_REG_X4)
    param5 = ql.register(UC_ARM64_REG_X5)
    pc = ql.register(UC_ARM64_REG_PC)


    while 1:
        MACOS_SYSCALL_FUNC = ql.dict_posix_syscall.get(syscall_num, None)
        if MACOS_SYSCALL_FUNC != None:
            MACOS_SYSCALL_FUNC_NAME = MACOS_SYSCALL_FUNC.__name__
            break
        MACOS_SYSCALL_FUNC_NAME = dict_arm64_macos_syscall.get(syscall_num, None)
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
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(pc, syscall_num, syscall_num))
        if ql.debug_stop:
            #td = ql.thread_management.cur_thread
            #td.stop()
            #td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise QlErrorSyscallNotFound("[!] Syscall Not Found")


def ql_arm64_enable_vfp(uc):
    ARM64FP = ql.register(UC_ARM64_REG_CPACR_EL1)
    ARM64FP |= 0x300000
    ql.register(UC_ARM64_REG_CPACR_EL1, ARM64FP)


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
    ql_arm64_enable_vfp(ql.uc)
    vm_shared_region_enter(ql)
    map_commpage(ql)
    ql.macho_thread = MachoThread()
    load_shared_region(ql)

    if (ql.until_addr == 0):
        ql.until_addr = QL_ARM64_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.mem.read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise QlErrorExecutionStop("[!] Execution Terminated")    
    
    if ql.internal_exception != None:
        raise ql.internal_exception    



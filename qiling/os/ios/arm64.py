#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.arm64_const import *

from qiling.loader.macho import *
from qiling.arch.x86 import *
from qiling.os.ios.arm64_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.ios.syscall import *
from qiling.os.macos.utils import *
from qiling.os.utils import *
from qiling.arch.filetype import *

QL_ARM64_IOS_PREDEFINE_STACKADDRESS = 0x7fffff500000
QL_ARM64_IOS_PREDEFINE_STACKSIZE = 0xa00000
QL_ARM64_IOS_PREDEFINE_MMAPADDRESS = 0x7fffff000000

QL_ARM64_EMU_END = 0xffffffffffffffff

def hook_syscall(ql):
    syscall_num  = ql.uc.reg_read(UC_ARM64_REG_X8)
    param0 = ql.uc.reg_read(UC_ARM64_REG_X0)
    param1 = ql.uc.reg_read(UC_ARM64_REG_X1)
    param2 = ql.uc.reg_read(UC_ARM64_REG_X2)
    param3 = ql.uc.reg_read(UC_ARM64_REG_X3)
    param4 = ql.uc.reg_read(UC_ARM64_REG_X4)
    param5 = ql.uc.reg_read(UC_ARM64_REG_X5)
    pc = ql.uc.reg_read(UC_ARM64_REG_PC)

    while 1:
        IOS_SYSCALL_FUNC = ql.dict_posix_syscall.get(syscall_num, None)
        if IOS_SYSCALL_FUNC != None:
            IOS_SYSCALL_FUNC_NAME = IOS_SYSCALL_FUNC.__name__
            break
        IOS_SYSCALL_FUNC_NAME = dict_arm64_ios_syscall.get(syscall_num, None)
        if IOS_SYSCALL_FUNC_NAME != None:
            IOS_SYSCALL_FUNC = eval(IOS_SYSCALL_FUNC_NAME)
            break
        IOS_SYSCALL_FUNC = None
        IOS_SYSCALL_FUNC_NAME = None
        break

    if IOS_SYSCALL_FUNC != None:
        try:
            IOS_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except KeyboardInterrupt:
            raise            
        except Exception:
            ql.nprint("[!] SYSCALL ERROR: %s" % (IOS_SYSCALL_FUNC_NAME))
            #td = ql.thread_management.cur_thread
            #td.stop()
            #td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise
    else:
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(pc, syscall_num, syscall_num))
        if ql.debug_stop:
            #td = ql.thread_management.cur_thread
            #td.stop()
            #td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise QlErrorSyscallNotFound("[!] Syscall Not Found")   


def loader_file(ql):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ql.uc = uc
    ql.mmap_start = QL_ARM64_IOS_PREDEFINE_MMAPADDRESS
    if (ql.stack_address == 0):
        ql.stack_address = QL_ARM64_IOS_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0):
        ql.stack_size = QL_ARM64_IOS_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    stack_esp = QL_ARM64_IOS_PREDEFINE_STACKADDRESS + QL_ARM64_IOS_PREDEFINE_STACKSIZE
    envs = env_dict_to_array(ql.env)
    loader = MachoARM64(ql, ql.path, stack_esp, [ql.path], envs, [ql.path], 1)
    loader.MachoARM64()
    ql.stack_address = (int(ql.stack_esp))

    ql.sp = ql.stack_address
    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, XXX_SYSCALL_INSN_FIXME)
    ql_x8664_setup_gdt_segment_ds(ql)
    ql_x8664_setup_gdt_segment_cs(ql)
    ql_x8664_setup_gdt_segment_ss(ql)


def loader_shellcode(ql):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0):
        ql.stack_size = 2 * 1024 * 1024
    ql.uc.mem_map(ql.stack_address,  ql.stack_size)
    ql.stack_address = ql.stack_address  + 0x200000 - 0x1000
    ql.uc.mem_write(ql.stack_address, ql.shellcoder)

    ql.sp = ql.stack_address
    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, XXX_SYSCALL_INSN_FIXME)
    ql_x8664_setup_gdt_segment_ds(ql)
    ql_x8664_setup_gdt_segment_cs(ql)
    ql_x8664_setup_gdt_segment_ss(ql)


def runner(ql):
    if (ql.until_addr == 0):
        ql.until_addr = QL_ARM64_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            #if ql.elf_entry != ql.entry_point:
            #    ql.uc.emu_start(ql.entry_point, ql.elf_entry, ql.timeout) 
            #    ql.enable_lib_patch()
            #ql.uc.emu_start(ql.elf_entry, ql.until_addr, ql.timeout) 
            
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
            
    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.uc.mem_read(ql.pc, 8)
            ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise
    
    if ql.internal_exception != None:
        raise ql.internal_exception    

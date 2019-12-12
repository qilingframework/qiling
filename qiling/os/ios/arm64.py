#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
import sys

from unicorn import *
from unicorn.x86_const import *

from capstone import *
from capstone.x86_const import *

from keystone import *
from keystone.x86_const import *

from struct import pack
import os

import string

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
        except Exception as e:
            ql.nprint("[!] SYSCALL: ", IOS_SYSCALL_FUNC_NAME)
            ql.nprint("[-] ERROR: %s" % (e))
            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                if ql.debug_stop:
                    ql.nprint("[-] Stopped due to ql.debug_stop is True")
                    raise QlErrorSyscallError("[!] Syscall Implenetation Error")
    else:
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(pc, syscall_num,  (syscall_num -  0x2000000)))
        if ql.debug_stop:
            ql.nprint("[-] Stopped due to ql.debug_stop is True")
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
    

def runner(ql):
    ql.uc.reg_write(UC_X86_REG_RSP, ql.stack_address)
    ql_setup(ql)
    ql.hook_insn(hook_syscall, XXX_SYSCALL_INSN_FIXME)
    ql_x8664_setup_gdt_segment_ds(ql)
    ql_x8664_setup_gdt_segment_cs(ql)
    ql_x8664_setup_gdt_segment_ss(ql)

    if (ql.until_addr == 0):
        ql.until_addr = QL_ARM64_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError as e:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.uc.mem_read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise QlErrorExecutionStop('[!] Emulation Stopped due to %s' %(e))
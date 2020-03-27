#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.x86_const import *


from qiling.loader.elf import *
from qiling.arch.x86 import *
from qiling.os.freebsd.x8664_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.freebsd.syscall import *
from qiling.os.utils import *
from qiling.arch.filetype import *

QL_X8664_FREEBSD_PREDEFINE_STACKADDRESS = 0x7ffffffde000
QL_X8664_FREEBSD_PREDEFINE_STACKSIZE = 0x21000
QL_X8664_EMU_END = 0xffffffffffffffff


def hook_syscall(ql):
    syscall_num  = ql.uc.reg_read(UC_X86_REG_RAX)
    param0 = ql.uc.reg_read(UC_X86_REG_RDI)
    param1 = ql.uc.reg_read(UC_X86_REG_RSI)
    param2 = ql.uc.reg_read(UC_X86_REG_RDX)
    param3 = ql.uc.reg_read(UC_X86_REG_R10)
    param4 = ql.uc.reg_read(UC_X86_REG_R8)
    param5 = ql.uc.reg_read(UC_X86_REG_R9)
    pc = ql.uc.reg_read(UC_X86_REG_RIP)
    
    ql.dprint(0, "[+] 0x%x: syscall number = 0x%x(%d)" % (pc, syscall_num, syscall_num))

    while 1:
        FREEBSD_SYSCALL_FUNC = ql.dict_posix_syscall.get(syscall_num, None)
        if FREEBSD_SYSCALL_FUNC != None:
            FREEBSD_SYSCALL_FUNC_NAME = FREEBSD_SYSCALL_FUNC.__name__
            break
        FREEBSD_SYSCALL_FUNC_NAME = dict_x8664_freebsd_syscall.get(syscall_num, None)
        if FREEBSD_SYSCALL_FUNC_NAME != None:
            FREEBSD_SYSCALL_FUNC = eval(FREEBSD_SYSCALL_FUNC_NAME)
            break
        FREEBSD_SYSCALL_FUNC = None
        FREEBSD_SYSCALL_FUNC_NAME = None
        break

    if FREEBSD_SYSCALL_FUNC != None:
        try:
            FREEBSD_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except KeyboardInterrupt:
            raise            
        except Exception:
            ql.nprint("[!] SYSCALL ERROR: %s" % (FREEBSD_SYSCALL_FUNC_NAME))
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
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_X8664_FREEBSD_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0):
        ql.stack_size = QL_X8664_FREEBSD_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv, env = ql.env):
        raise QlErrorFileType("Unsupported FileType")

    ql.stack_address = (int(ql.new_stack))

    init_rbp = ql.stack_address + 0x40
    init_rdi = ql.stack_address

    ql.uc.reg_write(UC_X86_REG_RSP, ql.stack_address)
    ql.uc.reg_write(UC_X86_REG_RBP, init_rbp)
    ql.uc.reg_write(UC_X86_REG_RDI, init_rdi)
    ql.uc.reg_write(UC_X86_REG_R14, init_rdi)

    ql.dprint(0, "[+] RSP = 0x%x" % (ql.stack_address))
    ql.dprint(0, "[+] RBP = 0x%x" % (init_rbp))
    ql.dprint(0, "[+] RDI = 0x%x" % (init_rdi))

    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)

    ql_x8664_setup_gdt_segment_cs(ql)
    ql_x8664_setup_gdt_segment_ss(ql)


def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0):    
        ql.stack_size = 2 * 1024 * 1024
    ql.uc.mem_map(ql.stack_address,  ql.stack_size)
    ql.stack_address = ql.stack_address  + 0x200000 - 0x1000
    ql.uc.mem_write(ql.stack_address, ql.shellcoder)

    init_rbp = ql.stack_address + 0x40
    #init_rdi = init_rbp + 0x8
    
    ql.uc.reg_write(UC_X86_REG_RSP, ql.stack_address)
    ql.uc.reg_write(UC_X86_REG_RBP, init_rbp)
    ql.uc.reg_write(UC_X86_REG_RDI, ql.stack_address)
    #ql.uc.reg_write(UC_X86_REG_R14, init_rdi)

    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)


def runner(ql):
    if (ql.until_addr == 0):
        ql.until_addr = QL_X8664_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            if ql.elf_entry != ql.entry_point:
                ql.uc.emu_start(ql.entry_point, ql.elf_entry, ql.timeout) 
                ql.enable_lib_patch()
            ql.uc.emu_start(ql.elf_entry, ql.until_addr, ql.timeout) 
            
    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP, QL_OUT_DISASM):
            ql.nprint("[+] PC = 0x%x\n" %(ql.pc))
            ql.show_map_info()
            try:
                buf = ql.uc.mem_read(ql.pc, 8)
                ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                ql.nprint("\n")
                ql_hook_code_disasm(ql, ql.pc, 64)
            except:
                pass
        raise
    
    if ql.internal_exception != None:
        raise ql.internal_exception


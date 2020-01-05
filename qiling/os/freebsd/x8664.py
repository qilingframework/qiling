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
            ql.nprint("[!] SYSCALL ERROR: ", FREEBSD_SYSCALL_FUNC_NAME)
            #td = ql.thread_management.cur_thread
            #td.stop()
            #td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise QlErrorSyscallError("[!] Syscall Implementation Error: %s" % (FREEBSD_SYSCALL_FUNC_NAME))
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
    ql.stack_address =(int(ql.new_stack-8))
    

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
    

def runner(ql):

    ql.uc.reg_write(UC_X86_REG_RSP, ql.stack_address)
    ql.uc.reg_write(UC_X86_REG_RDI, ql.stack_address)
    #ql.uc.reg_write(UC_X86_REG_RAX, 0x0)
    #ql.uc.reg_write(UC_X86_REG_R14D, 0xfffffffffffff000)
    #ql.uc.reg_write(UC_X86_REG_R15D, 0xfffffffffffff000)

    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)

    # https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_64_msr.py
    # some ref from unicorn.

    # FSMSR = 0xC0000100
    # GSMSR = 0xC0000101

    # SCRATCH_ADDR = 0x80000
    # SCRATCH_SIZE = 0x1000

    # SEGMENT_ADDR = 0x5000
    # SEGMENT_SIZE = 0x1000

    # def set_msr(uc, msr, value, scratch=SCRATCH_ADDR):
    #     '''
    #     set the given model-specific register (MSR) to the given value.
    #     this will clobber some memory at the given scratch address, as it emits some code.
    #     '''

    #     #uc = ql.uc
    #     # save clobbered registers
    #     orax = uc.reg_read(UC_X86_REG_RAX)
    #     ordx = uc.reg_read(UC_X86_REG_RDX)
    #     orcx = uc.reg_read(UC_X86_REG_RCX)
    #     orip = uc.reg_read(UC_X86_REG_RIP)

    #     # x86: wrmsr
    #     buf = b'\x0f\x30'
    #     uc.mem_write(scratch, buf)
    #     uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFF)
    #     uc.reg_write(UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    #     uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    #     uc.emu_start(scratch, scratch+len(buf), count=1)

    #     # restore clobbered registers
    #     uc.reg_write(UC_X86_REG_RAX, orax)
    #     uc.reg_write(UC_X86_REG_RDX, ordx)
    #     uc.reg_write(UC_X86_REG_RCX, orcx)
    #     uc.reg_write(UC_X86_REG_RIP, orip)
    
    # def set_fs(uc, addr):
    #     '''
    #     set the FS.base hidden descriptor-register field to the given address.
    #     this enables referencing the fs segment on x86-64.
    #     '''
    #     return set_msr(uc, FSMSR, addr)
    
    # def set_gs(uc, addr):
    #     '''
    #     set the GS.base hidden descriptor-register field to the given address.
    #     this enables referencing the gs segment on x86-64.
    #     '''
    #     return set_msr(uc, GSMSR, addr)        
    
    # ql.uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)
    # ql.uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
    # set_msr(ql.uc, FSMSR, 0x1000)
    # set_gs(ql.uc, SEGMENT_ADDR)
    # set_fs(ql.uc, SEGMENT_ADDR)

    if (ql.until_addr == 0):
        ql.until_addr = QL_X8664_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP, QL_OUT_DISASM):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.uc.mem_read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise QlErrorExecutionStop("[!] Execution Terminated")    
    
    if ql.internal_exception != None:
        raise ql.internal_exception


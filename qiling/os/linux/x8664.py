#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.x86_const import *

from qiling.loader.elf import *
from qiling.arch.x86 import *
from qiling.os.linux.x8664_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.utils import *
from qiling.const import *


QL_X8664_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
QL_X8664_LINUX_PREDEFINE_STACKSIZE = 0x21000

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
        LINUX_SYSCALL_FUNC = ql.dict_posix_syscall.get(syscall_num, None)
        if LINUX_SYSCALL_FUNC != None:
            LINUX_SYSCALL_FUNC_NAME = LINUX_SYSCALL_FUNC.__name__
            break
        LINUX_SYSCALL_FUNC_NAME = dict_x8664_linux_syscall.get(syscall_num, None)
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
        ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(pc, syscall_num, syscall_num))
        if ql.debug_stop:
            if ql.multithread == True:
                td = ql.thread_management.cur_thread
                td.stop()
                td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
            raise QlErrorSyscallNotFound("[!] Syscall Not Found")



def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_X8664_LINUX_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0):     
        ql.stack_size = QL_X8664_LINUX_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv,  env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))

    ql.sp = ql.stack_address
    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)

    ql_x8664_setup_gdt_segment_ds(ql)
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
    
    ql.sp = ql.stack_address
    ql_setup_output(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)


def runner(ql):
    if (ql.until_addr == 0):
        ql.until_addr = QL_X8664_EMU_END

    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            if ql.multithread == True:
                # start multithreading
                thread_management = ThreadManagement(ql)
                ql.thread_management = thread_management

                main_thread = Thread(ql, thread_management, total_time = ql.timeout)
                main_thread.save()
                main_thread.set_start_address(ql.entry_point)

                thread_management.set_main_thread(main_thread)

                # enable lib patch
                if ql.elf_entry != ql.entry_point:
                    main_thread.set_until_addr(ql.elf_entry)
                    thread_management.run()
                    ql.enable_lib_patch()

                    main_thread.set_start_address(ql.elf_entry)
                    main_thread.set_until_addr(ql.until_addr)
                    main_thread.running()

                    thread_management.clean_world()
                    thread_management.set_main_thread(main_thread)
                
                thread_management.run()

            else:
                if ql.elf_entry != ql.entry_point:
                    ql.uc.emu_start(ql.entry_point, ql.elf_entry, ql.timeout) 
                    ql.enable_lib_patch()
                ql.uc.emu_start(ql.elf_entry, ql.until_addr, ql.timeout) 

    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
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

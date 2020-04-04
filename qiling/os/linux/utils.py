#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm_const import *
from unicorn.mips_const import *

from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.linux.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.utils import *


"""
common utils 
"""
def ql_map_shellcode(ql, start, shellcode, shellcode_addr, shellcode_addr_size):
    if ql.shellcode_init == 0:
        ql.mem.map(shellcode_addr, shellcode_addr_size)
        ql.shellcode_init = 1
    ql.mem.write(shellcode_addr + start, shellcode)

def ql_os_run(ql):    
    if (ql.until_addr == 0):
        if ql.archbit == 32:
            ql.until_addr = QL_ARCHBIT32_EMU_END
        elif ql.archbit == 64:
            ql.until_addr = QL_ARCHBIT64_EMU_END           

    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            if ql.multithread == True:        
                # start multithreading
                thread_management = ThreadManagement(ql)
                ql.thread_management = thread_management
                
                if ql.arch == QL_ARM:
                    thread_set_tls = arm_thread_set_tls
                elif ql.arch == QL_MIPS32:
                    thread_set_tls = mips32_thread_set_tls
                elif ql.arch == QL_X86:
                    thread_set_tls = x86_thread_set_tls                    
                else:
                    thread_set_tls = None
                
                main_thread = Thread(ql, thread_management, total_time = ql.timeout, special_settings_fuc = thread_set_tls)
                
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

    except:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC = 0x%x\n" %(ql.pc))
            ql.show_map_info()
            try:
                buf = ql.mem.read(ql.pc, 8)
                ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                ql.nprint("\n")
                ql_hook_code_disasm(ql, ql.pc, 64)
            except:
                pass
        raise
    
    if ql.internal_exception != None:
        raise ql.internal_exception

"""
thread_set_tls
"""

def arm_thread_set_tls(ql, th, arg):
    address = arg
    mode = ql.archfunc.check_thumb()
    old_r0 = ql.register(UC_ARM_REG_R0)

    if mode == UC_MODE_THUMB:
        ql.dprint(0,"[+] settls THUMB mode")
        sc = '''
            .THUMB
             _start:
                push {r1}
                adr r1, main
                bx r1

            .code 32
            main:
                mcr p15, 0, r0, c13, c0, 3
                adr r1, ret_to
                add r1, r1, #1
                bx r1
            .THUMB
            ret_to:
                pop {r1}
                pop {r0}
                pop {pc}
            '''
        sc = b'\x02\xb4\x01\xa1\x08G\x00\x00p\x0f\r\xee\x04\x10\x8f\xe2\x01\x10\x81\xe2\x11\xff/\xe1\x02\xbc\x01\xbc' \
             b'\x00\xbd\x00\xbf'

        # if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc, 2)
    else:
        ql.dprint(0,"[+] settls ARM mode")
        sc = b'p\x0f\r\xee\x04\x00\x9d\xe4\x04\xf0\x9d\xe4'
        # if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc)
    
    codestart = 0
    ql_map_shellcode(ql, codestart, sc, QL_ARCHBIT32_SHELLCODE_ADDR, QL_ARCHBIT32_SHELLCODE_SIZE)
    codelen = 0
    if mode == UC_MODE_THUMB:
        codelen = 1
    ql.mem.write(ql.sp - 4, ql.pack32(ql.pc + codelen))
    ql.mem.write(ql.sp - 8, ql.pack32(old_r0))
    ql.register(UC_ARM_REG_SP, ql.sp - 8)
    ql.register(UC_ARM_REG_PC, QL_ARCHBIT32_SHELLCODE_ADDR + codestart + codelen)
    ql.mem.write(QL_ARM_KERNEL_GET_TLS_ADDR + 12, ql.pack32(address))
    ql.register(UC_ARM_REG_R0, address)


def mips32_thread_set_tls(ql, th, arg):
    address = arg
    CONFIG3_ULR = (1 << 13)
    ql.register(UC_MIPS_REG_CP0_CONFIG3, CONFIG3_ULR)
    ql.register(UC_MIPS_REG_CP0_USERLOCAL, address)

    ql.dprint (0, "[+] multithread set_thread_area(0x%x)" % address)
    # somehow for multithread these code are still not mature
    ql.dprint (0, "[+] shellcode_init is %i" % (ql.shellcode_init))
    if ql.shellcode_init == 0:
        from qiling.os.linux.mips32 import exec_shellcode
        if ql.archendian == QL_ENDIAN_EB:
            exec_shellcode(ql, ql.pc + 4, bytes.fromhex('0000102500003825'))
        else:    
            exec_shellcode(ql, ql.pc + 4, bytes.fromhex('2510000025380000'))


def x86_thread_set_tls(ql, th, arg):
    u_info = arg
    # u_info = ql.mem.read(u_info_addr, 4 * 3)
    base = ql.unpack32(u_info[4 : 8])
    limit = ql.unpack32(u_info[8 : 12])
    from qiling.os.linux.x86 import ql_x86_setup_syscall_set_thread_area
    ql_x86_setup_syscall_set_thread_area(ql, base, limit)            


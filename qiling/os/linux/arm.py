#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm_const import *

from qiling.loader.elf import *
from qiling.os.linux.arm_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.utils import *

# memory address where emulation starts
QL_ARM_LINUX_PREDEFINE_STACKADDRESS = 0xfff0d000
QL_ARM_LINUX_PREDEFINE_STACKSIZE = 0x21000

QL_SHELLCODE_ADDR = 0x0f000000
QL_SHELLCODE_LEN = 0x1000
QL_SHELLCODE_INIT = 0

QL_KERNEL_GET_TLS_ADDR = 0xFFFF0FE0
QL_ARM_EMU_END = 0x8fffffff

def ql_arm_check_thumb(ql, reg_cpsr):
    if ql.archendian == QL_ENDIAN_EB:
        reg_cpsr_v  = 0b100000
        #reg_cpsr_v = 0b000000
    else:
        reg_cpsr_v = 0b100000
    
    mode = UC_MODE_ARM
    if (reg_cpsr & reg_cpsr_v) != 0:
        mode = UC_MODE_THUMB
    return mode

def hook_syscall(ql, intno):
    syscall_num = ql.uc.reg_read(UC_ARM_REG_R7)
    param0 = ql.uc.reg_read(UC_ARM_REG_R0)
    param1 = ql.uc.reg_read(UC_ARM_REG_R1)
    param2 = ql.uc.reg_read(UC_ARM_REG_R2)
    param3 = ql.uc.reg_read(UC_ARM_REG_R3)
    param4 = ql.uc.reg_read(UC_ARM_REG_R4)
    param5 = ql.uc.reg_read(UC_ARM_REG_R5)
    reg_cpsr = ql.uc.reg_read(UC_ARM_REG_CPSR)
    pc = ql.uc.reg_read(UC_ARM_REG_PC)
    ql_arm_check_thumb(ql, reg_cpsr)

    while 1:
        LINUX_SYSCALL_FUNC = ql.dict_posix_syscall.get(syscall_num, None)
        if LINUX_SYSCALL_FUNC != None:
            LINUX_SYSCALL_FUNC_NAME = LINUX_SYSCALL_FUNC.__name__
            break
        
        LINUX_SYSCALL_FUNC_NAME = dict_arm_linux_syscall.get(syscall_num, None)
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
       

def exec_shellcode(ql, start, shellcode):
    if ql.shellcode_init == 0:
        ql.uc.mem_map(QL_SHELLCODE_ADDR, QL_SHELLCODE_LEN)
        ql.shellcode_init = 1
    ql.uc.mem_write(QL_SHELLCODE_ADDR + start, shellcode)


def ql_arm_enable_vfp(ql):
    uc = ql.uc
    tmp_val = uc.reg_read(UC_ARM_REG_C1_C0_2)
    tmp_val = tmp_val | (0xf << 20)
    uc.reg_write(UC_ARM_REG_C1_C0_2, tmp_val)
    if ql.archendian == QL_ENDIAN_EB:
        enable_vfp  = 0x40000000
        #enable_vfp = 0x00000040
    else:
        enable_vfp = 0x40000000
    uc.reg_write(UC_ARM_REG_FPEXC, enable_vfp)
    ql.dprint(0,"[+] Enable ARM VFP")


def ql_arm_init_kernel_get_tls(ql):
    uc = ql.uc
    uc.mem_map(0xFFFF0000, 0x1000)
    """
    'adr r0, data; ldr r0, [r0]; mov pc, lr; data:.ascii "\x00\x00"'
    """
    sc = b'\x04\x00\x8f\xe2\x00\x00\x90\xe5\x0e\xf0\xa0\xe1\x00\x00\x00\x00'

    #if ql.archendian == QL_ENDIAN_EB:
    #    sc = ql_lsbmsb_convert(ql, sc)

    uc.mem_write(QL_KERNEL_GET_TLS_ADDR, sc)
    ql.dprint(0,"[+] Set init_kernel_get_tls")

def ql_arm_thread_set_tls(ql, th, arg):
    address = arg
    uc = ql.uc
    reg_cpsr = uc.reg_read(UC_ARM_REG_CPSR)
    PC = uc.reg_read(UC_ARM_REG_PC)
    SP = uc.reg_read(UC_ARM_REG_SP)
    mode = ql_arm_check_thumb(ql, reg_cpsr)
    old_r0 = uc.reg_read(UC_ARM_REG_R0)

    if mode == UC_MODE_THUMB:
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
        sc = b'\x02\xb4\x01\xa1\x08G\x00\x00p\x0f\r\xee\x04\x10\x8f\xe2\x01\x10\x81\xe2\x11\xff/\xe1\x02\xbc\x01\xbc\x00\xbd\x00\xbf'
        #if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc, 2)
    else:
        sc = b'p\x0f\r\xee\x04\x00\x9d\xe4\x04\xf0\x9d\xe4'
        #if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc)

    codestart = 4
    exec_shellcode(ql, codestart, sc)
    codelen = 0
    if mode == UC_MODE_THUMB:
        codelen = 1
    uc.mem_write(SP - 4, ql.pack32(PC + codelen))
    uc.mem_write(SP - 8, ql.pack32(old_r0))
    uc.reg_write(UC_ARM_REG_SP, SP - 8)
    uc.reg_write(UC_ARM_REG_PC, QL_SHELLCODE_ADDR + codestart + codelen)
    uc.mem_write(QL_KERNEL_GET_TLS_ADDR + 12, ql.pack32(address))
    uc.reg_write(UC_ARM_REG_R0, address)
    

def ql_syscall_arm_settls(ql, address, null0, null1, null2, null3, null4):
    #ql.nprint("settls(0x%x)" % address)
    
    if ql.thread_management != None and ql.multithread == True:
        ql.thread_management.cur_thread.special_settings_arg = address

    reg_cpsr = ql.uc.reg_read(UC_ARM_REG_CPSR)
    PC = ql.uc.reg_read(UC_ARM_REG_PC)
    SP = ql.uc.reg_read(UC_ARM_REG_SP)
    mode = ql_arm_check_thumb(ql, reg_cpsr)
    #ql.nprint("THUMB and Mode %x %x" % (UC_MODE_THUMB, mode))
    if mode == UC_MODE_THUMB:
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
                pop {pc}
            '''
        sc = b'\x02\xb4\x01\xa1\x08G\x00\x00p\x0f\r\xee\x04\x10\x8f\xe2\x01\x10\x81\xe2\x11\xff/\xe1\x02\xbc\x00\xbd'
        #if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc, 2)
    else:
        sc = b'p\x0f\r\xee\x04\xf0\x9d\xe4'
        #if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc)

    codestart = 4
    exec_shellcode(ql, codestart, sc)
    codelen = 0
    if mode == UC_MODE_THUMB:
        codelen = 1
    ql.uc.mem_write(SP - 4, ql.pack32(PC + codelen))
    ql.uc.reg_write(UC_ARM_REG_SP, SP - 4)
    ql.uc.reg_write(UC_ARM_REG_PC, QL_SHELLCODE_ADDR + codestart + codelen)

    ql.uc.mem_write(QL_KERNEL_GET_TLS_ADDR + 12, ql.pack32(address))
    ql.uc.reg_write(UC_ARM_REG_R0, address)
    ql.nprint("settls(0x%x)" % address)


def loader_file(ql):
    if ql.archendian == QL_ENDIAN_EB:
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        # uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN)
    else:
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_ARM_LINUX_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0):  
        ql.stack_size = QL_ARM_LINUX_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv,  env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address  = (int(ql.new_stack))


def loader_shellcode(ql):
    if ql.archendian == QL_ENDIAN_EB:
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN)
    else:
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    ql.stack_address  = (ql.stack_address + 0x200000 - 0x1000)
    ql.uc.mem_write(ql.stack_address, ql.shellcoder) 


def runner(ql):
    ql.uc.reg_write(UC_ARM_REG_SP, ql.stack_address)
    ql_setup_output(ql)
    ql.hook_intr(hook_syscall)
    ql_arm_enable_vfp(ql)
    ql_arm_init_kernel_get_tls(ql)

    if (ql.until_addr == 0):
        ql.until_addr = QL_ARM_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            if ql.multithread == True:        
                # start multithreading
                thread_management = ThreadManagement(ql)
                ql.thread_management = thread_management

                main_thread = Thread(ql, thread_management, total_time = ql.timeout, special_settings_fuc = ql_arm_thread_set_tls)
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

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

"""
thread_set_tls
"""
def ql_arm_init_kernel_get_tls(ql):
    ql.mem.map(0xFFFF0000, 0x1000)
    """
    'adr r0, data; ldr r0, [r0]; mov pc, lr; data:.ascii "\x00\x00"'
    """
    sc = b'\x04\x00\x8f\xe2\x00\x00\x90\xe5\x0e\xf0\xa0\xe1\x00\x00\x00\x00'

    # if ql.archendian == QL_ENDIAN_EB:
    #    sc = ql_lsbmsb_convert(ql, sc)

    ql.mem.write(QL_ARM_KERNEL_GET_TLS_ADDR, sc)
    ql.dprint(0, "[+] Set init_kernel_get_tls")    

def arm_thread_set_tls(ql, th, arg):
    address = arg
    mode = ql.arch.check_thumb()
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
    from qiling.os.arch.x86 import ql_x86_setup_syscall_set_thread_area
    ql_x86_setup_syscall_set_thread_area(ql, base, limit)            

"""
shellcode injection for mips
these shellcodes are for bootup initialization
"""

def exec_shellcode(ql, addr, shellcode):
    '''
    nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	sw $ra, -8($sp)
	sw $a0, -12($sp)
	sw $a1, -16($sp)
	sw $a2, -20($sp)
	sw $a3, -24($sp)
	sw $v0, -28($sp)
	sw $v1, -32($sp)
	sw $t0, -36($sp)

	slti $a2, $zero, -1
lab1:
	bltzal $a2, lab1

	addu $a1, $ra, 140
	addu $t0, $ra, 60
	lw $a0, -4($sp)
	li $a2, 8
	jal $t0
	nop

	lw $ra, -8($sp)
	lw $a0, -12($sp)
	lw $a1, -16($sp)
	lw $a2, -20($sp)
	lw $a3, -24($sp)
	lw $v0, -28($sp)
	lw $v1, -32($sp)
	lw $t0, -36($sp)
	j 0
	nop


 my_mem_cpy:
	move    $a3, $zero
	move    $a3, $zero
	b       loc_400804
	nop

 loc_4007D8:
	move    $v0, $a3
	move    $v1, $a1
	addu    $v1, $v0
	move    $v0, $a3
	addu    $v0, $a0, $v0
	lb      $v1, 0($v1)
	sb      $v1, 0($v0)
	addiu   $a3, 1

 loc_400804:
	move    $v0, $a3
	move    $v1, $a2
	sltu    $v0, $v1
	bnez    $v0, loc_4007D8
	nop
	nop
	jr      $ra
	nop

 store_code:
	nop
    '''

    store_code = ql.mem.read(addr, 8)
    sc = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\xff\xbf\xaf\xf4\xff\xa4\xaf\xf0\xff\xa5\xaf\xec\xff\xa6\xaf\xe8\xff\xa7\xaf\xe4\xff\xa2\xaf\xe0\xff\xa3\xaf\xdc\xff\xa8\xaf\xff\xff\x06(\xff\xff\xd0\x04\x8c\x00\xe5'<\x00\xe8'\xfc\xff\xa4\x8f\x08\x00\x06$\t\xf8\x00\x01\x00\x00\x00\x00\xf8\xff\xbf\x8f\xf4\xff\xa4\x8f\xf0\xff\xa5\x8f\xec\xff\xa6\x8f\xe8\xff\xa7\x8f\xe4\xff\xa2\x8f\xe0\xff\xa3\x8f\xdc\xff\xa8\x8f\x00\x00\x00\x08\x00\x00\x00\x00%8\x00\x00%8\x00\x00\t\x00\x00\x10\x00\x00\x00\x00%\x10\xe0\x00%\x18\xa0\x00!\x18b\x00%\x10\xe0\x00!\x10\x82\x00\x00\x00c\x80\x00\x00C\xa0\x01\x00\xe7$%\x10\xe0\x00%\x18\xc0\x00+\x10C\x00\xf4\xff@\x14\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xe0\x03\x00\x00\x00\x00"

    if ql.archendian == QL_ENDIAN_EB:
        ebsc = ql_lsbmsb_convert(ql, sc)
        sc = ebsc.replace(b'\x08\x00\x00\x00', ql.pack32(0x08000000 ^ (addr // 4)), 1)       
    else:
        sc = sc.replace(b'\x00\x00\x00\x08', ql.pack32(0x08000000 ^ (addr // 4)), 1)
    
    sc = shellcode + sc[len(shellcode) :] + store_code
    ql_map_shellcode(ql, 0, sc, QL_ARCHBIT32_SHELLCODE_ADDR, QL_ARCHBIT32_SHELLCODE_SIZE)
    
    if ql.archendian == QL_ENDIAN_EB:
        ql.mem.write(addr, b'\x0b\xc0\x00\x00\x00\x00\x00\x00')
    else:
        ql.mem.write(addr, b'\x00\x00\xc0\x0b\x00\x00\x00\x00')
    sp = ql.register(UC_MIPS_REG_SP)
    ql.mem.write(sp - 4, ql.pack32(addr))
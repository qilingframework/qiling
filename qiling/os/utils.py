#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that are only used in qiling.os
"""

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from capstone.arm64_const import *
from capstone.mips_const import *

from keystone import *

from qiling.arch.filetype import *
from qiling.exception import *
from qiling.utils import *

from binascii import unhexlify
import ipaddress
import struct
import os


def ql_definesyscall_return(ql, regreturn):
    if (ql.arch == QL_ARM): # QL_ARM
        ql.uc.reg_write(UC_ARM_REG_R0, regreturn)
        #ql.nprint("-[+] Write %i to UC_ARM_REG_R0" % regreturn)

    elif (ql.arch == QL_ARM64): # QL_ARM64
        ql.uc.reg_write(UC_ARM64_REG_X0, regreturn)

    elif (ql.arch == QL_X86): # QL_X86
        ql.uc.reg_write(UC_X86_REG_EAX, regreturn)

    elif (ql.arch == QL_X8664): # QL_X86_64
        ql.uc.reg_write(UC_X86_REG_RAX, regreturn)

    elif (ql.arch == QL_MIPS32EL): # QL_MIPSE32EL
        if regreturn == -1:
            a3return = 1
        elif regreturn == 2:
            regreturn = 2
            a3return = 1
        else:    
            a3return = 0
        #if ql.output == QL_OUT_DEBUG:    
        #    print("[+] A3 is %d" % a3return)
        ql.uc.reg_write(UC_MIPS_REG_V0, regreturn)
        ql.uc.reg_write(UC_MIPS_REG_A3, a3return)

def ql_bin_to_ipv4(ip):
    return "%d.%d.%d.%d" % (
        (ip & 0xff000000) >> 24,
        (ip & 0xff0000) >> 16,
        (ip & 0xff00) >> 8,
        (ip & 0xff))


def ql_bin_to_ip(ip):
    return ipaddress.ip_address(ip).compressed


def ql_read_string(ql, address):
    ret = ""
    c = ql.uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = ql.uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret


def ql_parse_sock_address(sock_addr):
    sin_family, = struct.unpack("<h", sock_addr[:2])

    if sin_family == 2:  # AF_INET
        port, host = struct.unpack(">HI", sock_addr[2:8])
        return "%s:%d" % (ql_bin_to_ip(host), port)
    elif sin_family == 6:  # AF_INET6
        return ""


def ql_hook_block_disasm(ql, address, size):
    ql.nprint("[+] Tracing basic block at 0x%x\n" % (address))


def ql_hook_code_disasm(ql, address, size):
    uc = ql.uc
    tmp = uc.mem_read(address, size)

    if (ql.arch == QL_ARM): # QL_ARM
        reg_cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        mode = CS_MODE_ARM
        # ql.nprint("cpsr : " + bin(reg_cpsr))
        if reg_cpsr & 0b100000 != 0:
            mode = CS_MODE_THUMB
        md = Cs(CS_ARCH_ARM, mode)
        syscall_num = [uc.reg_read(UC_ARM_REG_R7),"R7"]
        arg_0 = [uc.reg_read(UC_ARM_REG_R0),"R0"]
        arg_1 = [uc.reg_read(UC_ARM_REG_R1),"R1"]
        arg_2 = [uc.reg_read(UC_ARM_REG_R2),"R2"]
        arg_3 = [uc.reg_read(UC_ARM_REG_R3),"R3"]
        arg_4 = [uc.reg_read(UC_ARM_REG_R4),"R4"]
        arg_5 = [uc.reg_read(UC_ARM_REG_R5),"R5"]

    elif (ql.arch == QL_X86): # QL_X86
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        if ql.ostype == QL_MACOS:
            syscall_num = [uc.reg_read(UC_X86_REG_EAX),"EAX"]
            arg_0 = [uc.reg_read(UC_X86_REG_ESP + 4 * 1),"ESP_1"]
            arg_1 = [uc.reg_read(UC_X86_REG_ESP + 4 * 2),"ESP_2"]
            arg_2 = [uc.reg_read(UC_X86_REG_ESP + 4 * 3),"ESP_3"]
            arg_3 = [uc.reg_read(UC_X86_REG_ESP + 4 * 4),"ESP_4"]
            arg_4 = [uc.reg_read(UC_X86_REG_ESP + 4 * 5),"ESP_5"]
            arg_5 = [uc.reg_read(UC_X86_REG_ESP + 4 * 6),"ESP_6"]
        else:
            syscall_num = [uc.reg_read(UC_X86_REG_EAX),"EAX"]
            arg_0 = [uc.reg_read(UC_X86_REG_EBX),"EBX"]
            arg_1 = [uc.reg_read(UC_X86_REG_ECX),"ECX"]
            arg_2 = [uc.reg_read(UC_X86_REG_EDX),"EDX"]
            arg_3 = [uc.reg_read(UC_X86_REG_ESI),"ESI"]
            arg_4 = [uc.reg_read(UC_X86_REG_EDI),"EDI"]
            arg_5 = [uc.reg_read(UC_X86_REG_EBP),"EBP"]

    elif (ql.arch == QL_X8664): # QL_X86_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        syscall_num = [uc.reg_read(UC_X86_REG_RAX),"RAX"]
        arg_0 = [uc.reg_read(UC_X86_REG_RDI),"RDI"]
        arg_1 = [uc.reg_read(UC_X86_REG_RSI),"RSI"]
        arg_2 = [uc.reg_read(UC_X86_REG_RDX),"RDX"]
        arg_3 = [uc.reg_read(UC_X86_REG_R10),"R10"]
        arg_4 = [uc.reg_read(UC_X86_REG_R8),"R8"]
        arg_5 = [uc.reg_read(UC_X86_REG_R9),"R9"]

    elif (ql.arch == QL_ARM64): # QL_ARM64
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        syscall_num = [uc.reg_read(UC_ARM64_REG_X0),"X7"]
        arg_0 = [uc.reg_read(UC_ARM64_REG_X0),"X0"]
        arg_1 = [uc.reg_read(UC_ARM64_REG_X1),"X1"]
        arg_2 = [uc.reg_read(UC_ARM64_REG_X2),"X2"]
        arg_3 = [uc.reg_read(UC_ARM64_REG_X3),"X3"]
        arg_4 = [uc.reg_read(UC_ARM64_REG_X4),"X4"]
        arg_5 = [uc.reg_read(UC_ARM64_REG_X5),"X5"]

    elif (ql.arch in (QL_MIPS32EL, QL_MIPS32)): # QL_MIPS32
        if ql.archendian == QL_ENDIAN_EB:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        else:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)    
        syscall_num = [uc.reg_read(UC_MIPS_REG_V0),"V0"]
        arg_0 = [uc.reg_read(UC_MIPS_REG_A0),"A0"]
        arg_1 = [uc.reg_read(UC_MIPS_REG_A1),"A1"]
        arg_2 = [uc.reg_read(UC_MIPS_REG_A2),"A2"]
        arg_3 = [uc.reg_read(UC_MIPS_REG_A3),"A3"]
        arg_4 = uc.reg_read(UC_MIPS_REG_SP)
        arg_4 = [arg_4 + 0x10, "SP+0x10"]
        arg_5 = uc.reg_read(UC_MIPS_REG_SP)
        arg_5 = [arg_5 + 0x14, "SP+0x14"]

    else:
        raise QlErrorArch("[!] Unknown arch defined in utils.py (debug output mode)")

    insn = md.disasm(tmp, address)
    opsize = int(size)

    ql.nprint("[+] 0x%x\t" %(address))

    for i in tmp:
        ql.nprint(" %02x" %i)

    if opsize < 4:
        ql.nprint("\t  ")

    for i in insn:
        ql.nprint('\t%s \t%s\n' %(i.mnemonic, i.op_str))

    if ql.output == QL_OUT_DUMP:
        ql.nprint("[-] %s= 0x%x %s= 0x%x %s= 0x%x %s= 0x%x %s= 0x%x %s= 0x%x %s= 0x%x\n" % \
            (syscall_num[1], syscall_num[0], arg_0[1], arg_0[0], arg_1[1], arg_1[0], arg_2[1], arg_2[0], arg_3[1], arg_3[0], arg_4[1], arg_4[0], arg_5[1], arg_5[0]))


def ql_setup_output(ql):
    if ql.output in (QL_OUT_DISASM, QL_OUT_DUMP):
        if ql.output == QL_OUT_DUMP:
            ql.hook_block(ql_hook_block_disasm)
        ql.hook_code(ql_hook_code_disasm)


def ql_asm2bytes(ql, archtype, runcode, arm_thumb):

    def ks_convert(arch):
        adapter = {
            QL_X86: (KS_ARCH_X86, KS_MODE_32),
            QL_X8664: (KS_ARCH_X86, KS_MODE_64),
            QL_MIPS32EL: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN),
            QL_ARM: (KS_ARCH_ARM, KS_MODE_ARM),
            QL_ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
            QL_ARM64: (KS_ARCH_ARM64, KS_MODE_ARM),
            }

        if arch in adapter:
            return adapter[arch]
        # invalid
        return None, None


    def compile_instructions(fname, archtype, archmode):
        f = open(fname, 'rb')
        assembly = f.read()
        f.close()

        ks = Ks(archtype, archmode)

        shellcode = ''
        try:
            # Initialize engine in X86-32bit mode
            encoding, count = ks.asm(assembly)
            shellcode = ''.join('%02x'%i for i in encoding)
            shellcode = unhexlify(shellcode)

        except KsError as e:
            print("ERROR Keystone Compile Error: %s" % e)
            exit

        return shellcode   

    if arm_thumb == 1 and archtype == QL_ARM:
        archtype = QL_ARM_THUMB
    
    archtype, archmode = ks_convert(archtype)
    return compile_instructions(runcode, archtype, archmode)


def ql_transform_to_link_path(ql, path):
    if ql.thread_management != None:
        cur_path = ql.thread_management.cur_thread.get_current_path()
    else:
        cur_path = ql.current_path

    rootfs = ql.rootfs

    if path[0] == '/':
        relative_path = os.path.abspath(path)
    else:
        relative_path = os.path.abspath(cur_path + '/' + path)

    from_path = None
    to_path = None
    for fm, to in ql.fs_mapper:
        fm_l = len(fm)
        if len(relative_path) >= fm_l and relative_path[ : fm_l] == fm:
            from_path = fm
            to_path = to
            break

    if from_path != None:
        real_path = os.path.abspath(to_path + relative_path[fm_l : ])
    else:
        real_path = os.path.abspath(rootfs + '/' + relative_path)

    return real_path


def ql_transform_to_real_path(ql, path):
    if ql.thread_management != None:
        cur_path = ql.thread_management.cur_thread.get_current_path()
    else:
        cur_path = ql.current_path

    rootfs = ql.rootfs

    if path[0] == '/':
        relative_path = os.path.abspath(path)
    else:
        relative_path = os.path.abspath(cur_path + '/' + path)

    from_path = None
    to_path = None
    for fm, to in ql.fs_mapper:
        fm_l = len(fm)
        if len(relative_path) >= fm_l and relative_path[ : fm_l] == fm:
            from_path = fm
            to_path = to
            break

    if from_path != None:
        real_path = os.path.abspath(to_path + relative_path[fm_l : ])
    else:
        if rootfs == None:
            rootfs = ""
        real_path = os.path.abspath(rootfs + '/' + relative_path)
            

        if os.path.islink(real_path):
            link_path = os.readlink(real_path)
            if link_path[0] == '/':
                real_path = ql_transform_to_real_path(ql, link_path)
            else:
                real_path = ql_transform_to_real_path(ql, os.path.dirname(relative_path) + '/' + link_path)

    return real_path


def ql_transform_to_relative_path(ql, path):
    if ql.thread_management != None:
        cur_path = ql.thread_management.cur_thread.get_current_path()
    else:
        cur_path = ql.current_path

    if path[0] == '/':
        relative_path = os.path.abspath(path)
    else:
        relative_path = os.path.abspath(cur_path + '/' + path)

    return relative_path


def ql_vm_to_vm_abspath(ql, relative_path):
    if path[0] == '/':
        # abspath input
        abspath = relative_path
        return os.path.abspath(abspath)
    else:
        # relative path input
        cur_path = ql_get_vm_current_path(ql)
        return os.path.abspath(cur_path + '/' + relative_path)


def ql_vm_to_real_abspath(ql, path):
    # TODO:// check Directory traversal, we have the vul
    if path[0] != '/':
        # relative path input
        cur_path = ql_get_vm_current_path(ql)
        path = cur_path + '/' + path
    return os.path.abspath(ql.rootfs + path)

def ql_real_to_vm_abspath(ql, path):
    # rm ".." in path
    abs_path = os.path.abspath(path)
    abs_rootfs = os.path.abspath(ql.rootfs)

    return '/' + abs_path.lstrip(abs_rootfs)

def ql_get_vm_current_path(ql):
    if ql.thread_management != None:
        return ql.thread_management.cur_thread.get_current_path()
    else:
        return ql.current_path

def flag_mapping(flags, mapping_name, mapping_from, mapping_to):
    ret = 0
    for n in mapping_name:
        if mapping_from[n] & flags == mapping_from[n]:
            ret = ret | mapping_to[n]
    return ret


def open_flag_mapping(flags, ql):
        
    open_flags_name = [
        "O_RDONLY",
        "O_WRONLY",
        "O_RDWR",
        "O_NONBLOCK",
        "O_APPEND",
        "O_ASYNC",
        "O_SYNC",
        "O_NOFOLLOW",
        "O_CREAT",
        "O_TRUNC",
        "O_EXCL",
        "O_NOCTTY",
        "O_DIRECTORY",
    ]

    mac_open_flags = {
        "O_RDONLY" : 0x0000,
        "O_WRONLY" : 0x0001,
        "O_RDWR"   : 0x0002,
        "O_NONBLOCK" : 0x0004,
        "O_APPEND" : 0x0008,
        "O_ASYNC" : 0x0040,
        "O_SYNC" : 0x0080,
        "O_NOFOLLOW" : 0x0100,
        "O_CREAT" : 0x0200,
        "O_TRUNC" : 0x0400,
        "O_EXCL" : 0x0800,
        "O_NOCTTY" : 0x20000,
        "O_DIRECTORY" : 0x100000
    }

    linux_open_flags = {
        'O_RDONLY' : 0,
        'O_WRONLY' : 1,
        'O_RDWR' : 2,
        'O_NONBLOCK' : 2048,
        'O_APPEND' : 1024,
        'O_ASYNC' : 8192,
        'O_SYNC' : 1052672,
        'O_NOFOLLOW' : 131072,
        'O_CREAT' : 64,
        'O_TRUNC' : 512,
        'O_EXCL' : 128,
        'O_NOCTTY' : 256,
        'O_DIRECTORY' : 65536
    }

    mips32el_open_flags = {
        'O_RDONLY'   : 0x0,
        'O_WRONLY'   : 0x1,
        'O_RDWR'     : 0x2,
        'O_NONBLOCK' : 0x80,
        'O_APPEND'   : 0x8,
        'O_ASYNC'    : 0x1000,
        'O_SYNC'     : 0x4000,
        'O_NOFOLLOW' : 0x20000,
        'O_CREAT'    : 0x100,
        'O_TRUNC'    : 0x200,
        'O_EXCL'     : 0x400,
        'O_NOCTTY'   : 0x800,
        'O_DIRECTORY': 0x100000,
    }

    if ql.arch != QL_MIPS32EL:
        if ql.platform == None or ql.platform == ql.ostype:
            return flags

        if ql.platform == QL_MACOS and ql.ostype == QL_LINUX:
            f = linux_open_flags
            t = mac_open_flags
    
        elif ql.platform == QL_LINUX and ql.ostype == QL_MACOS:
            f = mac_open_flags
            t = linux_open_flags

    elif ql.arch == QL_MIPS32EL and ql.platform == QL_LINUX:
        f = mips32el_open_flags
        t = linux_open_flags

    elif ql.arch == QL_MIPS32EL and ql.platform == QL_MACOS:
        f = mips32el_open_flags
        t = mac_open_flags

    return flag_mapping(flags, open_flags_name, f, t)


def print_function(ql, address, function_name, params, ret):
    function_name = function_name.replace('hook_', '')
    if function_name in ("__stdio_common_vfprintf", "printf"):
        return
    log = '0x%0.2x: %s(' % (address, function_name)
    for each in params:
        value = params[each]
        if type(value) == str or type(value) == bytearray:
            log += '%s = "%s", ' % (each, value)
        else:
            log += '%s = 0x%x, ' % (each, value)
    log = log.strip(", ")
    log += ')'
    if ret is not None:
        log += ' = 0x%x' % ret
    ql.nprint(log)


def read_cstring(ql, address):
    result = ""
    char = ql.uc.mem_read(address, 1)
    while char.decode() != "\x00":
        address += 1
        result += char.decode()
        char = ql.uc.mem_read(address, 1)
    return result



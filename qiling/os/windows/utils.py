#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.arch.filetype import *


def ql_windows_setup32(ql): 
    ql.PE_IMAGE_BASE = 0
    ql.PE_IMAGE_SIZE = 0
    ql.entry_point = 0

    ql.X86_PE_FUNCTION_ADDR_INIT = 0x800000
    ql.X86_PE_FUNCTION_ADDR = 0x800000
    ql.X86_PE_FUNCTION_SIZE = 0x4000

    ql.HEAP_ADDR = 0x50000000
    ql.HEAP_SIZE = 0x500000

    ql.PE = None
    ql.RUN = True

    ql.FS_SEGMENT_ADDR = 0x6000
    ql.FS_SEGMENT_SIZE = 0x6000
    ql.STRUCTERS_LAST_ADDR = ql.FS_SEGMENT_ADDR

    ql.GS_SEGMENT_ADDR = 0x5000
    ql.GS_SEGMENT_SIZE = 0x1000

    ql.DLL_ADDR = 0x1000000
    ql.DLL_SIZE = 0
    ql.DLL_LAST_ADDR = ql.DLL_ADDR


def ql_windows_setup64(ql):
    ql.code_address = 0x555555554000
    ql.code_size = 20 * 1024

    ql.GDT_ADDR = 0x333333334000
    ql.GDT_LIMIT = 0x1000
    ql.GDT_ENTRY_SIZE = 0x8

    ql.GS_SEGMENT_ADDR = 0x333333335000
    ql.GS_SEGMENT_SIZE = 0x8000
    ql.STRUCTERS_LAST_ADDR = ql.GS_SEGMENT_ADDR

    ql.DLL_ADDR = 0x7ffff79e4000
    ql.DLL_SIZE = 20 * 1024 * 1024
    ql.DLL_LAST_ADDR = ql.DLL_ADDR

    ql.HEAP_ADDR = 0x555557000000
    ql.HEAP_SIZE = 4 * 1024 * 1024

    ql.PE_IMAGE_BASE = 0
    ql.PE_IMAGE_SIZE = 0
    ql.entry_point = 0

    ql.DS_ADDR = 0
    ql.DS_SIZE = 0

    ql.CS_ADDR = 0
    ql.CS_SIZE = 0

    ql.RUN = True


# def ql_x86_windows_hook_mem_error(uc, type, addr, *args):
def ql_x86_windows_hook_mem_error(uc, addr, size, dummy0, dummy1, ql):
    ql.nprint(">>> ERROR: unmapped memory access at 0x%x" % addr)
    return False


def string_unpack(string):
    return string.decode().split("\x00")[0]


def _x86_get_args(ql, number):
    arg_list = []
    for i in range(number):
        # skip ret_addr
        arg_list.append(ql.stack_read((i + 1) * 4))
    if number == 1:
        return arg_list[0]
    else:
        return arg_list


def _x8664_get_args(ql, number):
    reg_list = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    arg_list = []
    reg_num = number
    if reg_num > 4:
        reg_num = 4
    number -= reg_num
    for i in reg_list[:reg_num]:
        arg_list.append(ql.uc.reg_read(i))
    for i in range(number):
        # skip ret_addr
        arg_list.append(ql.stack_read((i + 1) * 8))
    if reg_num == 1:
        return arg_list[0]
    else:
        return arg_list


def get_params(ql, number):
    if ql.arch == QL_X86:
        return _x86_get_args(ql, number)
    elif ql.arch == QL_X8664:
        return _x8664_get_args(ql, number)


def read_cstring(ql, address):
    result = ""
    char = ql.uc.mem_read(address, 1)
    while char.decode() != "\x00":
        address += 1
        result += char.decode()
        char = ql.uc.mem_read(address, 1)
    return result


def read_wstring(ql, address):
    result = ""
    char = ql.uc.mem_read(address, 2)
    while char.decode() != "\x00\x00":
        address += 2
        result += char.decode()
        char = ql.uc.mem_read(address, 2)
    return result


def w2cstring(string):
    return bytes(string, "ascii").decode("utf-16le")


def set_return_value(ql, ret):
    if ql.arch == QL_X86:
        ql.uc.reg_write(UC_X86_REG_EAX, ret)
    elif ql.arch == QL_X8664:
        ql.uc.reg_write(UC_X86_REG_RAX, ret)


def get_return_value(ql):
    if ql.arch == QL_X86:
        return ql.uc.reg_read(UC_X86_REG_EAX)
    elif ql.arch == QL_X8664:
        return ql.uc.reg_read(UC_X86_REG_RAX)


def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def debug_print_stack(ql, num, message=None):
    if message:
        print("========== %s ==========" % message)
    if ql.arch == QL_X86:
        sp = ql.uc.reg_read(UC_X86_REG_ESP)
    else:
        sp = ql.uc.reg_read(UC_X86_REG_RSP)
    for i in range(num):
        print(hex(sp + ql.pointersize * i) + ": " + hex(ql.stack_read(i * ql.pointersize)))

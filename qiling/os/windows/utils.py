#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.arch.filetype import *


# def ql_x86_windows_hook_mem_error(uc, type, addr, *args):
def ql_x86_windows_hook_mem_error(uc, addr, size, dummy0, dummy1, ql):
    ql.nprint("[+] ERROR: unmapped memory access at 0x%x" % addr)
    return False


def string_unpack(string):
    return string.decode().split("\x00")[0]


def x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)


def x8664_get_params_by_index(ql, index):
    reg_list = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    if index < 4:
        return ql.uc.reg_read(reg_list[index])

    index -= 4
    # skip ret_addr
    return ql.stack_read((index + 1) * 8)


def get_params_by_index(ql, index):
    if ql.arch == QL_X86:
        return x86_get_params_by_index(ql, index)
    elif ql.arch == QL_X8664:
        return x8664_get_params_by_index(ql, index)


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
        # skip ret_addr and 32 byte home space
        arg_list.append(ql.stack_read((i + 5) * 8))
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

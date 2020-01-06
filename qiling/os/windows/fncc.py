#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.os.windows.utils import *
from qiling.arch.filetype import *


def _x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)


def _x8664_get_params_by_index(ql, index):
    reg_list = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    if index < 4:
        return ql.uc.reg_read(reg_list[index])

    index -= 4
    # skip ret_addr
    return ql.stack_read((index + 1) * 8)


def _get_param_by_index(ql, index):
    if ql.arch == QL_X86:
        return _x86_get_params_by_index(ql, index)
    elif ql.arch == QL_X8664:
        return _x8664_get_params_by_index(ql, index)


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


def set_function_params(ql, in_params, out_params):
    index = 0
    for each in in_params:
        if in_params[each] == DWORD or in_params[each] == POINTER:
            out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == ULONGLONG:
            if ql.arch == QL_X86:
                low = _get_param_by_index(ql, index)
                index += 1
                high = _get_param_by_index(ql, index)
                out_params[each] = high << 8 + low
            else:
                out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == STRING:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = read_cstring(ql, ptr)
        elif in_params[each] == WSTRING:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = read_wstring(ql, ptr)
        index += 1
    return index


def get_function_param(ql, number):
    if ql.arch == QL_X86:
        return _x86_get_args(ql, number)
    elif ql.arch == QL_X8664:
        return _x8664_get_args(ql, number)


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



#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.os.macos.utils import *

DWORD = 1
UINT = 1
ULONG = 1
INT = 1
BOOL = 1
SIZE_T = 1
BYTE = 1
CHAR = 1
UCHAR = 1
USHORT = 1
SHORT = 1
ULONGLONG = 2
POINTER = 3
STRING = 4
BOOLEAN = 8
BOOL = 8


def _get_param_by_index(ql, index):
    return get_params_by_index(ql, index)


def get_params_by_index(ql, index):
    reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    if index < 6:
        return ql.uc.reg_read(reg_list[index])

    index -= 6
    # skip ret_addr
    return ql.stack_read((index + 1) * 8)


def _x8664_get_args(ql, number):
    reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    arg_list = []
    reg_num = number
    if reg_num > 6:
        reg_num = 6

    number -= reg_num
    # get args in registers first
    for i in reg_list[:reg_num]:
        arg_list.append(ql.uc.reg_read(i))

    # the rest args are from stack
    for i in range(number):
        # skip ret_addr and 32 byte home space
        arg_list.append(ql.stack_read((i + 7) * 8))

    if reg_num == 1:
        return arg_list[0]
    else:
        return arg_list


def set_function_params(ql, in_params, out_params, index=0):
    for each in in_params:
        if in_params[each] in (DWORD, POINTER, ULONGLONG):
            out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == STRING:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = macho_read_string(ql, ptr, 0x1000)
        elif in_params[each] in (BOOLEAN, BOOL):
            ptr = _get_param_by_index(ql, index)
            if ptr == 1:
                out_params[each] = "True"
            else:
                out_params[each] = "False"

        index += 1

    return index


def get_function_param(ql, number):
    return _x8664_get_args(ql, number)


def set_return_value(ql, ret):
    ql.uc.reg_write(UC_X86_REG_RAX, ret)


def get_return_value(ql):
    return ql.uc.reg_read(UC_X86_REG_RAX)


def __x86_cc(ql, passthru, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_function_params(ql, params, args[2])

    # call function
    result = func(*args, **kwargs)

    # set return value
    if result is not None:
        set_return_value(ql, result)

    # print
    print_function(ql, passthru, args[1], func.__name__, args[2], result)
    return result, param_num


def x8664_fastcall(ql, passthru, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, passthru, param_num, params, func, args, kwargs)

    if not passthru and ql.os.RUN is True:
        try:
            ql.reg.arch_pc = ql.stack_pop()
        except UcError:
            raise

    return result


def macos_kernel_api(param_num=None, params=None, passthru=False):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            return x8664_fastcall(ql, passthru, param_num, params, func, args, kwargs)
        return wrapper
    return decorator


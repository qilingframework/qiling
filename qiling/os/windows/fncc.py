#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.const import *

DWORD = 1
UINT = 1
INT = 1
BOOL = 1
SIZE_T = 1
BYTE = 1
ULONGLONG = 2
HANDLE = 3
POINTER = 3
STRING = 4
WSTRING = 5


def _x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)


def _x8664_get_params_by_index(ql, index):
    reg_list = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    if index < 4:
        return ql.register(reg_list[index])

    index -= 4
    # skip ret_addr
    return ql.stack_read((index + 5) * 8)


def _get_param_by_index(ql, index):
    if ql.archtype== QL_X86:
        return _x86_get_params_by_index(ql, index)
    elif ql.archtype== QL_X8664:
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
        arg_list.append(ql.register(i))
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
            if ql.archtype== QL_X86:
                low = _get_param_by_index(ql, index)
                index += 1
                high = _get_param_by_index(ql, index)
                out_params[each] = high << 32 + low
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
    if ql.archtype== QL_X86:
        return _x86_get_args(ql, number)
    elif ql.archtype== QL_X8664:
        return _x8664_get_args(ql, number)


def set_return_value(ql, ret):
    if ql.archtype== QL_X86:
        ql.register(UC_X86_REG_EAX, ret)
    elif ql.archtype== QL_X8664:
        ql.register(UC_X86_REG_RAX, ret)


def get_return_value(ql):
    if ql.archtype== QL_X86:
        return ql.register(UC_X86_REG_EAX)
    elif ql.archtype== QL_X8664:
        return ql.register(UC_X86_REG_RAX)


def __x86_cc(ql, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_function_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)
    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[2], result)
    return result, param_num


def x86_stdcall(ql, param_num, params, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)

    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    # update stack pointer
    ql.sp = ql.sp + ((param_num + 1) * 4)

    if ql.os.PE_RUN:
        ql.pc = ret_addr

    return result


def x86_cdecl(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    if ql.os.PE_RUN:
        ql.pc = ql.stack_pop()

    return result


def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    if ql.os.PE_RUN:
        ql.pc = ql.stack_pop()

    return result


# x86/x8664 PE should share Windows APIs
def winapi(cc, param_num=None, params=None):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @params: params dict
    @param_num: the number of function params, used by variadic functions, e.g printf
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            if ql.archtype== QL_X86:
                if cc == STDCALL:
                    return x86_stdcall(ql, param_num, params, func, args, kwargs)
                elif cc == CDECL:
                    return x86_cdecl(ql, param_num, params, func, args, kwargs)
            elif ql.archtype== QL_X8664:
                return x8664_fastcall(ql, param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown ql.arch")

        return wrapper

    return decorator

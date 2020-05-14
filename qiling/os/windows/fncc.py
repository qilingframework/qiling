#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from functools import wraps

from qiling.os.const import *
from .utils import *
from qiling.const import *
from qiling.exception import *

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
STRING_ADDR = 6
WSTRING_ADDR = 7
GUID = 8

def _x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)


def _x8664_get_params_by_index(ql, index):
    reg_list = ["rcx", "rdx", "r8", "r9"]
    if index < 4:
        return ql.reg.read(reg_list[index])

    index -= 4
    # skip ret_addr
    return ql.stack_read((index + 5) * 8)


def _get_param_by_index(ql, index):
    if ql.archtype == QL_ARCH.X86:
        return _x86_get_params_by_index(ql, index)
    elif ql.archtype == QL_ARCH.X8664:
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
    reg_list = ["rcx", "rdx", "r8", "r9"]
    arg_list = []
    reg_num = number
    if reg_num > 4:
        reg_num = 4
    number -= reg_num
    for i in reg_list[:reg_num]:
        arg_list.append(ql.reg.read(i))
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
            if ql.archtype == QL_ARCH.X86:
                low = _get_param_by_index(ql, index)
                index += 1
                high = _get_param_by_index(ql, index)
                out_params[each] = high << 32 + low
            else:
                out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == STRING or in_params[each] == STRING_ADDR:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                content = read_cstring(ql, ptr)
                if in_params[each] == STRING_ADDR:
                    out_params[each] = (ptr, content)
                else:
                    out_params[each] = content
        elif in_params[each] == WSTRING or in_params[each] == WSTRING_ADDR:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                content = read_wstring(ql, ptr)
                if in_params[each] == WSTRING_ADDR:
                    out_params[each] = (ptr, content)
                else:
                    out_params[each] = content
        elif in_params[each] == GUID:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = str(read_guid(ql, ptr))
        index += 1
    return index


def get_function_param(ql, number):
    if ql.archtype == QL_ARCH.X86:
        return _x86_get_args(ql, number)
    elif ql.archtype == QL_ARCH.X8664:
        return _x8664_get_args(ql, number)


def set_return_value(ql, ret):
    if ql.archtype == QL_ARCH.X86:
        ql.reg.eax = ret
    elif ql.archtype == QL_ARCH.X8664:
        ql.reg.rax = ret


def get_return_value(ql):
    if ql.archtype == QL_ARCH.X86:
        return ql.reg.eax
    elif ql.archtype == QL_ARCH.X8664:
        return ql.reg.rax


#
# stdcall cdecl fastcall cc
#

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


def _call_api(ql, name, params, result, address, return_address):
    params_with_values = {}
    if name.startswith("hook_"):
        name = name.split("hook_", 1)[1]
        # printfs are shit
        if params is not None:
            set_function_params(ql, params, params_with_values)
    ql.os.syscalls.setdefault(name, []).append({
        "params": params_with_values,
        "result": result,
        "address": address,
        "return_address": return_address,
        "position": ql.os.syscalls_counter
    })

    ql.os.syscalls_counter += 1


def x86_stdcall(ql, param_num, params, func, args, kwargs):
    # if we check ret_addr before the call, we can't modify the ret_addr from inside the hook
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    # get ret addr
    ret_addr = ql.stack_read(0)

    # append syscall to list
    _call_api(ql, func.__name__, params, result, ql.reg.arch_pc, ret_addr)

    # update stack pointer
    ql.reg.arch_sp = ql.reg.arch_sp + ((param_num + 1) * 4)

    if ql.os.PE_RUN:
        ql.reg.arch_pc = ret_addr

    return result


def x86_cdecl(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)
    old_pc = ql.reg.arch_pc
    # append syscall to list
    _call_api(ql, func.__name__, params, result, old_pc, ql.stack_read(0))

    if ql.os.PE_RUN:
        ql.reg.arch_pc = ql.stack_pop()

    return result


def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)
    old_pc = ql.reg.arch_pc
    # append syscall to list
    _call_api(ql, func.__name__, params, result, old_pc, ql.stack_read(0))

    if ql.os.PE_RUN:
        ql.reg.arch_pc = ql.stack_pop()

    return result


# x86/x8664 PE should share Windows APIs
def winapi(cc, param_num=None, params=None):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @params: params dict
    @param_num: the number of function params, used by variadic functions, e.g printf
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ql = args[0]
            if ql.archtype == QL_ARCH.X86:
                if cc == STDCALL:
                    return x86_stdcall(ql, param_num, params, func, args, kwargs)
                elif cc == CDECL:
                    return x86_cdecl(ql, param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.X8664:
                return x8664_fastcall(ql, param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown self.ql.arch")

        return wrapper

    return decorator

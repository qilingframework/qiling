#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null)<null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

# function calling convention

from unicorn.x86_const import *
from qiling.os.windows.utils import *
from qiling.exception import *


X86_STDCALL = 1
X86_CDECL = 2
X8664_FASTCALL = 3

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


def set_params(ql, in_params, out_params):
    index = 0
    for each in in_params:
        if in_params[each] == DWORD or in_params[each] == POINTER:
            out_params[each] = get_params_by_index(ql, index)
        elif in_params[each] == ULONGLONG:
            if ql.arch == QL_X86:
                low = get_params_by_index(ql, index)
                index += 1
                high = get_params_by_index(ql, index)
                out_params[each] = high << 8 + low
            else:
                out_params[each] = get_params_by_index(ql, index)
        elif in_params[each] == STRING:
            ptr = get_params_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = read_cstring(ql, ptr)
        elif in_params[each] == WSTRING:
            ptr = get_params_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = read_wstring(ql, ptr)
        index += 1
    return index


def print_function(ql, address, function_name, params, ret):
    function_name = function_name.replace('hook_', '')
    if function_name == "__stdio_common_vfprintf" or function_name == "printf":
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


def x86_stdcall(ql, param_num, params, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)
    # read params
    if params is not None:
        param_num = set_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)
    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[2], result)
    # add esp
    esp = ql.uc.reg_read(UC_X86_REG_ESP)
    ql.uc.reg_write(UC_X86_REG_ESP, esp + (param_num + 1) * 4)
    # ret => pop eip
    if ql.RUN:
        ql.uc.reg_write(UC_X86_REG_EIP, ret_addr)
    return result


def x86_cdecl(ql, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)
    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[2], result)
    # ret => pop eip
    if ql.RUN:
        ret_addr = ql.stack_pop()
        ql.uc.reg_write(UC_X86_REG_EIP, ret_addr)
    return result


def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)
    # read params
    if params is not None:
        param_num = set_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)
    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[2], result)
    # add rsp
    rsp = ql.uc.reg_read(UC_X86_REG_RSP)
    if param_num > 4:
        ql.uc.reg_write(UC_X86_REG_RSP, rsp + (param_num - 4 + 1) * 8)
    else:
        ql.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    # ret => pop rip
    if ql.RUN:
        ql.uc.reg_write(UC_X86_REG_RIP, ret_addr)
    return result


# x86/x8664 PE should share Windows APIs
def winapi(x86, x8664, param_num=None, params=None):
    """
    @param_num: the number of function params
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            if ql.arch == QL_X86:
                if x86 == X86_STDCALL:
                    return x86_stdcall(ql, param_num, params, func, args, kwargs)
                elif x86 == X86_CDECL:
                    return x86_cdecl(ql, param_num, params, func, args, kwargs)
            elif ql.arch == QL_X8664:
                if x8664 == X8664_FASTCALL:
                    return x8664_fastcall(ql, param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown ql.arch")
        return wrapper
    return decorator

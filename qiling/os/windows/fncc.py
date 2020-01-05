#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# function calling convention

from unicorn.x86_const import *
from qiling.os.windows.utils import *
from qiling.exception import *


STDCALL = 1
CDECL = 2

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


def __x86_cc(ql, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_params(ql, params, args[1])
    # call function
    result = func(*args, **kwargs)
    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[1], result)
    return result, param_num


def x86_stdcall(ql, param_num, params, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)
    # update stack pointer
    esp = ql.sp
    ql.sp = esp + ((param_num + 1) * 4)

    if ql.RUN:
        ql.pc = ret_addr

    return result


def x86_cdecl(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    if ql.RUN:
        ret_addr = ql.stack_pop()
        ql.pc = ret_addr

    return result


def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    # update stack pointer
    rsp = ql.sp
    if param_num > 4:
        ql.sp = rsp + ((param_num - 4 + 1) * 8)
    else:
        ql.sp = rsp + 8

    if ql.RUN:
        ql.pc = ret_addr

    return result


# x86/x8664 PE should share Windows APIs
def winapi(cc, param_num=None, params=None):
    """
    @param_num: the number of function params
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            if ql.arch == QL_X86:
                if cc == STDCALL:
                    return x86_stdcall(ql, param_num, params, func, args, kwargs)
                elif cc == CDECL:
                    return x86_cdecl(ql, param_num, params, func, args, kwargs)
            elif ql.arch == QL_X8664:
                return x8664_fastcall(ql, param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown ql.arch")
        return wrapper
    return decorator

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# function calling convention

from unicorn.x86_const import *
from qiling.os.windows.fncc import *
from qiling.exception import *


STDCALL = 1
CDECL = 2


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

    if ql.RUN:
        ql.pc = ret_addr

    return result


def x86_cdecl(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    if ql.RUN:
        ql.pc = ql.stack_pop()

    return result


def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    if ql.RUN:
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

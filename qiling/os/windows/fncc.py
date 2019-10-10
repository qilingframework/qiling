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


def x86_stdcall(ql, param_num, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)
    result = func(*args, **kwargs)
    # add esp
    esp = ql.uc.reg_read(UC_X86_REG_ESP)
    ql.uc.reg_write(UC_X86_REG_ESP, esp + (param_num + 1) * 4)
    # set ret
    if result is not None:
        ql.set_return_value(result)
    # ret => pop eip
    if ql.RUN:
        ql.uc.reg_write(UC_X86_REG_EIP, ret_addr)
    return result


def x86_cdecl(ql, param_num, func, args, kwargs):
    result = func(*args, **kwargs)
    if result is not None:
        ql.set_return_value(result)
    # ret => pop eip
    if ql.RUN:
        ret_addr = ql.stack_pop()
        ql.uc.reg_write(UC_X86_REG_EIP, ret_addr)
    return result


def x8664_fastcall(ql, param_num, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)
    result = func(*args, **kwargs)
    if result is not None:
        ql.set_return_value(result)
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
def winapi(x86, x8664, param_num, raw=False):
    """
    @param_num: the number of function params
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if raw:
                return func(*args, **kwargs)
            ql = args[0]
            if ql.arch == QL_X86:
                if x86 == X86_STDCALL:
                    return x86_stdcall(ql, param_num, func, args, kwargs)
                elif x86 == X86_CDECL:
                    return x86_cdecl(ql, param_num, func, args, kwargs)
            elif ql.arch == QL_X8664:
                if x8664 == X8664_FASTCALL:
                    return x8664_fastcall(ql, param_num, func, args, kwargs)
            else:
                raise QlErrorArch("unknown ql.arch")
        return wrapper
    return decorator

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

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

def linux_kernel_api(param_num=None, params=None):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @params: params dict
    @param_num: the number of function params, used by variadic functions, e.g printf
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            if ql.archtype == QL_ARCH.X86:
                # if cc == STDCALL:
                return ql.os.x86_stdcall(param_num, params, func, args, kwargs)
                #elif cc == CDECL:
                #    return ql.os.x86_cdecl(param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.X8664:
                return ql.os.x8664_fastcall(param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.MIPS:
                return ql.os.mips_o32_call(param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("Unknown ql.archtype")
        return wrapper
    return decorator


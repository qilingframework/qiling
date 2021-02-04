#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.x86_const import *

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

def macos_kernel_api(param_num=None, params=None, passthru=False):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            return ql.os.x8664_fastcall(param_num, params, func, args, kwargs, passthru)
        return wrapper
    return decorator


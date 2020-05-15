#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.const import *
from qiling.os.fncc import *
from qiling.os.windows.utils import read_cstring, read_wstring, read_guid, print_function

def dxeapi(param_num=None, params=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            arg = (ql, ql.reg.arch_pc, {})
            f = func
            if func.__name__ in ql.loader.user_defined_api:
                f = ql.loader.user_defined_api[func.__name__]
            return x8664_fastcall(ql, param_num, params, f, arg, kwargs)

        return wrapper

    return decorator

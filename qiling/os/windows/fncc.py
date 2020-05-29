#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from functools import wraps

from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.const import *
from qiling.exception import *


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
                    return ql.os.x86_stdcall(param_num, params, func, args, kwargs)
                elif cc == CDECL:
                    return ql.os.x86_cdecl(param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.X8664:
                return ql.os.x8664_fastcall(param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown self.ql.arch")

        return wrapper

    return decorator

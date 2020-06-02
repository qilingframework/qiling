#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.const import *

def dxeapi(param_num=None, params=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            arg = (ql, ql.reg.arch_pc, {})
            f = func

            if func.__name__ in ql.loader.user_defined_api:
                f = ql.loader.user_defined_api[func.__name__]
            
            if func.__name__ in ql.loader.user_defined_api_onenter:
                ql.os.winapi_func_onenter = ql.loader.user_defined_api_onenter[func.__name__]
            else:    
                ql.os.winapi_func_onenter = None

            if func.__name__ in ql.loader.user_defined_api_onexit:
                ql.os.winapi_func_onexit = ql.loader.user_defined_api_onexit[func.__name__]
            else:    
                ql.os.winapi_func_onexit = None                

            return ql.os.x8664_fastcall(param_num, params, f, arg, kwargs)

        return wrapper

    return decorator

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import wraps

def dxeapi(param_num=None, params=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ql = args[0]
            arg = (ql, ql.reg.arch_pc, {})

            f = ql.os.user_defined_api.get(func.__name__, func)
            ql.os.api_func_onenter = ql.os.user_defined_api_onenter.get(func.__name__, None)
            ql.os.api_func_onexit = ql.os.user_defined_api_onexit.get(func.__name__, None)

            return ql.os.x8664_fastcall(param_num, params, f, arg, kwargs)

        return wrapper

    return decorator

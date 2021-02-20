#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

def dxeapi(param_num=None, params={}):
    def decorator(func):
        def wrapper(ql, *args, **kwargs):
            return ql.os.call(func, params)

        return wrapper

    return decorator

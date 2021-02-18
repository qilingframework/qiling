#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

def dxeapi(param_num=None, params=None):
    def decorator(func):
        def wrapper(ql, *args, **kwargs):
            f = ql.loader.user_defined_api.get(func.__name__, func)

            return ql.os.call(f, params)

        return wrapper

    return decorator

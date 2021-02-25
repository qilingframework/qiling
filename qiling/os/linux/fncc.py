#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def linux_kernel_api(param_num=None, params={}):
    def decorator(func):
        def wrapper(ql: Qiling, *args, **kwargs):
            return ql.os.call(func, params)

        return wrapper

    return decorator

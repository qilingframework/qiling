#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_INTERCEPT

def macos_kernel_api(param_num=None, params={}, passthru=False):
    def decorator(func):
        def wrapper(ql: Qiling, pc: int, api_name: str):
            onenter = ql.os.user_defined_api[QL_INTERCEPT.ENTER].get(api_name)
            onexit = ql.os.user_defined_api[QL_INTERCEPT.EXIT].get(api_name)

            return ql.os.call(pc, func, params, onenter, onexit, passthru=passthru)

        return wrapper

    return decorator

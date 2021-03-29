#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Any, Mapping

from qiling import Qiling
from qiling.const import QL_INTERCEPT

def dxeapi(params: Mapping[str, Any] = {}):
    def decorator(func):
        def wrapper(ql: Qiling):
            pc = ql.reg.arch_pc
            fname = func.__name__

            f = ql.os.user_defined_api[QL_INTERCEPT.CALL].get(fname) or func
            onenter = ql.os.user_defined_api[QL_INTERCEPT.ENTER].get(fname)
            onexit = ql.os.user_defined_api[QL_INTERCEPT.EXIT].get(fname)

            return ql.os.call(pc, f, params, onenter, onexit)

        return wrapper

    return decorator

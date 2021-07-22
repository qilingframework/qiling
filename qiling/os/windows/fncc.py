#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import wraps
from typing import Any, Mapping

from qiling import Qiling
from qiling.const import QL_INTERCEPT

# calling conventions
STDCALL = 1
CDECL   = 2
MS64    = 3

def winsdkapi(cc: int, params: Mapping[str, Any] = {}, passthru: bool = False):
    def decorator(func):
        @wraps(func)
        def wrapper(ql: Qiling, pc: int, api_name: str):
            ql.os.fcall = ql.os.fcall_select(cc)

            onenter = ql.os.user_defined_api[QL_INTERCEPT.ENTER].get(api_name)
            onexit = ql.os.user_defined_api[QL_INTERCEPT.EXIT].get(api_name)

            return ql.os.call(pc, func, params, onenter, onexit, passthru=passthru)

        return wrapper

    return decorator

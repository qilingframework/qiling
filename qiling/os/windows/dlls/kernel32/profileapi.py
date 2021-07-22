#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# BOOL QueryPerformanceCounter(
#   LARGE_INTEGER *lpPerformanceCount
# );
@winsdkapi(cc=STDCALL, params={
    'lpPerformanceCount' : POINTER
})
def hook_QueryPerformanceCounter(ql: Qiling, address: int, params):
    return 0

# BOOL QueryPerformanceFrequency(
#  LARGE_INTEGER *lpFrequency
# );
@winsdkapi(cc=STDCALL, params={
    'lpFrequency' : POINTER
})
def hook_QueryPerformanceFrequency(ql: Qiling, address: int, params):
    lpFrequency = params['lpFrequency']

    ql.mem.write(lpFrequency, ql.pack64(10000000))

    return 1

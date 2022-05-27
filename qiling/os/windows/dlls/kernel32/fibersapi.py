#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# DWORD FlsFree(
#  DWORD dwFlsIndex
# );
@winsdkapi(cc=STDCALL, params={
    'dwFlsIndex' : DWORD
})
def hook_FlsFree(ql: Qiling, address: int, params):
    return int(ql.os.fiber_manager.free(params['dwFlsIndex']))

# LPVOID FlsGetValue(
#  DWORD dwFlsIndex
# );
@winsdkapi(cc=STDCALL, params={
    'dwFlsIndex' : DWORD
})
def hook_FlsGetValue(ql: Qiling, address: int, params):
    return ql.os.fiber_manager.get(params['dwFlsIndex'])

# BOOL FlsSetValue(
#  DWORD dwFlsIndex
#  PVOID lpFlsData
# );
@winsdkapi(cc=STDCALL, params={
    'dwFlsIndex' : DWORD,
    'lpFlsData'  : PVOID
})
def hook_FlsSetValue(ql: Qiling, address: int, params):
    return int(ql.os.fiber_manager.set(params['dwFlsIndex'], params['lpFlsData']))

# DWORD FlsAlloc(
#  PFLS_CALLBACK_FUNCTION lpCallback
# );
@winsdkapi(cc=STDCALL, params={
    'lpCallback' : PFLS_CALLBACK_FUNCTION
})
def hook_FlsAlloc(ql: Qiling, address: int, params):
    cb = params['lpCallback']

    return ql.os.fiber_manager.alloc(cb or None)

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

dllname = 'kernel32_dll'

# DWORD FlsFree(
#  DWORD dwFlsIndex
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'UINT'})
def hook_FlsFree(ql, address, params):
    return ql.os.fiber_manager.free(params['dwFlsIndex'])


# LPVOID FlsGetValue(
#  DWORD dwFlsIndex
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'UINT'})
def hook_FlsGetValue(ql, address, params):
    return ql.os.fiber_manager.get(params['dwFlsIndex'])


# LPVOID FlsSetValue(
#  DWORD dwFlsIndex
#  PVOID lpFlsData
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'UINT'})
def hook_FlsSetValue(ql, address, params):
    return ql.os.fiber_manager.set(params['dwFlsIndex'], params['lpFlsData'])


# DWORD FlsAlloc(
#  PFLS_CALLBACK_FUNCTION lpCallback
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_FlsAlloc(ql, address, params):
    # global cb = params['lpCallback']
    cb = params['lpCallback']
    if cb:
        return ql.os.fiber_manager.alloc(cb)
    else:
        return ql.os.fiber_manager.alloc()

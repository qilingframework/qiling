#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.fncc import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# DWORD FlsFree(
#  DWORD dwFlsIndex
# );
@winapi(cc=STDCALL, params={
    "dwFlsIndex": UINT
})
def hook_FlsFree(self, address, params):
    return self.fiber_manager.free(params['dwFlsIndex'])


# LPVOID FlsGetValue(
#  DWORD dwFlsIndex
# );
@winapi(cc=STDCALL, params={
    "dwFlsIndex": UINT})
def hook_FlsGetValue(self, address, params):
    return self.fiber_manager.get(params['dwFlsIndex'])


# LPVOID FlsSetValue(
#  DWORD dwFlsIndex
# );
@winapi(cc=STDCALL, params={
    "dwFlsIndex": UINT,
    "lpFlsValue": POINTER
})
def hook_FlsSetValue(self, address, params):
    return self.fiber_manager.set(params['dwFlsIndex'], params['lpFlsValue'])


# DWORD FlsAlloc(
#  PFLS_CALLBACK_FUNCTION lpCallback
# );
@winapi(cc=STDCALL, params={
    "lpCallback": POINTER
})
def hook_FlsAlloc(self, address, params):
    # global cb = params['lpCallback']
    cb = params['lpCallback']
    if cb:
        return self.fiber_manager.alloc(cb)
    else:
        return self.fiber_manager.alloc()

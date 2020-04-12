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


# LPVOID VirtualAlloc(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  flAllocationType,
#   DWORD  flProtect
# );
@winapi(cc=STDCALL, params={
    "lpAddress": POINTER,
    "dwSize": SIZE_T,
    "flAllocationType": DWORD,
    "flProtect": DWORD
})
def hook_VirtualAlloc(self, address, params):
    dwSize = params["dwSize"]
    addr = self.ql.os.heap.mem_alloc(dwSize)
    return addr


# BOOL VirtualFree(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  dwFreeType
# );
@winapi(cc=STDCALL, params={
    "lpAddress": POINTER,
    "dwSize": SIZE_T,
    "dwFreeType": DWORD
})
def hook_VirtualFree(self, address, params):
    lpAddress = params["lpAddress"]
    addr = self.ql.os.heap.mem_free(lpAddress)
    return 1


# BOOL VirtualProtect(
#  LPVOID lpAddress,
#  SIZE_T dwSize,
#  DWORD  flNewProtect,
#  PDWORD lpflOldProtect
# );
@winapi(cc=STDCALL, params={
    "lpAddress": POINTER,
    "dwSize": UINT,
    "flNewProtect": UINT,
    "lpflOldProtect": POINTER
})
def hook_VirtualProtect(self, address, params):
    return 1

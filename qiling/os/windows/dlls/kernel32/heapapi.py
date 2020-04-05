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


# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winapi(cc=STDCALL, params={
    "flOptions": DWORD,
    "dwInitialSize": SIZE_T,
    "dwMaximumSize": SIZE_T
})
def hook_HeapCreate(ql, address, params):
    dwInitialSize = params["dwInitialSize"]
    addr = ql.heap.mem_alloc(dwInitialSize)
    return addr


# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winapi(cc=STDCALL, params={
    "hHeap": HANDLE,
    "dwFlags": DWORD,
    "dwBytes": SIZE_T
})
def hook_HeapAlloc(ql, address, params):
    ret = ql.heap.mem_alloc(params["dwBytes"])
    return ret


# SIZE_T HeapSize(
#   HANDLE  hHeap,
#   DWORD   dwFlags,
#   LPCVOID lpMem
# );
@winapi(cc=STDCALL, params={
    "hHeap": HANDLE,
    "dwFlags": DWORD,
    "lpMem": POINTER
})
def hook_HeapSize(ql, address, params):
    pointer = params["lpMem"]
    return ql.heap.mem_size(pointer)


# BOOL HeapFree(
#  HANDLE                 hHeap,
#  DWORD                  dwFlags,
#  _Frees_ptr_opt_ LPVOID lpMem
# );
@winapi(cc=STDCALL, params={
    "hHeap": HANDLE,
    "dwFlags": DWORD,
    "lpMem": POINTER
})
def hook_HeapFree(ql, address, params):
    return ql.heap.mem_free(params['lpMem'])


# BOOL HeapSetInformation(
#  HANDLE                 HeapHandle,
#  HEAP_INFORMATION_CLASS HeapInformationClass,
#  PVOID                  HeapInformation,
#  SIZE_T                 HeapInformationLength
# );
@winapi(cc=STDCALL, params={
    "HeapHandle": HANDLE,
    "HeapInformationClass": UINT,
    "HeapInformation": POINTER,
    "HeapInformationLength": UINT
})
def hook_HeapSetInformation(ql, address, params):
    return 1


# HANDLE GetProcessHeap(
# );
@winapi(cc=STDCALL, params={})
def hook_GetProcessHeap(ql, address, params):
    ret = ql.heap.start_address
    return ret

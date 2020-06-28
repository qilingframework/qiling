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

# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_HeapCreate(ql, address, params):
    dwInitialSize = params["dwInitialSize"]
    addr = ql.os.heap.alloc(dwInitialSize)
    return addr


# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_HeapAlloc(ql, address, params):
    ret = ql.os.heap.alloc(params["dwBytes"])
    return ret


# SIZE_T HeapSize(
#   HANDLE  hHeap,
#   DWORD   dwFlags,
#   LPCVOID lpMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_HeapSize(ql, address, params):
    pointer = params["lpMem"]
    return ql.os.heap.size(pointer)


# BOOL HeapFree(
#  HANDLE                 hHeap,
#  DWORD                  dwFlags,
#  _Frees_ptr_opt_ LPVOID lpMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_HeapFree(ql, address, params):
    return ql.os.heap.free(params['lpMem'])


# BOOL HeapSetInformation(
#  HANDLE                 HeapHandle,
#  HEAP_INFORMATION_CLASS HeapInformationClass,
#  PVOID                  HeapInformation,
#  SIZE_T                 HeapInformationLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'SIZE_T': 'UINT'})
def hook_HeapSetInformation(ql, address, params):
    return 1


# HANDLE GetProcessHeap(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetProcessHeap(ql, address, params):
    ret = ql.os.heap.start_address
    return ret

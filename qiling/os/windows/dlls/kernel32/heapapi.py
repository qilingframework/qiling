#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winsdkapi(cc=STDCALL, params={
    'flOptions'     : DWORD,
    'dwInitialSize' : SIZE_T,
    'dwMaximumSize' : SIZE_T
})
def hook_HeapCreate(ql: Qiling, address: int, params):
    dwInitialSize = params["dwInitialSize"]

    return ql.os.heap.alloc(dwInitialSize)

# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'dwBytes' : SIZE_T
})
def hook_HeapAlloc(ql: Qiling, address: int, params):
    dwBytes = params["dwBytes"]

    return ql.os.heap.alloc(dwBytes)

# SIZE_T HeapSize(
#   HANDLE  hHeap,
#   DWORD   dwFlags,
#   LPCVOID lpMem
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'lpMem'   : LPCVOID
})
def hook_HeapSize(ql: Qiling, address: int, params):
    pointer = params["lpMem"]

    return ql.os.heap.size(pointer)

# BOOL HeapFree(
#  HANDLE                 hHeap,
#  DWORD                  dwFlags,
#  _Frees_ptr_opt_ LPVOID lpMem
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'lpMem'   : LPVOID
})
def hook_HeapFree(ql: Qiling, address: int, params):
    lpMem = params['lpMem']

    return ql.os.heap.free(lpMem)

# BOOL HeapSetInformation(
#  HANDLE                 HeapHandle,
#  HEAP_INFORMATION_CLASS HeapInformationClass,
#  PVOID                  HeapInformation,
#  SIZE_T                 HeapInformationLength
# );
@winsdkapi(cc=STDCALL, params={
    'HeapHandle'            : HANDLE,
    'HeapInformationClass'  : HEAP_INFORMATION_CLASS,
    'HeapInformation'       : PVOID,
    'HeapInformationLength' : SIZE_T
})
def hook_HeapSetInformation(ql: Qiling, address: int, params):
    return 1

# HANDLE GetProcessHeap(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetProcessHeap(ql: Qiling, address: int, params):
    return ql.os.heap.start_address

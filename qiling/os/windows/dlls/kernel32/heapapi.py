#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import TYPE_CHECKING

from qiling.os.windows.api import *
from qiling.os.windows.const import HEAP_ZERO_MEMORY
from qiling.os.windows.fncc import STDCALL, winsdkapi


if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.os.memory import QlMemoryManager


def __zero_mem(mem: QlMemoryManager, ptr: int, size: int) -> None:
    """Zero a memory range, but avoid hogging to much on host resources.
    """

    # go by page granularity
    npages, remainder = divmod(size, mem.pagesize)

    if npages:
        zeros = b'\x00' * mem.pagesize

        for _ in range(npages):
            mem.write(ptr, zeros)
            ptr += len(zeros)

    if remainder:
        mem.write(ptr, b'\x00' * remainder)


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

def _HeapAlloc(ql: Qiling, address: int, params):
    dwFlags = params["dwFlags"]
    dwBytes = params["dwBytes"]

    ptr = ql.os.heap.alloc(dwBytes)

    if ptr and (dwFlags & HEAP_ZERO_MEMORY):
        __zero_mem(ql.mem, ptr, dwBytes)

    return ptr

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
    return _HeapAlloc(ql, address, params)

# DECLSPEC_ALLOCATOR LPVOID HeapReAlloc(
#   HANDLE                 hHeap,
#   DWORD                  dwFlags,
#   _Frees_ptr_opt_ LPVOID lpMem,
#   SIZE_T                 dwBytes
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap'   : HANDLE,
    'dwFlags' : DWORD,
    'lpMem': LPVOID,
    'dwBytes' : SIZE_T
})
def hook_HeapReAlloc(ql: Qiling, address: int, params):
    base = params["lpMem"]
    newSize = params["dwBytes"]

    if not base:
        return _HeapAlloc(ql, address, params)
    
    if newSize == 0:
        ql.os.heap.free(base)
        
        return 0

    oldSize = ql.os.heap.size(base)
    oldData = bytes(ql.mem.read(base, oldSize))
    
    ql.os.heap.free(base)

    if newSize < oldSize:
        oldData = oldData[0:newSize]

    newBase = ql.os.heap.alloc(newSize)
    if newBase:
        ql.mem.write(newBase, oldData)

    return newBase

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

# BOOL HeapValidate(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   LPCVOID lpMem
# );
@winsdkapi(cc=STDCALL, params={
    'hHeap': PVOID,
    'dwFlags': DWORD,
    'lpMem': PVOID
})
def hook_HeapValidate(ql: Qiling, address: int, params):
    hHeap = params['hHeap']
    lpMem = params['lpMem']

    if not hHeap:
        return 0
    
    # TODO: Maybe _find is a heap manager implementation
    # detail, in which case we shouldn't rely on it.
    chunk = ql.os.heap._find(lpMem)

    if not chunk:
        return 0
    
    return chunk.inuse

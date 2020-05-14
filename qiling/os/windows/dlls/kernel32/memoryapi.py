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
def hook_VirtualAlloc(ql, address, params):
    dwSize = params["dwSize"]
    addr = ql.os.heap.alloc(dwSize)
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
def hook_VirtualFree(ql, address, params):
    lpAddress = params["lpAddress"]
    ql.os.heap.free(lpAddress)
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
def hook_VirtualProtect(ql, address, params):
    return 1


# SIZE_T VirtualQuery(
#  LPCVOID                   lpAddress,
#  PMEMORY_BASIC_INFORMATION lpBuffer,
#  SIZE_T                    dwLength
# );
@winapi(cc=STDCALL, params={
    "lpAddress": POINTER,
    "lpBuffer": POINTER,
    "dwLength": UINT
})
def hook_VirtualQuery(ql, address, params):
    """
    typedef struct _MEMORY_BASIC_INFORMATION {
      PVOID  BaseAddress;
      PVOID  AllocationBase;
      DWORD  AllocationProtect;
      SIZE_T RegionSize;
      DWORD  State;
      DWORD  Protect;
      DWORD  Type;
    } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
    """
    # find chunk,
    base = None
    size = None
    for chunk in ql.os.heap.chunks:
        if chunk.address <= params['lpAddress'] < chunk.address + chunk.size:
            base = chunk.address
            size = chunk.size

    if not base and not size:
        # Page not found
        # printable = sorted(['0x%x-0x%x' % (chunk.address, chunk.address+chunk.size) for chunk in ql.os.heap.chunks])
        # ql.dprint(D_INFO, 'Could not find memory chunk containing address 0x%x in %s' % (params['lpAddress'],
        # printable))
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0

    mbi = params['lpBuffer']
    ql.mem.write(mbi, base.to_bytes(length=ql.pointersize, byteorder='little'))
    ql.mem.write(mbi + ql.pointersize * 1, base.to_bytes(length=ql.pointersize, byteorder='little'))
    ql.mem.write(mbi + ql.pointersize * 2,
                 (0x40).to_bytes(length=ql.pointersize, byteorder='little'))  # 0x40 = EXECUTE_READ_WRITE
    ql.mem.write(mbi + ql.pointersize * 3, size.to_bytes(length=ql.pointersize, byteorder='little'))
    ql.mem.write(mbi + ql.pointersize * 4,
                 (0x1000).to_bytes(length=ql.pointersize, byteorder='little'))  # 0x1000 == MEM_COMMIT
    ql.mem.write(mbi + ql.pointersize * 5,
                 (0x40).to_bytes(length=ql.pointersize, byteorder='little'))  # 0x40 = EXECUTE_READ_WRITE
    ql.mem.write(mbi + ql.pointersize * 6,
                 (0x40000).to_bytes(length=ql.pointersize, byteorder='little'))  # 0x40000 = MEM_MAPPED

    return ql.pointersize * 7

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# LPVOID VirtualAlloc(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  flAllocationType,
#   DWORD  flProtect
# );
@winsdkapi(cc=STDCALL, params={
    'lpAddress'        : LPVOID,
    'dwSize'           : SIZE_T,
    'flAllocationType' : DWORD,
    'flProtect'        : DWORD
})
def hook_VirtualAlloc(ql: Qiling, address: int, params):
    dwSize = params["dwSize"]

    return ql.os.heap.alloc(dwSize)

# BOOL VirtualFree(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  dwFreeType
# );
@winsdkapi(cc=STDCALL, params={
    'lpAddress'  : LPVOID,
    'dwSize'     : SIZE_T,
    'dwFreeType' : DWORD
})
def hook_VirtualFree(ql: Qiling, address: int, params):
    lpAddress = params["lpAddress"]

    ql.os.heap.free(lpAddress)

    return 1

# BOOL VirtualProtect(
#  LPVOID lpAddress,
#  SIZE_T dwSize,
#  DWORD  flNewProtect,
#  PDWORD lpflOldProtect
# );
@winsdkapi(cc=STDCALL, params={
    'lpAddress'      : LPVOID,
    'dwSize'         : SIZE_T,
    'flNewProtect'   : DWORD,
    'lpflOldProtect' : PDWORD
})
def hook_VirtualProtect(ql: Qiling, address: int, params):
    return 1

# SIZE_T VirtualQuery(
#  LPCVOID                   lpAddress,
#  PMEMORY_BASIC_INFORMATION lpBuffer,
#  SIZE_T                    dwLength
# );
@winsdkapi(cc=STDCALL, params={
    'lpAddress' : LPCVOID,
    'lpBuffer'  : PMEMORY_BASIC_INFORMATION,
    'dwLength'  : SIZE_T
})
def hook_VirtualQuery(ql: Qiling, address: int, params):
    # typedef struct _MEMORY_BASIC_INFORMATION {
    #   PVOID  BaseAddress;
    #   PVOID  AllocationBase;
    #   DWORD  AllocationProtect;
    #   SIZE_T RegionSize;
    #   DWORD  State;
    #   DWORD  Protect;
    #   DWORD  Type;
    # } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

    # find chunk,
    base = None
    size = None

    for chunk in ql.os.heap.chunks:
        if chunk.address <= params['lpAddress'] < chunk.address + chunk.size:
            base = chunk.address
            size = chunk.size
            break
    else:
        # Page not found
        # printable = sorted(['0x%x-0x%x' % (chunk.address, chunk.address+chunk.size) for chunk in ql.os.heap.chunks])
        # ql.log.debug('Could not find memory chunk containing address 0x%x in %s' % (params['lpAddress'],
        # printable))
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0

    mbi = params['lpBuffer']
    values = (
        base,
        base,
        0x40,   # EXECUTE_READ_WRITE
        size,
        0x1000, # MEM_COMMIT
        0x40,   # EXECUTE_READ_WRITE
        0x40000 # MEM_MAPPED
    )

    for i, v in enumerate(values):
        ql.mem.write(mbi + i * ql.pointersize, ql.pack(v))

    return ql.pointersize * len(values)

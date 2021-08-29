#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# BOOL DuplicateHandle(
#   HANDLE   hSourceProcessHandle,
#   HANDLE   hSourceHandle,
#   HANDLE   hTargetProcessHandle,
#   LPHANDLE lpTargetHandle,
#   DWORD    dwDesiredAccess,
#   BOOL     bInheritHandle,
#   DWORD    dwOptions
# );
@winsdkapi(cc=STDCALL, params={
    'hSourceProcessHandle' : HANDLE,
    'hSourceHandle'        : HANDLE,
    'hTargetProcessHandle' : HANDLE,
    'lpTargetHandle'       : LPHANDLE,
    'dwDesiredAccess'      : DWORD,
    'bInheritHandle'       : BOOL,
    'dwOptions'            : DWORD
})
def hook_DuplicateHandle(ql: Qiling, address: int, params):
    # TODO for how we manage handle, i think this doesn't work
    content = params["hSourceHandle"]
    dst = params["lpTargetHandle"]

    ql.mem.write(dst, ql.pack(content))

    return 1

# BOOL CloseHandle(
#   HANDLE hObject
# );
@winsdkapi(cc=STDCALL, params={
    'hObject' : HANDLE
})
def hook_CloseHandle(ql: Qiling, address: int, params):
    value = params["hObject"]
    handle = ql.os.handle_manager.get(value)

    if handle is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0
    else:
        if handle.permissions is not None and handle.permissions & HANDLE_FLAG_PROTECT_FROM_CLOSE >= 1:
            # FIXME: add error
            return 0
        else:
            ql.os.handle_manager.delete(value)

    return 1

# BOOL SetHandleInformation(
#   HANDLE hObject,
#   DWORD  dwMask,
#   DWORD  dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'hObject' : HANDLE,
    'dwMask'  : DWORD,
    'dwFlags' : DWORD
})
def hook_SetHandleInformation(ql: Qiling, address: int, params):
    val = params["hObject"]

    handle = ql.os.handle_manager.get(val)
    handle.permissions = params["dwFlags"]

    return 1

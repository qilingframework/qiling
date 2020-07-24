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

# BOOL DuplicateHandle(
#   HANDLE   hSourceProcessHandle,
#   HANDLE   hSourceHandle,
#   HANDLE   hTargetProcessHandle,
#   LPHANDLE lpTargetHandle,
#   DWORD    dwDesiredAccess,
#   BOOL     bInheritHandle,
#   DWORD    dwOptions
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HANDLE': 'POINTER'})
def hook_DuplicateHandle(ql, address, params):
    # TODO for how we manage handle, i think this doesn't work
    content = params["hSourceHandle"]
    dst = params["lpTargetHandle"]
    ql.mem.write(dst, content.to_bytes(length=ql.pointersize, byteorder='little'))
    return 1


# BOOL CloseHandle(
#   HANDLE hObject
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CloseHandle(ql, address, params):
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HANDLE': 'POINTER'})
def hook_SetHandleInformation(ql, address, params):
    val = params["hObject"]
    handle = ql.os.handle_manager.get(val)
    handle.permissions = params["dwFlags"]
    return 1

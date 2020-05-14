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


# LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
#   LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
# );
@winapi(cc=STDCALL, params={
    "lpTopLevelExceptionFilter": DWORD
})
def hook_SetUnhandledExceptionFilter(ql, address, params):
    addr = params["lpTopLevelExceptionFilter"]
    handle = ql.os.handle_manager.search("TopLevelExceptionHandler")
    if handle is None:
        handle = Handle(name="TopLevelExceptionHandler", obj=addr)
        ql.os.handle_manager.append(handle)
    else:
        handle.obj = addr
    return 0


# _Post_equals_last_error_ DWORD GetLastError();
@winapi(cc=STDCALL, params={})
def hook_GetLastError(ql, address, params):
    return ql.os.last_error


# void SetLastError(
#  DWORD dwErrCode
# );
@winapi(cc=STDCALL, params={
    "dwErrCode": UINT
})
def hook_SetLastError(ql, address, params):
    ql.os.last_error = params['dwErrCode']
    return 0


# LONG UnhandledExceptionFilter(
#   _EXCEPTION_POINTERS *ExceptionInfo
# );
@winapi(cc=STDCALL, params={
    "ExceptionInfo": POINTER
})
def hook_UnhandledExceptionFilter(ql, address, params):
    ret = 1
    return ret


# UINT SetErrorMode(
#   UINT uMode
# );
@winapi(cc=STDCALL, params={
    "uMode": UINT
})
def hook_SetErrorMode(ql, address, params):
    # TODO maybe this need a better implementation
    return 0


# __analysis_noreturn VOID RaiseException(
#   DWORD           dwExceptionCode,
#   DWORD           dwExceptionFlags,
#   DWORD           nNumberOfArguments,
#   const ULONG_PTR *lpArguments
# );
@winapi(cc=STDCALL, params={
    "dwExceptionCode": DWORD,
    "dwExceptionFlags": DWORD,
    "nNumberOfArguments": DWORD,
    "lpArguments": POINTER
})
def hook_RaiseException(ql, address, params):
    func_addr = ql.os.handle_manager.search("TopLevelExceptionHandler").obj

    # We have to retrieve the return address position
    code = ql.mem.read(func_addr, 0x100)
    if b"\xc3" in code:
        code = code[:code.index(b"\xc3")]
    if b"\xc2" in code:
        code = code[:code.index(b"\xc2")]
    if b"\xcb" in code:
        code = code[:code.index(b"\xcb")]
    if b"\xca" in code:
        code = code[:code.index(b"\xca")]

    ql.os.exec_arbitrary(func_addr, func_addr + len(code))

    return 0


# PVOID AddVectoredExceptionHandler(
#   ULONG                       First,
#   PVECTORED_EXCEPTION_HANDLER Handler
# );
@winapi(cc=STDCALL, params={
    "First": UINT,
    "Handler": HANDLE
})
def hook_AddVectoredExceptionHandler(ql, address, params):
    addr = params["Handler"]
    handle = ql.os.handle_manager.search("VectoredHandler")
    if handle is None:
        handle = Handle(name="VectoredHandler", obj=addr)
        ql.os.handle_manager.append(handle)
    else:
        handle.obj = addr
    return 0


# ULONG RemoveVectoredExceptionHandler(
#   PVOID Handle
# );
@winapi(cc=STDCALL, params={
    "Handler": HANDLE
})
def hook_RemoveVectoredExceptionHandler(ql, address, params):
    handle = ql.os.handle_manager.search("VectoredHandler")
    ql.os.handle_manager.delete(handle.id)
    return 0

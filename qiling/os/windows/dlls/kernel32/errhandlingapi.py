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

    size = find_size_function(ql, func_addr)

    ql.os.exec_arbitrary(func_addr, func_addr + size)

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

    # this case is an anomaly from other interrupts (from what i learned, can be wrong)
    def exec_into_0x2d(ql, into, start):
        old_sp = ql.reg.arch_sp
        # we read where this hook is supposed to return
        ret = ql.stack_pop()

        # https://github.com/LordNoteworthy/al-khaser/wiki/Anti-Debugging-Tricks#interrupt-0x2d
        pointer = ql.os.heap.alloc(0x4)
        # the value has just to be different from 0x80000003
        ql.mem.write(pointer, (0).to_bytes(4, "little"))
        double_pointer = ql.os.heap.alloc(0x4)
        ql.mem.write(double_pointer, pointer.to_bytes(4, "little"))
        # arg
        ql.stack_push(double_pointer)
        # ret
        ql.stack_push(ret)
        # func
        ql.stack_push(start)

    def exec_standard_into(ql, into, user_data):
        # FIXME: probably this works only with al-khaser.
        pointer = ql.os.heap.alloc(0x4)
        # the value has just to be different from 0x80000003
        ql.mem.write(pointer, (0).to_bytes(4, "little"))
        double_pointer = ql.os.heap.alloc(0x4)
        ql.mem.write(double_pointer, pointer.to_bytes(4, "little"))

        ql.reg.eax = double_pointer
        ql.reg.esi = user_data

    addr = params["Handler"]
    size = find_size_function(ql, addr)
    # the interrupts 0x2d, 0x3 must be hooked
    hook = ql.hook_intno(exec_standard_into, 0x3, user_data=addr)
    hook = ql.hook_intno(exec_into_0x2d, 0x2d, user_data=addr)
    handle = Handle(obj=hook)
    ql.os.handle_manager.append(handle)
    return handle.id


# ULONG RemoveVectoredExceptionHandler(
#   PVOID Handle
# );
@winapi(cc=STDCALL, params={
    "Handler": HANDLE
})
def hook_RemoveVectoredExceptionHandler(ql, address, params):
    hook = ql.os.handle_manager.get(params["Handler"]).obj
    hook.remove()
    return 0

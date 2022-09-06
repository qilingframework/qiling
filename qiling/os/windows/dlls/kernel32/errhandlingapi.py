#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *

# LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
#   LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
# );
@winsdkapi(cc=STDCALL, params={
    'lpTopLevelExceptionFilter' : LPTOP_LEVEL_EXCEPTION_FILTER
})
def hook_SetUnhandledExceptionFilter(ql: Qiling, address: int, params):
    addr = params["lpTopLevelExceptionFilter"]
    handle = ql.os.handle_manager.search("TopLevelExceptionHandler")

    if handle is None:
        handle = Handle(name="TopLevelExceptionHandler", obj=addr)
        ql.os.handle_manager.append(handle)
    else:
        handle.obj = addr

    return 0

# _Post_equals_last_error_ DWORD GetLastError();
@winsdkapi(cc=STDCALL, params={})
def hook_GetLastError(ql: Qiling, address: int, params):
    return ql.os.last_error

# void SetLastError(
#  DWORD dwErrCode
# );
@winsdkapi(cc=STDCALL, params={
    'dwErrCode' : DWORD
})
def hook_SetLastError(ql: Qiling, address: int, params):
    ql.os.last_error = params['dwErrCode']

# LONG UnhandledExceptionFilter(
#   _EXCEPTION_POINTERS *ExceptionInfo
# );
@winsdkapi(cc=STDCALL, params={
    'ExceptionInfo' : POINTER
})
def hook_UnhandledExceptionFilter(ql: Qiling, address: int, params):
    return 1

# UINT SetErrorMode(
#   UINT uMode
# );
@winsdkapi(cc=STDCALL, params={
    'uMode' : UINT
})
def hook_SetErrorMode(ql: Qiling, address: int, params):
    # TODO maybe this need a better implementation
    return 0

# __analysis_noreturn VOID RaiseException(
#   DWORD           dwExceptionCode,
#   DWORD           dwExceptionFlags,
#   DWORD           nNumberOfArguments,
#   const ULONG_PTR *lpArguments
# );
@winsdkapi(cc=STDCALL, params={
    'dwExceptionCode'    : DWORD,
    'dwExceptionFlags'   : DWORD,
    'nNumberOfArguments' : DWORD,
    'lpArguments'        : POINTER
})
def hook_RaiseException(ql: Qiling, address: int, params):
    func_addr = ql.os.handle_manager.search("TopLevelExceptionHandler").obj

    ql.os.fcall.call_native(func_addr, [], None)

    return 0

# PVOID AddVectoredExceptionHandler(
#   ULONG                       First,
#   PVECTORED_EXCEPTION_HANDLER Handler
# );
@winsdkapi(cc=STDCALL, params={
    'First'   : ULONG,
    'Handler' : PVECTORED_EXCEPTION_HANDLER
})
def hook_AddVectoredExceptionHandler(ql: Qiling, address: int, params):

    # this case is an anomaly from other interrupts (from what i learned, can be wrong)
    def exec_into_0x2d(ql: Qiling, intno: int, start):
        # we read where this hook is supposed to return
        ret = ql.stack_pop()

        # https://github.com/LordNoteworthy/al-khaser/wiki/Anti-Debugging-Tricks#interrupt-0x2d
        pointer = ql.os.heap.alloc(0x4)
        # the value has just to be different from 0x80000003
        ql.mem.write(pointer, ql.pack32(0))
        double_pointer = ql.os.heap.alloc(0x4)
        ql.mem.write(double_pointer, ql.pack32(pointer))

        # arg
        ql.stack_push(double_pointer)
        # ret
        ql.stack_push(ret)
        # func
        ql.stack_push(start)

    def exec_standard_into(ql: Qiling, intno: int, user_data):
        # FIXME: probably this works only with al-khaser.
        pointer = ql.os.heap.alloc(0x4)
        # the value has just to be different from 0x80000003
        ql.mem.write(pointer, ql.pack32(0))
        double_pointer = ql.os.heap.alloc(0x4)
        ql.mem.write(double_pointer, ql.pack32(pointer))

        ql.reg.eax = double_pointer
        ql.reg.esi = user_data

    addr = params["Handler"]

    # the interrupts 0x2d, 0x3 must be hooked
    hook = ql.hook_intno(exec_standard_into, 0x3, user_data=addr)
    hook = ql.hook_intno(exec_into_0x2d, 0x2d, user_data=addr)
    handle = Handle(obj=hook)
    ql.os.handle_manager.append(handle)
    return handle.id


# ULONG RemoveVectoredExceptionHandler(
#   PVOID Handle
# );
@winsdkapi(cc=STDCALL, params={
    'Handle' : HANDLE
})
def hook_RemoveVectoredExceptionHandler(ql: Qiling, address: int, params):
    hook = ql.os.handle_manager.get(params["Handle"]).obj
    hook.remove()

    return 0

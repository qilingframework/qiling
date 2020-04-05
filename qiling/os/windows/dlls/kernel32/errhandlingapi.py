#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.fncc import *
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
    ret = 0x4
    return ret


# _Post_equals_last_error_ DWORD GetLastError();
@winapi(cc=STDCALL, params={})
def hook_GetLastError(ql, address, params):
    return ql.commos.last_error 


# void SetLastError(
#  DWORD dwErrCode
# );
@winapi(cc=STDCALL, params={
    "dwErrCode": UINT
})
def hook_SetLastError(ql, address, params):
    ql.commos.last_error  = params['dwErrCode']
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

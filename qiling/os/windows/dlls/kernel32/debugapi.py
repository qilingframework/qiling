#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# BOOL IsDebuggerPresent();
@winsdkapi(cc=STDCALL, params={})
def hook_IsDebuggerPresent(ql: Qiling, address: int, params):
    return 0

# BOOL CheckRemoteDebuggerPresent(
#   HANDLE hProcess,
#   PBOOL  pbDebuggerPresent
# );
@winsdkapi(cc=STDCALL, params={
    'hProcess'          : HANDLE,
    'pbDebuggerPresent' : PBOOL
})
def hook_CheckRemoteDebuggerPresent(ql: Qiling, address: int, params):
    pointer = params["pbDebuggerPresent"]

    ql.mem.write(pointer, b'\x00')

    return 1

# void OutputDebugStringW(
#   LPCWSTR lpOutputString
# );
@winsdkapi(cc=STDCALL, params={
    'lpOutputString' : LPCWSTR
})
def hook_OutputDebugStringW(ql: Qiling, address: int, params):
    ql.log.info(f'OutputDebugStringW: "{params["lpOutputString"]}"')

    return 0

# void OutputDebugStringA(
#  LPCSTR lpOutputString
# );
@winsdkapi(cc=STDCALL, params={
    'lpOutputString' : LPCSTR
})
def hook_OutputDebugStringA(ql: Qiling, address: int, params):
    ql.log.info(f'OutputDebugStringA: "{params["lpOutputString"]}"')

    return 0

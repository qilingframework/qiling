#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

def __is_debugger_present(ql: Qiling) -> int:
    """Read PEB.BeingDebugger fied to determine whether debugger
    is present or not.
    """

    return ql.loader.PEB.BeingDebugged

# BOOL IsDebuggerPresent();
@winsdkapi(cc=STDCALL, params={})
def hook_IsDebuggerPresent(ql: Qiling, address: int, params):
    return __is_debugger_present(ql)

# BOOL CheckRemoteDebuggerPresent(
#   HANDLE hProcess,
#   PBOOL  pbDebuggerPresent
# );
@winsdkapi(cc=STDCALL, params={
    'hProcess'          : HANDLE,
    'pbDebuggerPresent' : PBOOL
})
def hook_CheckRemoteDebuggerPresent(ql: Qiling, address: int, params):
    pbDebuggerPresent = params['pbDebuggerPresent']

    res = __is_debugger_present(ql)
    ql.mem.write(pbDebuggerPresent, ql.pack8(res))

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

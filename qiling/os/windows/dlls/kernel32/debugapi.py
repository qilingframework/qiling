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

# BOOL IsDebuggerPresent();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_IsDebuggerPresent(ql, address, params):
    return 0


# BOOL CheckRemoteDebuggerPresent(
#   HANDLE hProcess,
#   PBOOL  pbDebuggerPresent
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CheckRemoteDebuggerPresent(ql, address, params):
    pointer = params["pbDebuggerPresent"]
    ql.mem.write(pointer, 0x0.to_bytes(1, byteorder="little"))
    return 1


# void OutputDebugStringW(
#   LPCWSTR lpOutputString
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_OutputDebugStringW(ql, address, params):
    string = params["lpOutputString"]
    ql.nprint('OutputDebugStringW: "%s"' % (string.encode()))
    return 0


# void OutputDebugStringA(
#  LPCSTR lpOutputString
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_OutputDebugStringA(ql, address, params):
    ql.nprint('OutputDebugStringA: "%s"' % (params['lpOutputString']))
    return 0

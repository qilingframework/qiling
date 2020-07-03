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

# BOOL WINAPI SetConsoleTitle(
#   _In_ LPCTSTR lpConsoleTitle
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"lpConsoleTitle": WSTRING})
def hook_SetConsoleTitleW(ql, address, params):
    return 1


# BOOL WINAPI GetConsoleScreenBufferInfo(
#   _In_  HANDLE                      hConsoleOutput,
#   _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"hConsoleOutput": HANDLE, "lpConsoleScreenBufferInfo": POINTER})
def hook_GetConsoleScreenBufferInfo(ql, address, params):
    # Todo should we really?
    return 1


# BOOL WINAPI SetConsoleTextAttribute(
#   _In_ HANDLE hConsoleOutput,
#   _In_ WORD   wAttributes
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"hConsoleOutput": HANDLE, "wAttributes": INT})
def hook_SetConsoleTextAttribute(ql, address, params):
    return 1

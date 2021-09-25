#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# BOOL WINAPI SetConsoleTitle(
#   _In_ LPCTSTR lpConsoleTitle
# );
@winsdkapi(cc=STDCALL, params={
    'lpConsoleTitle' : LPCTSTR
})
def hook_SetConsoleTitleW(ql: Qiling, address: int, params):
    return 1

# BOOL WINAPI GetConsoleScreenBufferInfo(
#   _In_  HANDLE                      hConsoleOutput,
#   _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
# );
@winsdkapi(cc=STDCALL, params={
    'hConsoleOutput'            : HANDLE,
    'lpConsoleScreenBufferInfo' : PCONSOLE_SCREEN_BUFFER_INFO
})
def hook_GetConsoleScreenBufferInfo(ql: Qiling, address: int, params):
    # Todo should we really?
    return 1

# BOOL WINAPI SetConsoleTextAttribute(
#   _In_ HANDLE hConsoleOutput,
#   _In_ WORD   wAttributes
# );
@winsdkapi(cc=STDCALL, params={
    'hConsoleOutput' : HANDLE,
    'wAttributes'    : WORD
})
def hook_SetConsoleTextAttribute(ql: Qiling, address: int, params):
    return 1

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# BOOL WINAPI GetConsoleMode(
#   _In_  HANDLE  hConsoleHandle,
#   _Out_ LPDWORD lpMode
# );
@winsdkapi(cc=STDCALL, params={
    'hConsoleHandle' : HANDLE,
    'lpMode'         : LPDWORD
})
def hook_GetConsoleMode(ql: Qiling, address: int, params):
    return 1

def _WriteConsole(ql: Qiling, address: int, params, unicode: bool) -> int:
    hConsoleOutput = params["hConsoleOutput"]
    lpBuffer = params["lpBuffer"]
    nNumberOfCharsToWrite = params["nNumberOfCharsToWrite"]
    lpNumberOfCharsWritten = params["lpNumberOfCharsWritten"]

    handle = ql.os.handle_manager.get(hConsoleOutput)

    if handle is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0

    character_size = 2 if unicode else 1
    encoding = 'utf-16le' if unicode else 'utf-8'

    text = ql.mem.read(lpBuffer, nNumberOfCharsToWrite * character_size).decode(encoding)

    if hConsoleOutput in (STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
        ql.os.stats.log_string(text)

    written = handle.obj.write(bytes(text, encoding='utf-8'))
    ql.mem.write_ptr(lpNumberOfCharsWritten, written, 4)

    return 1

# BOOL WriteConsoleW(
#   _In_       HANDLE  hConsoleOutput,
#   _In_       const VOID    *lpBuffer,
#   _In_       DWORD   nNumberOfCharsToWrite,
#   _Out_opt_  LPDWORD lpNumberOfCharsWritten,
#   _Reserved_ LPVOID  lpReserved
# );
@winsdkapi(cc=STDCALL, params={
    'hConsoleOutput'          : HANDLE,
    'lpBuffer'                : LPCVOID,
    'nNumberOfCharsToWrite'   : DWORD,
    'lpNumberOfCharsWritten' : LPDWORD,
    'lpReserved'              : LPVOID
})
def hook_WriteConsoleW(ql: Qiling, address: int, params):
    return _WriteConsole(ql, address, params, True)

# BOOL WriteConsoleA(
#   _In_       HANDLE  hConsoleOutput,
#   _In_       const VOID    *lpBuffer,
#   _In_       DWORD   nNumberOfCharsToWrite,
#   _Out_opt_  LPDWORD lpNumberOfCharsWritten,
#   _Reserved_ LPVOID  lpReserved
# );
@winsdkapi(cc=STDCALL, params={
    'hConsoleOutput'          : HANDLE,
    'lpBuffer'                : LPCVOID,
    'nNumberOfCharsToWrite'   : DWORD,
    'lpNumberOfCharsWritten' : LPDWORD,
    'lpReserved'              : LPVOID
})
def hook_WriteConsoleA(ql: Qiling, address: int, params):
    return _WriteConsole(ql, address, params, False)
#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );
@winsdkapi(cc=STDCALL, params={
    'nStdHandle' : DWORD
})
def hook_GetStdHandle(ql, address, params):
    nStdHandle = params["nStdHandle"]

    return nStdHandle

# LPSTR GetCommandLineA(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetCommandLineA(ql: Qiling, address: int, params):
    cmdline = ql.loader.cmdline + b"\x00"
    addr = ql.os.heap.alloc(len(cmdline))

    ql.mem.write(addr, cmdline)

    return addr

# LPSTR GetCommandLineW(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetCommandLineW(ql: Qiling, address: int, params):
    cmdline = ql.loader.cmdline.decode('ascii').encode('utf-16le')
    addr = ql.os.heap.alloc(len(cmdline))

    ql.mem.write(addr, cmdline)

    return addr

# LPWCH GetEnvironmentStrings(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetEnvironmentStrings(ql: Qiling, address: int, params):
    envstr = b"\x00"
    addr = ql.os.heap.alloc(len(envstr))

    ql.mem.write(addr, envstr)

    return addr

# LPWCH GetEnvironmentStringsW(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetEnvironmentStringsW(ql: Qiling, address: int, params):
    envstr = b"\x00\x00"
    addr = ql.os.heap.alloc(len(envstr))

    ql.mem.write(addr, envstr)

    return addr

# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winsdkapi(cc=STDCALL, params={
    'penv' : LPWCH
})
def hook_FreeEnvironmentStringsW(ql: Qiling, address: int, params):
    return 1

# DWORD ExpandEnvironmentStringsW(
#   LPCWSTR lpSrc,
#   LPWSTR  lpDst,
#   DWORD   nSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpSrc' : LPCWSTR,
    'lpDst' : LPWSTR,
    'nSize' : DWORD
})
def hook_ExpandEnvironmentStringsW(ql: Qiling, address: int, params):
    src: str = params["lpSrc"]
    dst: int = params["lpDst"]
    size: int = params["nSize"]

    pos = 0

    while pos < len(src):
        lmarker = src.find('%', pos)
        rmarker = src.find('%', lmarker + 1)

        if lmarker == (-1) or rmarker == (-1):
            break

        key = src[lmarker + 1:rmarker]
        val = ql.os.profile["PATH"].get(key, None)

        if val is None:
            ql.log.debug(f'profile does not contain a value for "{key}"')
            val = f'%{key}%'
        else:
            src = src.replace(f'%{key}%', val, 1)

        pos = rmarker + len(val)

    result = (src + '\x00').encode("utf-16le")

    if len(result) <= size:
        ql.mem.write(dst, result)

    return len(result)

# DWORD GetEnvironmentVariableA(
#   LPCSTR lpName,
#   LPSTR  lpBuffer,
#   DWORD  nSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpName'   : LPCSTR,
    'lpBuffer' : LPSTR,
    'nSize'    : DWORD
})
def hook_GetEnvironmentVariableA(ql: Qiling, address: int, params):
    return 0

# DWORD GetEnvironmentVariableW(
#   LPCWSTR lpName,
#   LPWSTR  lpBuffer,
#   DWORD  nSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpName'   : LPCWSTR,
    'lpBuffer' : LPWSTR,
    'nSize'    : DWORD
})
def hook_GetEnvironmentVariableW(ql: Qiling, address: int, params):
    return 0

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.fncc import *
from qiling.exception import *

dllname = 'kernel32_dll'

# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"nStdHandle": DWORD})
def hook_GetStdHandle(ql, address, params):
    nStdHandle = params["nStdHandle"]
    return nStdHandle


# LPSTR GetCommandLineA(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetCommandLineA(ql, address, params):
    cmdline = ql.loader.cmdline + b"\x00"
    addr = ql.os.heap.alloc(len(cmdline))
    ql.mem.write(addr, cmdline)
    return addr


# LPSTR GetCommandLineW(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetCommandLineW(ql, address, params):
    cmdline = ql.loader.cmdline.decode('ascii').encode('utf-16le')
    addr = ql.os.heap.alloc(len(cmdline))
    ql.mem.write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStrings(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetEnvironmentStrings(ql, address, params):
    cmdline = b"\x00"
    addr = ql.os.heap.alloc(len(cmdline))
    ql.mem.write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStringsW(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetEnvironmentStringsW(ql, address, params):
    cmdline = b"\x00\x00"
    addr = ql.os.heap.alloc(len(cmdline))
    ql.mem.write(addr, cmdline)
    return addr


# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_FreeEnvironmentStringsW(ql, address, params):
    ret = 1
    return ret


# DWORD ExpandEnvironmentStringsW(
#   LPCWSTR lpSrc,
#   LPWSTR  lpDst,
#   DWORD   nSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_ExpandEnvironmentStringsW(ql, address, params):
    string: str = params["lpSrc"]
    start = string.find("%")
    end = string.rfind("%")
    substring = string[start + 1:end]
    result = ql.os.profile["PATH"].get(substring, None)
    if result is None:
        ql.dprint(D_INFO, substring)
        raise QlErrorNotImplemented("[!] API not implemented")
    result = (string[:start] + result + string[end + 1:] + "\x00").encode("utf-16le")
    dst = params["lpDst"]
    max_size = params["nSize"]
    if len(result) <= max_size:
        ql.mem.write(dst, result)
    return len(result)


# DWORD GetEnvironmentVariableA(
#   LPCSTR lpName,
#   LPSTR  lpBuffer,
#   DWORD  nSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetEnvironmentVariableA(ql, address, params):
    ret = 0
    return ret

# DWORD GetEnvironmentVariableW(
#   LPCWSTR lpName,
#   LPWSTR  lpBuffer,
#   DWORD  nSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetEnvironmentVariableW(ql, address, params):
    ret = 0
    return ret

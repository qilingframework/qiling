#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.fncc import *
from qiling.exception import *

# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );


@winapi(cc=STDCALL, params={
    "nStdHandle": DWORD
})
def hook_GetStdHandle(self, address, params):
    nStdHandle = params["nStdHandle"]
    return nStdHandle


# LPSTR GetCommandLineA(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCommandLineA(self, address, params):
    cmdline = self.ql.loader.cmdline + b"\x00"
    addr = self.ql.os.heap.mem_alloc(len(cmdline))
    self.ql.mem.write(addr, cmdline)
    return addr


# LPSTR GetCommandLineW(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCommandLineW(self, address, params):
    cmdline = self.ql.loader.cmdline.decode('ascii').encode('utf-16le')
    addr = self.ql.os.heap.mem_alloc(len(cmdline))
    self.ql.mem.write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStrings(
# );s
@winapi(cc=STDCALL, params={})
def hook_GetEnvironmentStrings(self, address, params):
    cmdline = b"\x00"
    addr = self.ql.os.heap.mem_alloc(len(cmdline))
    self.ql.mem.write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStringsW(
# );
@winapi(cc=STDCALL, params={})
def hook_GetEnvironmentStringsW(self, address, params):
    cmdline = b"\x00\x00"
    addr = self.ql.os.heap.mem_alloc(len(cmdline))
    self.ql.mem.write(addr, cmdline)
    return addr


# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winapi(cc=STDCALL, params={
    "penv": POINTER
})
def hook_FreeEnvironmentStringsW(self, address, params):
    ret = 1
    return ret


# DWORD ExpandEnvironmentStringsW(
#   LPCWSTR lpSrc,
#   LPWSTR  lpDst,
#   DWORD   nSize
# );
@winapi(cc=STDCALL, params={
    "lpSrc": WSTRING,
    "lpDst": POINTER,
    "nSize": DWORD,
})
def hook_ExpandEnvironmentStringsW(self, address, params):
    string: str = params["lpSrc"]
    start = string.find("%")
    end = string.rfind("%")
    substring = string[start + 1:end]
    result = self.profile["PATHS"].get(substring, None)
    if result is None:
        self.ql.dprint(substring)
        raise QlErrorNotImplemented("[!] API not implemented")
    result = (string[:start] + result + string[end + 1:] + "\x00").encode("utf-16le")
    dst = params["lpDst"]
    max_size = params["nSize"]
    if len(result) <= max_size:
        self.ql.mem.write(dst, result)
    return len(result)


# DWORD GetEnvironmentVariableA(
#   LPCSTR lpName,
#   LPSTR  lpBuffer,
#   DWORD  nSize
# );
@winapi(cc=STDCALL, params={
    "lpName": STRING,
    "lpBuffer": POINTER,
    "nSize": DWORD
})
def hook_GetEnvironmentVariableA(self, address, params):
    ret = 0
    return ret


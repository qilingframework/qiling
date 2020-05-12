#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.const import *


# LPCSTR PathFindExtensionA(
#   LPWSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": STRING_ADDR
})
def hook_PathFindExtensionA(ql, address, params):
    return hook_PathFindExtensionW.__wrapped__(ql, address, params)


# LPCSTR PathFindExtensionW(
#   LPCSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": WSTRING_ADDR
})
def hook_PathFindExtensionW(ql, address, params):
    # Must return the address of the dot
    pointer = params["pszPath"][0]
    pathname = params["pszPath"][1]
    size_before_dot = len(pathname.split(".")[0])
    pointer_dot = pointer + size_before_dot
    return pointer_dot


# LPCSTR PathFindFileNameA(
#   LPCSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": STRING_ADDR
})
def hook_PathFindFileNameA(ql, address, params):
    return hook_PathFindFileNameW.__wrapped__(ql, address, params)


# LPCSTR PathFindFileNameW(
#   LPWSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": WSTRING_ADDR
})
def hook_PathFindFileNameW(ql, address, params):
    # Must return the address of the start of the filename
    pointer = params["pszPath"][0]
    pathname = params["pszPath"][1]
    size_before_last_slash = len("".join(pathname.split("\\")[:-1])) + pathname.count("\\")
    pointer_start = pointer + size_before_last_slash
    return pointer

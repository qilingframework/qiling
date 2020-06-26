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
    "pszPath": POINTER
})
def hook_PathFindExtensionA(ql, address, params):
    # Must return the address of the dot
    pointer = params["pszPath"]
    pathname = ql.os.read_wstring(pointer)
    params["pszPath"] = pathname
    size_before_dot = len(pathname.split(".")[0])
    pointer_dot = pointer + size_before_dot
    return pointer_dot


# LPCSTR PathFindExtensionW(
#   LPCSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": POINTER
})
def hook_PathFindExtensionW(ql, address, params):
    # Must return the address of the dot
    pointer = params["pszPath"]
    pathname = ql.os.read_wstring(pointer)
    params["pszPath"] = pathname
    size_before_dot = len(pathname.split(".")[0])
    pointer_dot = pointer + size_before_dot
    return pointer_dot


# LPCSTR PathFindFileNameA(
#   LPCSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": POINTER
})
def hook_PathFindFileNameA(ql, address, params):
    # Must return the address of the start of the filename
    pointer = params["pszPath"]
    pathname = ql.os.read_cstring(pointer)
    params["pszPath"] = pathname
    size_before_last_slash = len("".join(pathname.split("\\")[:-1])) + pathname.count("\\")
    pointer_start = pointer + size_before_last_slash
    return pointer


# LPCSTR PathFindFileNameW(
#   LPWSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": POINTER
})
def hook_PathFindFileNameW(ql, address, params):
    # Must return the address of the start of the filename
    pointer = params["pszPath"]
    pathname = ql.os.read_wstring(pointer)
    params["pszPath"] = pathname
    size_before_last_slash = len("".join(pathname.split("\\")[:-1])) + pathname.count("\\")
    pointer_start = pointer + size_before_last_slash
    return pointer


# int StrCmpW(
#   PCWSTR psz1,
#   PCWSTR psz2
# );
@winapi(cc=STDCALL, params={
    "psz1": WSTRING,
    "psz2": WSTRING,
})
def hook_StrCmpW(ql, address, params):
    # Copy String2 into String
    str1 = params["psz1"]
    str2 = params["psz2"]
    if str(str1) == str(str2):
        return 0
    elif str(str1) > str(str2):
        return 1
    else:
        return -1

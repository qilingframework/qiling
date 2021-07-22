#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import cmp

# LPCSTR PathFindExtensionA(
#   LPCSTR pszPath
# );
@winsdkapi(cc=STDCALL, params={
    'pszPath' : POINTER # LPCSTR
})
def hook_PathFindExtensionA(ql: Qiling, address: int, params):
    pointer = params["pszPath"]
    pathname = ql.os.utils.read_cstring(pointer)
    #params["pszPath"] = pathname

    # return a pointer to the dot, or null-terminator if there is no dot
    return pointer + len(pathname.rsplit('.', 1)[0])

# LPCSTR PathFindExtensionW(
#   LPWSTR pszPath
# );
@winsdkapi(cc=STDCALL, params={
    'pszPath' : POINTER # LPCWSTR
})
def hook_PathFindExtensionW(ql: Qiling, address: int, params):
    pointer = params["pszPath"]
    pathname = ql.os.utils.read_wstring(pointer)
    #params["pszPath"] = pathname

    # return a pointer to the dot, or null-terminator if there is no dot
    # TODO: do we need to multiply the offset by sizeof wchar?
    return pointer + len(pathname.rsplit('.', 1)[0])

# LPCSTR PathFindFileNameA(
#   LPCSTR pszPath
# );
@winsdkapi(cc=STDCALL, params={
    'pszPath' : POINTER # LPCSTR
})
def hook_PathFindFileNameA(ql: Qiling, address: int, params):
    pointer = params["pszPath"]
    pathname = ql.os.utils.read_cstring(pointer)
    #params["pszPath"] = pathname

    # return a pointer to the filename, or to the path if there is dir prefix
    return pointer + len(f'\\{pathname}'.rsplit('\\', 1)[0])

# LPCSTR PathFindFileNameW(
#   LPWSTR pszPath
# );
@winsdkapi(cc=STDCALL, params={
    'pszPath' : LPCWSTR
})
def hook_PathFindFileNameW(ql: Qiling, address: int, params):
    pointer = params["pszPath"]
    pathname = ql.os.utils.read_wstring(pointer)
    #params["pszPath"] = pathname

    # return a pointer to the filename, or to the path if there is dir prefix
    # TODO: do we need to multiply the offset by sizeof wchar?
    return pointer + len(f'\\{pathname}'.rsplit('\\', 1)[0])

# int StrCmpW(
#   PCWSTR psz1,
#   PCWSTR psz2
# );
@winsdkapi(cc=STDCALL, params={
    'psz1' : PCWSTR,
    'psz2' : PCWSTR
})
def hook_StrCmpW(ql: Qiling, address: int, params):
    str1 = params["psz1"]
    str2 = params["psz2"]

    return cmp(str1, str2)

@winsdkapi(cc=STDCALL, params={
    'psz1' : PCWSTR,
    'psz2' : PCWSTR
})
def hook_StrCmpIW(ql: Qiling, address: int, params):
    str1 = params["psz1"].lower()
    str2 = params["psz2"].lower()

    return cmp(str1, str2)

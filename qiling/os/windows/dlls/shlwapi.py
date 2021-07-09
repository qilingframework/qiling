#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import TypeVar

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# LPCSTR PathFindExtensionA(
#   LPCSTR pszPath
# );
@winsdkapi_new(cc=STDCALL, params={
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
@winsdkapi_new(cc=STDCALL, params={
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
@winsdkapi_new(cc=STDCALL, params={
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
@winsdkapi_new(cc=STDCALL, params={
    'pszPath' : LPCWSTR
})
def hook_PathFindFileNameW(ql: Qiling, address: int, params):
    pointer = params["pszPath"]
    pathname = ql.os.utils.read_wstring(pointer)
    #params["pszPath"] = pathname

    # return a pointer to the filename, or to the path if there is dir prefix
    # TODO: do we need to multiply the offset by sizeof wchar?
    return pointer + len(f'\\{pathname}'.rsplit('\\', 1)[0])

Comparable = TypeVar('Comparable', str, int)

# an alternative to Python2 cmp builtin which no longer exists in Python3
def __cmp__(a: Comparable, b: Comparable) -> int:
    return (a > b) - (a < b)

# int StrCmpW(
#   PCWSTR psz1,
#   PCWSTR psz2
# );
@winsdkapi_new(cc=STDCALL, params={
    'psz1' : PCWSTR,
    'psz2' : PCWSTR
})
def hook_StrCmpW(ql: Qiling, address: int, params):
    str1 = params["psz1"]
    str2 = params["psz2"]

    return __cmp__(str1, str2)

@winsdkapi_new(cc=STDCALL, params={
    'psz1' : PCWSTR,
    'psz2' : PCWSTR
})
def hook_StrCmpIW(ql: Qiling, address: int, params):
    str1 = params["psz1"].lower()
    str2 = params["psz2"].lower()

    return __cmp__(str1, str2)

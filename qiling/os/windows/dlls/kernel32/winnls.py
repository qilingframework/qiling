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
from qiling.const import *

dllname = 'kernel32_dll'

# BOOL SetThreadLocale(
#   LCID Locale
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LCID': 'UINT'})
def hook_SetThreadLocale(ql, address, params):
    return 0xC000  # LOCALE_CUSTOM_DEFAULT


# LCID GetThreadLocale();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetThreadLocale(ql, address, params):
    return 0xC000  # LOCALE_CUSTOM_DEFAULT


# UINT GetACP(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetACP(ql, address, params):
    return OEM_US


# BOOL GetCPInfo(
#   UINT     CodePage,
#   LPCPINFO lpCPInfo
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetCPInfo(ql, address, params):
    ret = 1
    return ret


# int GetLocaleInfoA(
#   LCID   Locale,
#   LCTYPE LCType,
#   LPSTR  lpLCData,
#   int    cchData
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LCID': 'DWORD', 'LCTYPE': 'DWORD'})
def hook_GetLocaleInfoA(ql, address, params):
    locale_value = params["Locale"]
    lctype_value = params["LCType"]
    cchData = params["cchData"]

    local_dict = LOCALE.get(locale_value, None)
    if local_dict is None:
        # raise QlErrorNotImplemented("[!] API not implemented")
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0

    lctype = local_dict[lctype_value] + "\x00"

    if cchData != 0:
        lplcdata = params["lpLCData"]
        ql.mem.write(lplcdata, lctype.encode("utf-16le"))
    return len(lctype)


# BOOL IsValidCodePage(
#  UINT CodePage
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_IsValidCodePage(ql, address, params):
    return 1


def _LCMapString(ql, address, params):
    cchDest = params["cchDest"]
    result = (params["lpSrcStr"] + "\x00").encode("utf-16le")
    dst = params["lpDestStr"]
    if cchDest != 0 and dst != 0:
        # TODO maybe do some other check, for now is working
        ql.mem.write(dst, result)
    return len(result)


# int LCMapStringW(
#   LCID    Locale,
#   DWORD   dwMapFlags,
#   LPCWSTR lpSrcStr,
#   int     cchSrc,
#   LPWSTR  lpDestStr,
#   int     cchDest
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LCMapStringW(ql, address, params):
    return _LCMapString(ql, address, params)


# int LCMapStringA(
#   LCID   Locale,
#   DWORD  dwMapFlags,
#   LPCSTR lpSrcStr,
#   int    cchSrc,
#   LPSTR  lpDestStr,
#   int    cchDest
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LCMapStringA(ql, address, params):
    return _LCMapString(ql, address, params)


# int LCMapStringEx(
#   LPCWSTR          lpLocaleName,
#   DWORD            dwMapFlags,
#   LPCWSTR          lpSrcStr,
#   int              cchSrc,
#   LPWSTR           lpDestStr,
#   int              cchDest,
#   LPNLSVERSIONINFO lpVersionInformation,
#   LPVOID           lpReserved,
#   LPARAM           sortHandle
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LCMapStringEx(ql, address, params):
    return _LCMapString(ql, address, params)


# LANGID GetUserDefaultUILanguage();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetUserDefaultUILanguage(ql, address, params):
    # TODO find better documentation
    # https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
    return ql.os.profile.getint("USER", "language")


# LANGID GetSystemDefaultUILanguage();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSystemDefaultUILanguage(ql, address, params):
    # TODO find better documentation
    # https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
    return ql.os.profile.getint("SYSTEM", "language")


# int CompareStringA(
#   LCID   Locale,
#   DWORD  dwCmpFlags,
#   PCNZCH lpString1,
#   int    cchCount1,
#   PCNZCH lpString2,
#   int    cchCount2
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CompareStringA(ql, address, params):
    st1 = params["lpString1"]
    st2 = params["lpString2"]
    if st1 < st2:
        return CSTR_LESS_THAN
    elif st1 == st2:
        return CSTR_EQUAL
    else:
        return CSTR_GREATER_THAN
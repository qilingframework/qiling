#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# BOOL SetThreadLocale(
#   LCID Locale
# );
@winsdkapi(cc=STDCALL, params={
    'Locale' : LCID
})
def hook_SetThreadLocale(ql: Qiling, address: int, params):
    return LOCALE_CUSTOM_DEFAULT

# LCID GetThreadLocale();
@winsdkapi(cc=STDCALL, params={})
def hook_GetThreadLocale(ql: Qiling, address: int, params):
    return LOCALE_CUSTOM_DEFAULT

# UINT GetACP(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetACP(ql: Qiling, address: int, params):
    return OEM_US

# BOOL GetCPInfo(
#   UINT     CodePage,
#   LPCPINFO lpCPInfo
# );
@winsdkapi(cc=STDCALL, params={
    'CodePage' : UINT,
    'lpCPInfo' : LPCPINFO
})
def hook_GetCPInfo(ql: Qiling, address: int, params):
    return 1

# int GetLocaleInfoA(
#   LCID   Locale,
#   LCTYPE LCType,
#   LPSTR  lpLCData,
#   int    cchData
# );
@winsdkapi(cc=STDCALL, params={
    'Locale'   : LCID,
    'LCType'   : LCTYPE,
    'lpLCData' : LPSTR,
    'cchData'  : INT
})
def hook_GetLocaleInfoA(ql: Qiling, address: int, params):
    locale_value = params["Locale"]
    lctype_value = params["LCType"]
    cchData = params["cchData"]

    local_dict = LOCALE.get(locale_value, None)
    if local_dict is None:
        # raise QlErrorNotImplemented("API not implemented")
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
@winsdkapi(cc=STDCALL, params={
    'CodePage' : UINT
})
def hook_IsValidCodePage(ql: Qiling, address: int, params):
    return 1

def __LCMapString(ql: Qiling, address: int, params, wstring: bool):
    lpSrcStr: str = params["lpSrcStr"]
    lpDestStr: int = params["lpDestStr"]
    cchDest: int = params["cchDest"]

    enc = "utf-16le" if wstring else "utf-8"
    res = f'{lpSrcStr}\x00'

    if cchDest and lpDestStr:
        # TODO maybe do some other check, for now is working
        ql.mem.write(lpDestStr, res.encode(enc))

    return len(res)

# int LCMapStringW(
#   LCID    Locale,
#   DWORD   dwMapFlags,
#   LPCWSTR lpSrcStr,
#   int     cchSrc,
#   LPWSTR  lpDestStr,
#   int     cchDest
# );
@winsdkapi(cc=STDCALL, params={
    'Locale'     : LCID,
    'dwMapFlags' : DWORD,
    'lpSrcStr'   : LPCWSTR,
    'cchSrc'     : INT,
    'lpDestStr'  : LPWSTR,
    'cchDest'    : INT
})
def hook_LCMapStringW(ql: Qiling, address: int, params):
    return __LCMapString(ql, address, params, True)

# int LCMapStringA(
#   LCID   Locale,
#   DWORD  dwMapFlags,
#   LPCSTR lpSrcStr,
#   int    cchSrc,
#   LPSTR  lpDestStr,
#   int    cchDest
# );
@winsdkapi(cc=STDCALL, params={
    'Locale'     : LCID,
    'dwMapFlags' : DWORD,
    'lpSrcStr'   : LPCSTR,
    'cchSrc'     : INT,
    'lpDestStr'  : LPSTR,
    'cchDest'    : INT
})
def hook_LCMapStringA(ql: Qiling, address: int, params):
    return __LCMapString(ql, address, params, False)

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
@winsdkapi(cc=STDCALL, params={
    'lpLocaleName'         : LPCWSTR,
    'dwMapFlags'           : DWORD,
    'lpSrcStr'             : LPCWSTR,
    'cchSrc'               : INT,
    'lpDestStr'            : LPWSTR,
    'cchDest'              : INT,
    'lpVersionInformation' : LPNLSVERSIONINFO,
    'lpReserved'           : LPVOID,
    'sortHandle'           : LPARAM
})
def hook_LCMapStringEx(ql: Qiling, address: int, params):
    return __LCMapString(ql, address, params, True)

# LANGID GetUserDefaultUILanguage();
@winsdkapi(cc=STDCALL, params={})
def hook_GetUserDefaultUILanguage(ql: Qiling, address: int, params):
    # TODO find better documentation
    # https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
    return ql.os.profile.getint("USER", "language")

# LANGID GetSystemDefaultUILanguage();
@winsdkapi(cc=STDCALL, params={})
def hook_GetSystemDefaultUILanguage(ql: Qiling, address: int, params):
    # TODO find better documentation
    # https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
    return ql.os.profile.getint("SYSTEM", "language")

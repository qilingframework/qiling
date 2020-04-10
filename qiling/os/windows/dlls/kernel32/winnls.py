#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.fncc import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.const import *

# BOOL SetThreadLocale(
#   LCID Locale
# );
@winapi(cc=STDCALL, params={
    "Locale": UINT
})
def hook_SetThreadLocale(self, address, params):
    return 0xC000  # LOCALE_CUSTOM_DEFAULT


# UINT GetACP(
# );
@winapi(cc=STDCALL, params={})
def hook_GetACP(self, address, params):
    return OEM_US


# BOOL GetCPInfo(
#   UINT     CodePage,
#   LPCPINFO lpCPInfo
# );
@winapi(cc=STDCALL, params={
    "CodePage": UINT,
    "lpCPInfo": POINTER
})
def hook_GetCPInfo(self, address, params):
    ret = 1
    return ret


# int GetLocaleInfoA(
#   LCID   Locale,
#   LCTYPE LCType,
#   LPSTR  lpLCData,
#   int    cchData
# );
@winapi(cc=STDCALL, params={
    "Locale": DWORD,
    "LCType": DWORD,
    "lpLCData": POINTER,
    "cchData": INT,
})
def hook_GetLocaleInfoA(self, address, params):
    locale_value = params["Locale"]
    lctype_value = params["LCType"]
    cchData = params["cchData"]

    local_dict = LOCALE.get(locale_value, None)
    if local_dict is None:
        raise QlErrorNotImplemented("[!] API not implemented")
    lctype = local_dict[lctype_value] + "\x00"

    if cchData != 0:
        lplcdata = params["lpLCData"]
        self.ql.mem.write(lplcdata, lctype.encode("utf16-le"))
    return len(lctype)


# BOOL IsValidCodePage(
#  UINT CodePage
# );
@winapi(cc=STDCALL, params={
    "CodePage": UINT
})
def hook_IsValidCodePage(self, address, params):
    return 1


def _LCMapString(self, address, params):
    cchDest = params["cchDest"]
    result = (params["lpSrcStr"] +"\x00").encode("utf-16le")
    dst = params["lpDestStr"]
    if cchDest != 0:
        # TODO maybe do some other check, for now is working
        self.ql.mem.write(dst, result)
    return len(result)


# int LCMapStringW(
#   LCID    Locale,
#   DWORD   dwMapFlags,
#   LPCWSTR lpSrcStr,
#   int     cchSrc,
#   LPWSTR  lpDestStr,
#   int     cchDest
# );
@winapi(cc=STDCALL, params={
    "Locale": POINTER,
    "dwMapFlags": DWORD,
    "lpSrcStr": WSTRING,
    "cchSrc": INT,
    "lpDestStr": POINTER,
    "cchDest": INT
})
def hook_LCMapStringW(self, address, params):
    return _LCMapString(self, address, params)


# int LCMapStringA(
#   LCID   Locale,
#   DWORD  dwMapFlags,
#   LPCSTR lpSrcStr,
#   int    cchSrc,
#   LPSTR  lpDestStr,
#   int    cchDest
# );
@winapi(cc=STDCALL, params={
    "Locale": POINTER,
    "dwMapFlags": DWORD,
    "lpSrcStr": STRING,
    "cchSrc": INT,
    "lpDestStr": POINTER,
    "cchDest": INT
})
def hook_LCMapStringA(self, address, params):
    return _LCMapString(self, address, params)


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
@winapi(cc=STDCALL, params={
    "lpLocaleName": POINTER,
    "dwMapFlags": DWORD,
    "lpSrcStr": WSTRING,
    "cchSrc": INT,
    "lpDestStr": POINTER,
    "cchDest": INT,
    "lpVersionInformation": POINTER,
    "lpReserved": UINT,
    "sortHandle": UINT

})
def hook_LCMapStringEx(self, address, params):
    return _LCMapString(self, address, params)


# LANGID GetUserDefaultUILanguage();
@winapi(cc=STDCALL, params={
})
def hook_GetUserDefaultUILanguage(self, address, params):
    # TODO find better documentation
    # https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
    self.ql.dprint(D_RPRT, "[=] Sample is checking user language!")
    return self.profile.getint("USER", "language")


# LANGID GetSystemDefaultUILanguage();
@winapi(cc=STDCALL, params={
})
def hook_GetSystemDefaultUILanguage(self, address, params):
    # TODO find better documentation
    # https://docs.microsoft.com/it-it/windows/win32/intl/language-identifiers
    self.ql.dprint(D_RPRT, "[=] Sample is checking system language!")
    return self.profile.getint("SYSTEM", "language")

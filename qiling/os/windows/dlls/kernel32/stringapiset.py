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


# BOOL GetStringTypeW(
#   DWORD                         dwInfoType,
#   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
#   int                           cchSrc,
#   LPWORD                        lpCharType
# );
@winapi(cc=STDCALL, params={
    "dwInfoType": DWORD,
    "lpSrcStr": POINTER,
    "cchSrc": INT,
    "lpCharType": POINTER
})
def hook_GetStringTypeW(ql, address, params):
    # TODO implement
    ret = 1
    return ret


#  BOOL GetStringTypeExA
#  (
#   LCID   locale,
#   DWORD  type,
#   LPCSTR src,
#   INT    count,
#   LPWORD chartype
#  )
@winapi(cc=STDCALL, params={
    "locale": POINTER,
    "type": DWORD,
    "src": STRING,
    "count": INT,
    "chartype": POINTER
})
def hook_GetStringTypeExA(ql, address, params):
    # TODO implement
    ret = 1
    return ret


# int WideCharToMultiByte(
#   UINT                               CodePage,
#   DWORD                              dwFlags,
#   _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
#   int                                cchWideChar,
#   LPSTR                              lpMultiByteStr,
#   int                                cbMultiByte,
#   LPCCH                              lpDefaultChar,
#   LPBOOL                             lpUsedDefaultChar
# );
@winapi(cc=STDCALL, params={
    "CodePage": UINT,
    "dwFlags": DWORD,
    "lpWideCharStr": WSTRING,
    "cchWideChar": INT,
    "lpMultiByteStr": POINTER,
    "cbMultiByte": INT,
    "lpDefaultChar": POINTER,
    "lpUsedDefaultChar": POINTER
})
def hook_WideCharToMultiByte(ql, address, params):
    ret = 0

    cbMultiByte = params["cbMultiByte"]
    s_lpWideCharStr = params["lpWideCharStr"]
    lpMultiByteStr = params["lpMultiByteStr"]
    s = (s_lpWideCharStr + "\x00").encode("utf-16le")
    if cbMultiByte != 0:
        ql.mem.write(lpMultiByteStr, s)
    ret = len(s)

    return ret


# int MultiByteToWideChar(
#  UINT                              CodePage,
#  DWORD                             dwFlags,
#  _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
#  int                               cbMultiByte,
#  LPWSTR                            lpWideCharStr,
#  int                               cchWideChar
# );
@winapi(cc=STDCALL, params={
    "CodePage": UINT,
    "dwFlags": UINT,
    "lpMultiByteStr": WSTRING,
    "cbMultiByte": INT,
    "lpWideCharStr": POINTER,
    "cchWideChar": INT
})
def hook_MultiByteToWideChar(ql, address, params):
    wide_str = (params['lpMultiByteStr']+"\x00").encode('utf-16le')
    if params['cchWideChar'] != 0:
        ql.mem.write(params['lpWideCharStr'], wide_str)
    return len(wide_str)

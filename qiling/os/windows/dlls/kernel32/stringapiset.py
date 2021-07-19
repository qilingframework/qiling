#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# BOOL GetStringTypeW(
#   DWORD                         dwInfoType,
#   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
#   int                           cchSrc,
#   LPWORD                        lpCharType
# );
@winsdkapi_new(cc=STDCALL, params={
    'dwInfoType' : DWORD,
    'lpSrcStr'   : LPCWCH,
    'cchSrc'     : INT,
    'lpCharType' : LPWORD
})
def hook_GetStringTypeW(ql: Qiling, address: int, params):
    # TODO: implement
    return 1

#  BOOL GetStringTypeExA
#  (
#   LCID   locale,
#   DWORD  type,
#   LPCSTR src,
#   INT    count,
#   LPWORD chartype
#  )
@winsdkapi_new(cc=STDCALL, params={
    'Locale'     : LCID,
    'dwInfoType' : DWORD,
    'lpSrcStr'   : LPCSTR,
    'cchSrc'     : INT,
    'lpCharType' : LPWORD
})
def hook_GetStringTypeExA(ql: Qiling, address: int, params):
    # TODO: implement
    return 1

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
@winsdkapi_new(cc=STDCALL, params={
    'CodePage'          : UINT,
    'dwFlags'           : DWORD,
    'lpWideCharStr'     : LPCWCH,
    'cchWideChar'       : INT,
    'lpMultiByteStr'    : LPSTR,
    'cbMultiByte'       : INT,
    'lpDefaultChar'     : LPCCH,
    'lpUsedDefaultChar' : LPBOOL
})
def hook_WideCharToMultiByte(ql: Qiling, address: int, params):
    cbMultiByte = params["cbMultiByte"]
    s_lpWideCharStr = params["lpWideCharStr"]
    lpMultiByteStr = params["lpMultiByteStr"]

    s = (s_lpWideCharStr + "\x00").encode("utf-16le")

    if cbMultiByte != 0 and lpMultiByteStr != 0:
        ql.mem.write(lpMultiByteStr, s)

    return len(s)

# int MultiByteToWideChar(
#  UINT                              CodePage,
#  DWORD                             dwFlags,
#  _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
#  int                               cbMultiByte,
#  LPWSTR                            lpWideCharStr,
#  int                               cchWideChar
# );
@winsdkapi_new(cc=STDCALL, params={
    'CodePage'       : UINT,
    'dwFlags'        : DWORD,
    'lpMultiByteStr' : WSTRING, # LPCCH
    'cbMultiByte'    : INT,
    'lpWideCharStr'  : LPWSTR,
    'cchWideChar'    : INT
})
def hook_MultiByteToWideChar(ql: Qiling, address: int, params):
    wide_str = (params['lpMultiByteStr'] + "\x00").encode('utf-16le')

    if params['cchWideChar'] != 0:
        ql.mem.write(params['lpWideCharStr'], wide_str)

    return len(wide_str)

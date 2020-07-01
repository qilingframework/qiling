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

dllname = 'kernel32_dll'

# BOOL GetStringTypeW(
#   DWORD                         dwInfoType,
#   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
#   int                           cchSrc,
#   LPWORD                        lpCharType
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCWCH': 'WSTRING'})
def hook_WideCharToMultiByte(ql, address, params):
    ret = 0

    cbMultiByte = params["cbMultiByte"]
    s_lpWideCharStr = params["lpWideCharStr"]
    lpMultiByteStr = params["lpMultiByteStr"]
    s = (s_lpWideCharStr + "\x00").encode("utf-16le")
    if cbMultiByte != 0 and lpMultiByteStr != 0:
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'UINT', 'LPCCH': 'WSTRING'})
def hook_MultiByteToWideChar(ql, address, params):
    wide_str = (params['lpMultiByteStr']+"\x00").encode('utf-16le')
    if params['cchWideChar'] != 0:
        ql.mem.write(params['lpWideCharStr'], wide_str)
    return len(wide_str)

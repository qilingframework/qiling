#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import cmp
from qiling.os.windows.const import *

# BOOL GetStringTypeW(
#   DWORD                         dwInfoType,
#   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
#   int                           cchSrc,
#   LPWORD                        lpCharType
# );
@winsdkapi(cc=STDCALL, params={
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
@winsdkapi(cc=STDCALL, params={
    'Locale'     : LCID,
    'dwInfoType' : DWORD,
    'lpSrcStr'   : LPCSTR,
    'cchSrc'     : INT,
    'lpCharType' : LPWORD
})
def hook_GetStringTypeExA(ql: Qiling, address: int, params):
    # TODO: implement
    return 1

def __encoding_name(codepage: int) -> str:
    '''Get python encoding name from codepage value.

    @see: https://docs.python.org/3.8/library/codecs.html#standard-encodings
    '''

    # mapping of special codepage values to encodings
    encodings = {
        # available only on windows hosts
        CP_ACP        : 'mbcs',
        CP_OEMCP      : 'oem',
        CP_THREAD_ACP : 'mbcs',

        # avaiable everywhere
        CP_UTF16      : 'utf-16',
        CP_UTF16BE    : 'utf-16be',
        CP_ASCII      : 'ascii',
        CP_UTF7       : 'utf-7',
        CP_UTF8       : 'utf-8'
    }

    if codepage in encodings:
        encname = encodings[codepage]

    else:
        encname = f'cp{codepage}'

    # encoding might break on the hosting system; test it and
    # fallback to windows-1252 ('western') if it fails
    try:
        _ = '\x00'.encode(encname)
    except LookupError:
        encname = 'cp1252'

    return encname

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
@winsdkapi(cc=STDCALL, params={
    'CodePage'          : UINT,
    'dwFlags'           : DWORD,
    'lpWideCharStr'     : POINTER, # WSTRING
    'cchWideChar'       : INT,
    'lpMultiByteStr'    : LPSTR,
    'cbMultiByte'       : INT,
    'lpDefaultChar'     : LPCCH,
    'lpUsedDefaultChar' : LPBOOL
})
def hook_WideCharToMultiByte(ql: Qiling, address: int, params):
    CodePage = params['CodePage']
    dwFlags = params['dwFlags']
    lpWideCharStr = params['lpWideCharStr']
    cchWideChar = params['cchWideChar']
    lpMultiByteStr = params['lpMultiByteStr']
    cbMultiByte = params["cbMultiByte"]

    if not cchWideChar:
        # TODO: set last error
        return 0

    # -1 indicates the string is null-terminated. the string is
    # read along with its null-terminator
    elif cchWideChar == 0xffffffff:
        wcstr = bytearray()
        ch = 1

        while ch != b'\x00\x00':
            ch = ql.mem.read(lpWideCharStr, 2)
            wcstr.extend(ch)

            lpWideCharStr += 2

    # read exactly cbMultiByte bytes. that may or may not include
    # a null-terminator
    else:
        wcstr = ql.mem.read(lpWideCharStr, cchWideChar * 2)

    decoded = wcstr.decode('utf-16le')

    encname = __encoding_name(CodePage)
    errors = 'strict' if dwFlags & WC_ERR_INVALID_CHARS else 'replace'

    try:
        encoded = decoded.encode(encname, errors)
    except UnicodeEncodeError:
        ql.os.last_error = ERROR_NO_UNICODE_TRANSLATION
        return 0

    if not cbMultiByte:
        return len(encoded)

    if not lpMultiByteStr:
        return 0

    ql.mem.write(lpMultiByteStr, encoded[:cbMultiByte])

    return min(len(encoded), cbMultiByte)

# int MultiByteToWideChar(
#  UINT                              CodePage,
#  DWORD                             dwFlags,
#  _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
#  int                               cbMultiByte,
#  LPWSTR                            lpWideCharStr,
#  int                               cchWideChar
# );
@winsdkapi(cc=STDCALL, params={
    'CodePage'       : UINT,
    'dwFlags'        : DWORD,
    'lpMultiByteStr' : POINTER, # STRING,
    'cbMultiByte'    : INT,
    'lpWideCharStr'  : LPWSTR,
    'cchWideChar'    : INT
})
def hook_MultiByteToWideChar(ql: Qiling, address: int, params):
    CodePage = params['CodePage']
    lpMultiByteStr = params['lpMultiByteStr']
    cbMultiByte = params['cbMultiByte']
    lpWideCharStr = params['lpWideCharStr']
    cchWideChar = params['cchWideChar']

    if not cbMultiByte:
        # TODO: set last error
        return 0

    # -1 indicates the string is null-terminated. the string is
    # read along with its null-terminator
    elif cbMultiByte == 0xffffffff:
        mbstr = bytearray()
        ch = 1

        while ch != b'\x00':
            ch = ql.mem.read(lpMultiByteStr, 1)
            mbstr.extend(ch)

            lpMultiByteStr += 1

    # read exactly cbMultiByte bytes. that may or may not include
    # a null-terminator
    else:
        mbstr = ql.mem.read(lpMultiByteStr, cbMultiByte)

    # use specified code page to translate bytes into string
    encname = __encoding_name(CodePage)
    decoded = mbstr.decode(encname)

    # this is a dry-run; just return the amount of chars
    if not cchWideChar:
        return len(decoded)

    if not lpWideCharStr:
        return 0

    ql.mem.write(lpWideCharStr, decoded[:cchWideChar].encode('utf-16le'))

    return min(len(decoded), cchWideChar)

def __CompareString(ql: Qiling, address: int, params) -> int:
    lpString1 = params["lpString1"]
    lpString2 = params["lpString2"]

    cchCount1 = params["cchCount1"]
    cchCount2 = params["cchCount2"]

    if cchCount1 > 0:
        lpString1 = lpString1[:cchCount1]

    if cchCount2 > 0:
        lpString2 = lpString2[:cchCount2]

    return cmp(lpString1, lpString2)

# int CompareStringA(
#   LCID   Locale,
#   DWORD  dwCmpFlags,
#   PCNZCH lpString1,
#   int    cchCount1,
#   PCNZCH lpString2,
#   int    cchCount2
# );
@winsdkapi(cc=STDCALL, params={
    'Locale'     : LCID,
    'dwCmpFlags' : DWORD,
    'lpString1'  : PCNZCH,
    'cchCount1'  : INT,
    'lpString2'  : PCNZCH,
    'cchCount2'  : INT
})
def hook_CompareStringA(ql: Qiling, address: int, params):
    return __CompareString(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'Locale'     : LCID,
    'dwCmpFlags' : DWORD,
    'lpString1'  : PCNZWCH,
    'cchCount1'  : INT,
    'lpString2'  : PCNZWCH,
    'cchCount2'  : INT
})
def hook_CompareStringW(ql: Qiling, address: int, params):
    return __CompareString(ql, address, params)

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *

# void InternetOpenA(
#   LPCSTR lpszAgent,
#   DWORD  dwAccessType,
#   LPCSTR lpszProxy,
#   LPCSTR lpszProxyBypass,
#   DWORD  dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpszAgent'       : LPCSTR,
    'dwAccessType'    : DWORD,
    'lpszProxy'       : LPCSTR,
    'lpszProxyBypass' : LPCSTR,
    'dwFlags'         : DWORD
})
def hook_InternetOpenA(ql: Qiling, address: int, params):
    pass

# void InternetOpenW(
#   LPCWSTR lpszAgent,
#   DWORD   dwAccessType,
#   LPCWSTR lpszProxy,
#   LPCWSTR lpszProxyBypass,
#   DWORD   dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpszAgent'       : LPCWSTR,
    'dwAccessType'    : DWORD,
    'lpszProxy'       : LPCWSTR,
    'lpszProxyBypass' : LPCWSTR,
    'dwFlags'         : DWORD
})
def hook_InternetOpenW(ql: Qiling, address: int, params):
    pass

# void InternetOpenUrlA(
#   HINTERNET hInternet,
#   LPCSTR    lpszUrl,
#   LPCSTR    lpszHeaders,
#   DWORD     dwHeadersLength,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet'       : HINTERNET,
    'lpszUrl'         : LPCSTR,
    'lpszHeaders'     : LPCSTR,
    'dwHeadersLength' : DWORD,
    'dwFlags'         : DWORD,
    'dwContext'       : DWORD_PTR
})
def hook_InternetOpenUrlA(ql: Qiling, address: int, params):
    pass

# void InternetOpenUrlW(
#   HINTERNET hInternet,
#   LPCWSTR   lpszUrl,
#   LPCWSTR   lpszHeaders,
#   DWORD     dwHeadersLength,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet'       : HINTERNET,
    'lpszUrl'         : LPCWSTR,
    'lpszHeaders'     : LPCWSTR,
    'dwHeadersLength' : DWORD,
    'dwFlags'         : DWORD,
    'dwContext'       : DWORD_PTR
})
def hook_InternetOpenUrlW(ql: Qiling, address: int, params):
    pass

# BOOLAPI InternetCloseHandle(
#   HINTERNET hInternet
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet' : HINTERNET
})
def hook_InternetCloseHandle(ql: Qiling, address: int, params):
    return 1

# void InternetConnectA(
#   HINTERNET     hInternet,
#   LPCSTR        lpszServerName,
#   INTERNET_PORT nServerPort,
#   LPCSTR        lpszUserName,
#   LPCSTR        lpszPassword,
#   DWORD         dwService,
#   DWORD         dwFlags,
#   DWORD_PTR     dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet'      : HINTERNET,
    'lpszServerName' : LPCSTR,
    'nServerPort'    : INTERNET_PORT,
    'lpszUserName'   : LPCSTR,
    'lpszPassword'   : LPCSTR,
    'dwService'      : DWORD,
    'dwFlags'        : DWORD,
    'dwContext'      : DWORD_PTR
})
def hook_InternetConnectA(ql: Qiling, address: int, params):
    pass

# void InternetConnectW(
#   HINTERNET     hInternet,
#   LPCWSTR       lpszServerName,
#   INTERNET_PORT nServerPort,
#   LPCWSTR       lpszUserName,
#   LPCWSTR       lpszPassword,
#   DWORD         dwService,
#   DWORD         dwFlags,
#   DWORD_PTR     dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet'      : HINTERNET,
    'lpszServerName' : LPCWSTR,
    'nServerPort'    : INTERNET_PORT,
    'lpszUserName'   : LPCWSTR,
    'lpszPassword'   : LPCWSTR,
    'dwService'      : DWORD,
    'dwFlags'        : DWORD,
    'dwContext'      : DWORD_PTR
})
def hook_InternetConnectW(ql: Qiling, address: int, params):
    pass

# void InternetCheckConnectionA(
#    LPCSTR lpszUrl,
#    DWORD  dwFlags,
#    DWORD  dwReserved
# );
@winsdkapi(cc=STDCALL, params={
    'lpszUrl'    : LPCSTR,
    'dwFlags'    : DWORD,
    'dwReserved' : DWORD
})
def hook_InternetCheckConnectionA(ql: Qiling, address: int, params):
    pass

# void HttpOpenRequestA(
#   HINTERNET hConnect,
#   LPCSTR    lpszVerb,
#   LPCSTR    lpszObjectName,
#   LPCSTR    lpszVersion,
#   LPCSTR    lpszReferrer,
#   LPCSTR    *lplpszAcceptTypes,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hConnect'          : HINTERNET,
    'lpszVerb'          : LPCSTR,
    'lpszObjectName'    : LPCSTR,
    'lpszVersion'       : LPCSTR,
    'lpszReferrer'      : LPCSTR,
    'lplpszAcceptTypes' : LPCSTR,
    'dwFlags'           : DWORD,
    'dwContext'         : DWORD_PTR
})
def hook_HttpOpenRequestA(ql: Qiling, address: int, params):
    pass

# vBOOLAPI HttpSendRequestExA(
#   HINTERNET           hRequest,
#   LPINTERNET_BUFFERSA lpBuffersIn,
#   LPINTERNET_BUFFERSA lpBuffersOut,
#   DWORD               dwFlags,
#   DWORD_PTR           dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hRequest'     : HINTERNET,
    'lpBuffersIn'  : LPINTERNET_BUFFERSA,
    'lpBuffersOut' : LPINTERNET_BUFFERSA,
    'dwFlags'      : DWORD,
    'dwContext'    : DWORD_PTR
})
def hook_HttpSendRequestExA(ql: Qiling, address: int, params):
    pass

# void HttpOpenRequestW(
#   HINTERNET hConnect,
#   LPCWSTR   lpszVerb,
#   LPCWSTR   lpszObjectName,
#   LPCWSTR   lpszVersion,
#   LPCWSTR   lpszReferrer,
#   LPCWSTR   *lplpszAcceptTypes,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hConnect'          : HINTERNET,
    'lpszVerb'          : LPCWSTR,
    'lpszObjectName'    : LPCWSTR,
    'lpszVersion'       : LPCWSTR,
    'lpszReferrer'      : LPCWSTR,
    'lplpszAcceptTypes' : LPCWSTR,
    'dwFlags'           : DWORD,
    'dwContext'         : DWORD_PTR
})
def hook_HttpOpenRequestW(ql: Qiling, address: int, params):
    pass

# BOOLAPI InternetSetOptionA(
#   HINTERNET hInternet,
#   DWORD     dwOption,
#   LPVOID    lpBuffer,
#   DWORD     dwBufferLength
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet'      : HINTERNET,
    'dwOption'       : DWORD,
    'lpBuffer'       : LPVOID,
    'dwBufferLength' : DWORD
})
def hook_InternetSetOptionA(ql: Qiling, address: int, params):
    return 1

# BOOLAPI InternetSetOptionW(
#   HINTERNET hInternet,
#   DWORD     dwOption,
#   LPVOID    lpBuffer,
#   DWORD     dwBufferLength
# );
@winsdkapi(cc=STDCALL, params={
    'hInternet'      : HINTERNET,
    'dwOption'       : DWORD,
    'lpBuffer'       : LPVOID,
    'dwBufferLength' : DWORD
})
def hook_InternetSetOptionW(ql: Qiling, address: int, params):
    return 1

# BOOLAPI HttpSendRequestA(
#  HINTERNET hRequest,
#  LPCSTR    lpszHeaders,
#  DWORD     dwHeadersLength,
#  LPVOID    lpOptional,
#  DWORD     dwOptionalLength
# );
@winsdkapi(cc=STDCALL, params={
    'hRequest'         : HINTERNET,
    'lpszHeaders'      : LPCSTR,
    'dwHeadersLength'  : DWORD,
    'lpOptional'       : LPVOID,
    'dwOptionalLength' : DWORD
})
def hook_HttpSendRequestA(ql: Qiling, address: int, params):
    return 1

# BOOLAPI HttpSendRequestW(
#  HINTERNET hRequest,
#  LPCWSTR   lpszHeaders,
#  DWORD     dwHeadersLength,
#  LPVOID    lpOptional,
#  DWORD     dwOptionalLength
# );
@winsdkapi(cc=STDCALL, params={
    'hRequest'         : HINTERNET,
    'lpszHeaders'      : LPCWSTR,
    'dwHeadersLength'  : DWORD,
    'lpOptional'       : LPVOID,
    'dwOptionalLength' : DWORD
})
def hook_HttpSendRequestW(ql: Qiling, address: int, params):
    return 1

# void InternetErrorDlg(
#   HWND      hWnd,
#   HINTERNET hRequest,
#   DWORD     dwError,
#   DWORD     dwFlags,
#   LPVOID    *lppvData
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'     : HWND,
    'hRequest' : HINTERNET,
    'dwError'  : DWORD,
    'dwFlags'  : DWORD,
    'lppvData' : LPVOID
})
def hook_InternetErrorDlg(ql: Qiling, address: int, params):
    pass

# BOOLAPI InternetReadFile(
#   HINTERNET hFile,
#   LPVOID    lpBuffer,
#   DWORD     dwNumberOfBytesToRead,
#   LPDWORD   lpdwNumberOfBytesRead
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'                 : HINTERNET,
    'lpBuffer'              : LPVOID,
    'dwNumberOfBytesToRead' : DWORD,
    'lpdwNumberOfBytesRead' : LPDWORD
})
def hook_InternetReadFile(ql: Qiling, address: int, params):
    return 1

# BOOLAPI InternetWriteFile(
#   HINTERNET hFile,
#   LPCVOID   lpBuffer,
#   DWORD     dwNumberOfBytesToWrite,
#   LPDWORD   lpdwNumberOfBytesWritten
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'                    : HINTERNET,
    'lpBuffer'                 : LPCVOID,
    'dwNumberOfBytesToWrite'   : DWORD,
    'lpdwNumberOfBytesWritten' : LPDWORD
})
def hook_InternetWriteFile(ql: Qiling, address: int, params):
    return 1

# BOOLAPI HttpEndRequestA(
#   HINTERNET           hRequest,
#   LPINTERNET_BUFFERSA lpBuffersOut,
#   DWORD               dwFlags,
#   DWORD_PTR           dwContext
# );
@winsdkapi(cc=STDCALL, params={
    'hRequest'     : HINTERNET,
    'lpBuffersOut' : LPINTERNET_BUFFERSA,
    'dwFlags'      : DWORD,
    'dwContext'    : DWORD_PTR
})
def hook_HttpEndRequestA(ql: Qiling, address: int, params):
    return 1

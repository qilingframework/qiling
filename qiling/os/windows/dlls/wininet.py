#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *


# void InternetOpenA(
#   LPCSTR lpszAgent,
#   DWORD  dwAccessType,
#   LPCSTR lpszProxy,
#   LPCSTR lpszProxyBypass,
#   DWORD  dwFlags
# );
@winapi(cc=STDCALL, params={
    "lpszAgent": STRING,
    "dwAccessType": DWORD,
    "lpszProxy": STRING,
    "lpszProxyBypass": STRING,
    "dwFlags": DWORD
})
def hook_InternetOpenA(ql, address, params):
    pass


# void InternetOpenW(
#   LPCWSTR lpszAgent,
#   DWORD   dwAccessType,
#   LPCWSTR lpszProxy,
#   LPCWSTR lpszProxyBypass,
#   DWORD   dwFlags
# );
@winapi(cc=STDCALL, params={
    "lpszAgent": WSTRING,
    "dwAccessType": DWORD,
    "lpszProxy": WSTRING,
    "lpszProxyBypass": WSTRING,
    "dwFlags": DWORD
})
def hook_InternetOpenW(ql, address, params):
    pass


# void InternetOpenUrlA(
#   HINTERNET hInternet,
#   LPCSTR    lpszUrl,
#   LPCSTR    lpszHeaders,
#   DWORD     dwHeadersLength,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winapi(cc=STDCALL, params={
    "hInternet": POINTER,
    "lpszUrl": STRING,
    "lpszHeaders": STRING,
    "dwHeadersLength": DWORD,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_InternetOpenUrlA(ql, address, params):
    pass


# void InternetOpenUrlW(
#   HINTERNET hInternet,
#   LPCWSTR   lpszUrl,
#   LPCWSTR   lpszHeaders,
#   DWORD     dwHeadersLength,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winapi(cc=STDCALL, params={
    "hInternet": POINTER,
    "lpszUrl": WSTRING,
    "lpszHeaders": WSTRING,
    "dwHeadersLength": DWORD,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_InternetOpenUrlW(ql, address, params):
    pass


# BOOLAPI InternetCloseHandle(
#   HINTERNET hInternet
# );
@winapi(cc=STDCALL, params={
    "hInternet": POINTER
})
def hook_InternetCloseHandle(ql, address, params):
    ret = 1
    return ret


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
@winapi(cc=STDCALL, params={
    "hInternet": POINTER,
    "lpszServerName": STRING,
    "nServerPort": DWORD,
    "lpszUserName": STRING,
    "lpszPassword": STRING,
    "dwService": DWORD,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_InternetConnectA(ql, address, params):
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
@winapi(cc=STDCALL, params={
    "hInternet": POINTER,
    "lpszServerName": WSTRING,
    "nServerPort": DWORD,
    "lpszUserName": WSTRING,
    "lpszPassword": WSTRING,
    "dwService": DWORD,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_InternetConnectW(ql, address, params):
    pass


# void InternetCheckConnectionA(
#    LPCSTR lpszUrl,
#    DWORD  dwFlags,
#    DWORD  dwReserved
# );
@winapi(cc=STDCALL, params={
    "lpszUrl": WSTRING,
    "dwFlags": DWORD,
    "dwContext": DWORD
})
def hook_InternetCheckConnectionA(ql, address, params):
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
@winapi(cc=STDCALL, params={
    "hConnect": POINTER,
    "lpszVerb": STRING,
    "lpszObjectName": STRING,
    "lpszVersion": STRING,
    "lpszReferrer": STRING,
    "lplpszAcceptTypes": POINTER,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_HttpOpenRequestA(ql, address, params):
    pass


# vBOOLAPI HttpSendRequestExA(
#   HINTERNET           hRequest,
#   LPINTERNET_BUFFERSA lpBuffersIn,
#   LPINTERNET_BUFFERSA lpBuffersOut,
#   DWORD               dwFlags,
#   DWORD_PTR           dwContext
# );
@winapi(cc=STDCALL, params={
    "hRequest": POINTER,
    "lpBuffersIn": POINTER,
    "lpBuffersOut": STRING,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_HttpSendRequestExA(ql, address, params):
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
@winapi(cc=STDCALL, params={
    "hConnect": POINTER,
    "lpszVerb": WSTRING,
    "lpszObjectName": WSTRING,
    "lpszVersion": WSTRING,
    "lpszReferrer": WSTRING,
    "lplpszAcceptTypes": POINTER,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_HttpOpenRequestW(ql, address, params):
    pass


# BOOLAPI InternetSetOptionA(
#   HINTERNET hInternet,
#   DWORD     dwOption,
#   LPVOID    lpBuffer,
#   DWORD     dwBufferLength
# );
@winapi(cc=STDCALL, params={
    "hInternet": POINTER,
    "dwOption": DWORD,
    "lpBuffer": POINTER,
    "dwBufferLength": DWORD
})
def hook_InternetSetOptionA(ql, address, params):
    return 1


# BOOLAPI InternetSetOptionW(
#   HINTERNET hInternet,
#   DWORD     dwOption,
#   LPVOID    lpBuffer,
#   DWORD     dwBufferLength
# );
@winapi(cc=STDCALL, params={
    "hInternet": POINTER,
    "dwOption": DWORD,
    "lpBuffer": POINTER,
    "dwBufferLength": DWORD
})
def hook_InternetSetOptionW(ql, address, params):
    return 1


# BOOLAPI HttpSendRequestA(
#  HINTERNET hRequest,
#  LPCSTR    lpszHeaders,
#  DWORD     dwHeadersLength,
#  LPVOID    lpOptional,
#  DWORD     dwOptionalLength
# );
@winapi(cc=STDCALL, params={
    "hRequest": POINTER,
    "lpszHeaders": STRING,
    "dwHeadersLength": DWORD,
    "lpOptional": POINTER,
    "dwOptionalLength": DWORD
})
def hook_HttpSendRequestA(ql, address, params):
    return 1


# BOOLAPI HttpSendRequestW(
#  HINTERNET hRequest,
#  LPCWSTR   lpszHeaders,
#  DWORD     dwHeadersLength,
#  LPVOID    lpOptional,
#  DWORD     dwOptionalLength
# );
@winapi(cc=STDCALL, params={
    "hRequest": POINTER,
    "lpszHeaders": WSTRING,
    "dwHeadersLength": DWORD,
    "lpOptional": POINTER,
    "dwOptionalLength": DWORD
})
def hook_HttpSendRequestW(ql, address, params):
    return 1


# void InternetErrorDlg(
#   HWND      hWnd,
#   HINTERNET hRequest,
#   DWORD     dwError,
#   DWORD     dwFlags,
#   LPVOID    *lppvData
# );
@winapi(cc=STDCALL, params={
    "hWnd": POINTER,
    "hRequest": POINTER,
    "dwError": DWORD,
    "dwFlags": DWORD,
    "lppvData": POINTER
})
def hook_InternetErrorDlg(ql, address, params):
    pass


# BOOLAPI InternetReadFile(
#   HINTERNET hFile,
#   LPVOID    lpBuffer,
#   DWORD     dwNumberOfBytesToRead,
#   LPDWORD   lpdwNumberOfBytesRead
# );
@winapi(cc=STDCALL, params={
    "hFile": POINTER,
    "lpBuffer": POINTER,
    "dwNumberOfBytesToRead": DWORD,
    "lpdwNumberOfBytesRead": POINTER
})
def hook_InternetReadFile(ql, address, params):
    return 1


# BOOLAPI InternetWriteFile(
#   HINTERNET hFile,
#   LPCVOID   lpBuffer,
#   DWORD     dwNumberOfBytesToWrite,
#   LPDWORD   lpdwNumberOfBytesWritten
# );
@winapi(cc=STDCALL, params={
    "hFile": POINTER,
    "lpBuffer": POINTER,
    "dwNumberOfBytesToWrite": DWORD,
    "lpdwNumberOfBytesWritten": POINTER
})
def hook_InternetWriteFile(ql, address, params):
    return 1


# BOOLAPI HttpEndRequestA(
#   HINTERNET           hRequest,
#   LPINTERNET_BUFFERSA lpBuffersOut,
#   DWORD               dwFlags,
#   DWORD_PTR           dwContext
# );
@winapi(cc=STDCALL, params={
    "hFile": POINTER,
    "lpBuffersOut": POINTER,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_HttpEndRequestA(ql, address, params):
    return 1

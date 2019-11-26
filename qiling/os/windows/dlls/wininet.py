#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *


# void InternetOpenA(
#   LPCSTR lpszAgent,
#   DWORD  dwAccessType,
#   LPCSTR lpszProxy,
#   LPCSTR lpszProxyBypass,
#   DWORD  dwFlags
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpszAgent": STRING,
    "dwAccessType": DWORD,
    "lpszProxy": STRING,
    "lpszProxyBypass": STRING,
    "dwFlags": DWORD
})
def hook_InternetOpenA(ql, address, params):
    pass


# void InternetOpenUrlA(
#   HINTERNET hInternet,
#   LPCSTR    lpszUrl,
#   LPCSTR    lpszHeaders,
#   DWORD     dwHeadersLength,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hInternet": POINTER,
    "lpszUrl": STRING,
    "lpszHeaders": STRING,
    "dwHeadersLength": DWORD,
    "dwFlags": DWORD,
    "dwContext": POINTER
})
def hook_InternetOpenUrlA(ql, address, params):
    pass


# BOOLAPI InternetCloseHandle(
#   HINTERNET hInternet
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hInternet": POINTER
})
def hook_InternetCloseHandle(ql, address, params):
    ret = 1
    return ret

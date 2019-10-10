#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *


@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_InternetOpenA(ql, address):
    lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags = ql.get_params(5)
    ql.nprint('0x%0.2x: InternetOpenA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)' %
        (address, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags))


# void InternetOpenUrlA(
#   HINTERNET hInternet,
#   LPCSTR    lpszUrl,
#   LPCSTR    lpszHeaders,
#   DWORD     dwHeadersLength,
#   DWORD     dwFlags,
#   DWORD_PTR dwContext
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=6)
def hook_InternetOpenUrlA(ql, address):
    hInternet, lpszUrl, lpszHeaders, dwHeadersLength, \
        dwFlags, dwContext = ql.get_params(6)
    s_lpszUrl = read_cstring(ql, lpszUrl) if lpszUrl != 0 else ""
    s_lpszHeaders = read_cstring(ql, lpszHeaders) if lpszHeaders != 0 else ""
    ql.nprint('0x%0.2x: InternetOpenUrlA(0x%x, "%s", "%s", 0x%x, 0x%x, 0x%x)' %
        (address, hInternet, s_lpszUrl, s_lpszHeaders, dwHeadersLength, dwFlags, dwContext))


# BOOLAPI InternetCloseHandle(
#   HINTERNET hInternet
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_InternetCloseHandle(ql, address):
    ret = 1
    hInternet = ql.get_params(1)
    ql.nprint('0x%0.2x: InternetCloseHandle(0x%x) = %d' % (address, hInternet, ret))
    return ret

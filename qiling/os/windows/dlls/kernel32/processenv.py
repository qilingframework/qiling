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
from qiling.os.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );
@winapi(cc=STDCALL, params={
    "nStdHandle": DWORD
})
def hook_GetStdHandle(ql, address, params):
    nStdHandle = params["nStdHandle"]
    return nStdHandle


# LPSTR GetCommandLineA(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCommandLineA(ql, address, params):
    cmdline = ql.PE.cmdline + b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# LPSTR GetCommandLineW(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCommandLineW(ql, address, params):
    cmdline = ql.PE.cmdline.decode('ascii').encode('utf-16le')
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStrings(
# );s
@winapi(cc=STDCALL, params={})
def hook_GetEnvironmentStrings(ql, address, params):
    cmdline = b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStringsW(
# );
@winapi(cc=STDCALL, params={})
def hook_GetEnvironmentStringsW(ql, address, params):
    cmdline = b"\x00\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winapi(cc=STDCALL, params={
    "penv": POINTER
})
def hook_FreeEnvironmentStringsW(ql, address, params):
    ret = 1
    return ret

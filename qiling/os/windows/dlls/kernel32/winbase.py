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


# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );
@winapi(cc=STDCALL, params={
    "ExitCode": INT
})
def hook_FatalExit(ql, address, params):
    ql.uc.emu_stop()
    ql.RUN = False


# PVOID EncodePointer(
#  _In_ PVOID Ptr
# );
@winapi(cc=STDCALL, params={
    "Ptr": POINTER
})
def hook_EncodePointer(ql, address, params):
    return params['Ptr']


# PVOID DecodePointer(
#  _In_ PVOID Ptr
# );
@winapi(cc=STDCALL, params={
    "Ptr": POINTER
})
def hook_DecodePointer(ql, address, params):
    return params['Ptr']


# UINT WinExec(
#   LPCSTR lpCmdLine,
#   UINT   uCmdShow
# );
@winapi(cc=STDCALL, params={
    "lpCmdLine": STRING,
    "uCmdShow": UINT
})
def hook_WinExec(ql, address, params):
    return 33


# DWORD GetEnvironmentVariableA(
#   LPCSTR lpName,
#   LPSTR  lpBuffer,
#   DWORD  nSize
# );
@winapi(cc=STDCALL, params={
    "lpName": STRING,
    "lpBuffer": POINTER,
    "nSize": DWORD
})
def hook_GetEnvironmentVariableA(ql, address, params):
    ret = 0
    return ret


# DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
#   UINT   uFlags,
#   SIZE_T uBytes
# );
@winapi(cc=STDCALL, params={
    "uFlags": UINT,
    "uBytes": SIZE_T
})
def hook_LocalAlloc(ql, address, params):
    ret = ql.heap.mem_alloc(params["uBytes"])
    return ret


# DECLSPEC_ALLOCATOR HLOCAL LocalReAlloc(
#   _Frees_ptr_opt_ HLOCAL hMem,
#   SIZE_T                 uBytes,
#   UINT                   uFlags
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER,
    "uBytes": SIZE_T,
    "uFlags": UINT
})
def hook_LocalReAlloc(ql, address, params):
    old_mem = params["hMem"]
    ql.heap.mem_free(old_mem)
    ret = ql.heap.mem_alloc(params["uBytes"])
    return ret


# HLOCAL LocalFree(
#   _Frees_ptr_opt_ HLOCAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_LocalFree(ql, address, params):
    old_mem = params["hMem"]
    ql.heap.mem_free(old_mem)
    return 0


# UINT SetHandleCount(
#   UINT uNumber
# );
@winapi(cc=STDCALL, params={
    "uNumber": UINT
})
def hook_SetHandleCount(ql, address, params):
    uNumber = params["uNumber"]
    return uNumber


# LPVOID GlobalLock(
#  HGLOBAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalLock(ql, address, params):
    return params['hMem']


# LPVOID GlobalUnlock(
#  HGLOBAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalUnlock(ql, address, params):
    return 1


# DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
#  UINT   uFlags,
#  SIZE_T dwBytes
# );
@winapi(cc=STDCALL, params={
    "uFlags": UINT,
    "dwBytes": UINT
})
def hook_GlobalAlloc(ql, address, params):
    return ql.heap.mem_alloc(params["dwBytes"])


# HGLOBAL GlobalFree(
#   _Frees_ptr_opt_ HGLOBAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalFree(ql, address, params):
    old_mem = params["hMem"]
    ql.heap.mem_free(old_mem)
    return 0


# HGLOBAL GlobalHandle(
#   LPCVOID pMem
# );
@winapi(cc=STDCALL, params={
    "pMem": POINTER
})
def hook_GlobalHandle(ql, address, params):
    return params["pMem"]


# LPSTR lstrcpynA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
#   int    iMaxLength
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": STRING,
    "iMaxLength": INT
})
def hook_lstrcpynA(ql, address, params):
    # Copy String2 into String for max iMaxLength chars
    src = params["lpString2"]
    dst = params["lpString1"]
    max_length = params["iMaxLength"]
    if len(src) > max_length:
        src = src[:max_length]
    ql.uc.mem_write(dst, bytes(src, encoding="utf-16le"))
    return dst


# LPSTR lstrcpyA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": STRING,
})
def hook_lstrcpyA(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    dst = params["lpString1"]
    ql.uc.mem_write(dst, bytes(src, encoding="utf-16le"))
    return dst


# LPSTR lstrcatA(
#   LPSTR  lpString1,
#   LPCSTR lpString2
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": STRING,
})
def hook_lstrcatA(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    pointer = params["lpString1"]
    string_base = read_cstring(ql, pointer)
    result = string_base + src
    ql.uc.mem_write(pointer, bytes(result, encoding="utf-16le"))
    return pointer


# HRSRC FindResourceA(
#   HMODULE hModule,
#   LPCSTR  lpName,
#   LPCSTR  lpType
# );
@winapi(cc=STDCALL, params={
    "hModule": POINTER,
    "lpName": POINTER,
    "lpType": POINTER
})
def hook_FindResourceA(ql, address, params):
    # Retrieve a resource
    # Name e Type can be int or strings, this can be a problem
    name = params["lpName"]
    type = params["lpType"]
    # TODO i don't know how to implement this, the return 0 is to simulate an error
    return 0

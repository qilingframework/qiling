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


# LPSTR lstrcpynW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2,
#   int    iMaxLength
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": WSTRING,
    "iMaxLength": INT
})
def hook_lstrcpynW(ql, address, params):
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
    result = string_base + src + "\x00"
    ql.uc.mem_write(pointer, bytes(result, encoding="utf-16le"))
    return pointer


# LPSTR lstrcatW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": WSTRING,
})
def hook_lstrcatW(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    ql.dprint(string_to_hex(src))
    pointer = params["lpString1"]
    string_base = read_wstring(ql, pointer)
    result = string_base + src + "\x00" + "\x00"
    ql.dprint(result)
    ql.uc.mem_write(pointer, bytes(result, encoding="utf-8"))
    return pointer


# int lstrcmpiW(
#   LPCWSTR lpString1,
#   LPCWSTR lpString2
# );
@winapi(cc=STDCALL, params={
    "lpString1": WSTRING,
    "lpString2": WSTRING,
})
def hook_lstrcmpiW(ql, address, params):
    # Copy String2 into String
    str1 = params["lpString1"]
    str2 = params["lpString2"]
    # Was a check for a ransomware, will think how to automatize some compare in the future
    # if str1.replace("\x00","") == "outlook.exe":
    #     return 0
    if str1 == str2:
        return 0
    elif str1 > str2:
        return 1
    else:
        # size depends on architecture?
        return 0xffffffff


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


# BOOL IsBadReadPtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winapi(cc=STDCALL, params={
    "lp": POINTER,
    "ucb": POINTER
})
def hook_IsBadReadPtr(ql, address, params):
    # Check read permission for size of memory
    ACCESS_TRUE = 0
    ACCESS_FALSE = 1
    return ACCESS_TRUE


# BOOL IsBadWritePtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winapi(cc=STDCALL, params={
    "lp": POINTER,
    "ucb": POINTER
})
def hook_IsBadWritePtr(ql, address, params):
    # Check read permission for size of memory
    ACCESS_TRUE = 0
    ACCESS_FALSE = 1
    return ACCESS_TRUE


# typedef struct _OSVERSIONINFOEXA {
#   DWORD dwOSVersionInfoSize;
#   DWORD dwMajorVersion;
#   DWORD dwMinorVersion;
#   DWORD dwBuildNumber;
#   DWORD dwPlatformId;
#   CHAR  szCSDVersion[128];
#   WORD  wServicePackMajor;
#   WORD  wServicePackMinor;
#   WORD  wSuiteMask;
#   BYTE  wProductType;
#   BYTE  wReserved;
# } OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;


# BOOL VerifyVersionInfoW(
#   LPOSVERSIONINFOEXW lpVersionInformation,
#   DWORD              dwTypeMask,
#   DWORDLONG          dwlConditionMask
# );
@winapi(cc=STDCALL, params={
    "lpVersionInformation": POINTER,
    "dwTypeMask": DWORD,
    "dwlConditionMask": ULONGLONG
})
def hook_VerifyVersionInfoW(ql, address, params):
    # TODO implement structure and compare parameters as the real function. I don't think is really necessary since
    #  this function is normally used by malwares to check if a system operative to attack
    #  https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow2
    checks_passed = True
    if checks_passed:
        return 1
    else:
        ql.last_error = ERROR_OLD_WIN_VERSION
        return 0

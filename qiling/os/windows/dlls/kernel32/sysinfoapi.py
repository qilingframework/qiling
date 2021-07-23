#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from datetime import datetime

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.structs import SystemInfo, SystemTime

# NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetVersion(ql: Qiling, address: int, params):
    return (0x0004 << 16) | 0x0004

def __GetVersionEx(ql: Qiling, address: int, params):
    return 1

# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
#   LPOSVERSIONINFOA lpVersionInformation
# );
@winsdkapi(cc=STDCALL, params={
    'lpVersionInformation' : LPOSVERSIONINFOA
})
def hook_GetVersionExA(ql: Qiling, address: int, params):
    return __GetVersionEx(ql, address, params)

# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExW(
#   LPOSVERSIONINFOW lpVersionInformation
# );
@winsdkapi(cc=STDCALL, params={
    'lpVersionInformation' : LPOSVERSIONINFOW
})
def hook_GetVersionExW(ql: Qiling, address: int, params):
    return __GetVersionEx(ql, address, params)

def __GetSystemInfo(ql: Qiling, address: int, params):
    pointer = params["lpSystemInfo"]

    # FIXME: dll_size no longer reflects the upper bound of used memory; should find a better way to specify max_address
    system_info = SystemInfo(ql, 0, ql.os.heap.page_size, ql.loader.pe_image_address,
                             ql.loader.dll_address + ql.loader.dll_size, 0x3, 0x4, 0x24a, ql.os.heap.page_size * 10,
                             0x6, 0x4601)
    system_info.write(pointer)

    return 0

# void GetSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemInfo' : LPSYSTEM_INFO
})
def hook_GetSystemInfo(ql: Qiling, address: int, params):
    return __GetSystemInfo(ql, address, params)

# void GetLocalTime(
#   LPSYSTEMTIME lpSystemTime
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemTime' : LPSYSTEMTIME
})
def hook_GetLocalTime(ql: Qiling, address: int, params):
    ptr = params['lpSystemTime']
    d = datetime.now()

    system_time = SystemTime(ql, d.year, d.month, d.isoweekday(), d.day, d.hour, d.minute, d.second, d.microsecond // 1000)
    system_time.write(ptr)

    return 0

# void GetSystemTimeAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemTimeAsFileTime' : LPFILETIME
})
def hook_GetSystemTimeAsFileTime(ql: Qiling, address: int, params):
    # TODO
    pass

# DWORD GetTickCount(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql: Qiling, address: int, params):
    return 200000

def __GetWindowsDirectory(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]

    enc = 'utf-16le' if wstring else 'utf-8'
    res = os.path.normpath(ql.os.windir)

    ql.mem.write(lpBuffer, f'{res}\x00'.encode(enc))

    return len(res)

def __GetSystemDirectory(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]

    enc = 'utf-16le' if wstring else 'utf-8'
    res = os.path.join(ql.os.windir, 'System32')

    ql.mem.write(lpBuffer, f'{res}\x00'.encode(enc))

    return len(res)

# UINT GetWindowsDirectoryW(
#   LPWSTR lpBuffer,
#   UINT   uSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPWSTR,
    'uSize'    : UINT
})
def hook_GetWindowsDirectoryW(ql: Qiling, address: int, params):
    return __GetWindowsDirectory(ql, address, params, True)

@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPSTR,
    'uSize'    : UINT
})
def hook_GetWindowsDirectoryA(ql: Qiling, address: int, params):
    return __GetWindowsDirectory(ql, address, params, False)

# UINT GetSystemWindowsDirectoryW(
#   LPWSTR lpBuffer,
#   UINT   uSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPWSTR,
    'uSize'    : UINT
})
def hook_GetSystemWindowsDirectoryW(ql: Qiling, address: int, params):
    return __GetWindowsDirectory(ql, address, params, True)

@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPSTR,
    'uSize'    : UINT
})
def hook_GetSystemWindowsDirectoryA(ql: Qiling, address: int, params):
    return __GetWindowsDirectory(ql, address, params, False)

@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPWSTR,
    'uSize'    : UINT
})
def hook_GetSystemDirectoryW(ql: Qiling, address: int, params):
    return __GetSystemDirectory(ql, address, params, True)

# UINT GetSystemDirectoryA(
#   LPSTR lpBuffer,
#   UINT  uSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPSTR,
    'uSize'    : UINT
})
def hook_GetSystemDirectoryA(ql: Qiling, address: int, params):
    return __GetSystemDirectory(ql, address, params, False)

# void GetNativeSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemInfo' : LPSYSTEM_INFO
})
def hook_GetNativeSystemInfo(ql: Qiling, address: int, params):
    return __GetSystemInfo(ql, address, params)

# void GetSystemTime(
#   LPSYSTEMTIME lpSystemTime
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemTime' : LPSYSTEMTIME
})
def hook_GetSystemTIme(ql: Qiling, address: int, params):
    pointer = params["lpSystemTime"]

    ms = ql.pack64(datetime.now().microsecond)
    ql.mem.write(pointer, ms)

    return 0

# void GetSystemTimePreciseAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemTimeAsFileTime' : LPFILETIME
})
def hook_GetSystemTimePreciseAsFileTime(ql: Qiling, address: int, params):
    pointer = params["lpSystemTimeAsFileTime"]

    # TODO: check if the value is correct
    ms = ql.pack64(datetime.now().microsecond)
    ql.mem.write(pointer, ms)

    return 0

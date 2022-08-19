#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ntpath
from datetime import datetime

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.structs import FILETIME, SYSTEMTIME, make_system_info

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
    lpSystemInfo = params['lpSystemInfo']

    sysinfo_struct = make_system_info(ql.arch.bits)

    # FIXME:
    #  - load configurable values rather than fixed / bogus ones
    #  - loader.dll_size no longer reflects the upper bound of used memory; should find a better way to specify max_address
    with sysinfo_struct.ref(ql.mem, lpSystemInfo) as si:
        si.dwOemId = 0
        si.dwPageSize = ql.mem.pagesize
        si.lpMinimumApplicationAddress = ql.loader.pe_image_address
        si.lpMaximumApplicationAddress = ql.loader.dll_address + ql.loader.dll_size
        si.dwActiveProcessorMask = 0x3
        si.dwNumberOfProcessors = 0x4
        si.dwProcessorType = 0x24a
        si.dwAllocationGranularity = ql.mem.pagesize * 10
        si.wProcessorLevel = 0x6
        si.wProcessorRevision = 0x4601

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
    lpSystemTime = params['lpSystemTime']
    now = datetime.now()

    with SYSTEMTIME.ref(ql.mem, lpSystemTime) as st:
        st.wYear = now.year
        st.wMonth = now.month
        st.wDayOfWeek = now.isoweekday()
        st.wDay = now.day
        st.wHour = now.hour
        st.wMinute = now.minute
        st.wSecond = now.second
        st.wMilliseconds = now.microsecond // 1000

    return 0

# void GetSystemTimeAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winsdkapi(cc=STDCALL, params={
    'lpSystemTimeAsFileTime' : LPFILETIME
})
def hook_GetSystemTimeAsFileTime(ql: Qiling, address: int, params):
    ptr = params['lpSystemTimeAsFileTime']

    epoch = datetime(1601, 1, 1)
    elapsed = datetime.now() - epoch

    # number of 100-nanosecond intervals since Jan 1, 1601 utc
    # where: (10 ** 9) / 100 -> (10 ** 7)
    hnano = int(elapsed.total_seconds() * (10 ** 7))

    mask = (1 << 32) - 1

    ftime = FILETIME(
        (hnano >>  0) & mask,
        (hnano >> 32) & mask
    )

    ftime.save_to(ql.mem, ptr)

# DWORD GetTickCount(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql: Qiling, address: int, params):
    return 200000

def __GetWindowsDirectory(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]

    enc = 'utf-16le' if wstring else 'utf-8'
    res = ntpath.normpath(ql.os.windir)

    ql.mem.write(lpBuffer, f'{res}\x00'.encode(enc))

    return len(res)

def __GetSystemDirectory(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]

    enc = 'utf-16le' if wstring else 'utf-8'
    res = ql.os.winsys

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
    return __GetWindowsDirectory(ql, address, params, wstring=True)

@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPSTR,
    'uSize'    : UINT
})
def hook_GetWindowsDirectoryA(ql: Qiling, address: int, params):
    return __GetWindowsDirectory(ql, address, params, wstring=False)

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

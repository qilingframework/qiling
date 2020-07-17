#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from datetime import datetime
from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.structs import *

dllname = 'kernel32_dll'

# NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetVersion(ql, address, params):
    ret = 0x0004
    ret = ret << 16
    ret = ret | 0x0004
    return ret


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
#   LPOSVERSIONINFOA lpVersionInformation
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetVersionExA(ql, address, params):
    return hook_GetVersionExW.__wrapped__(ql, address, params)


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExW(
#   LPOSVERSIONINFOW lpVersionInformation
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetVersionExW(ql, address, params):
    return 1


# void GetSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSystemInfo(ql, address, params):
    pointer = params["lpSystemInfo"]
    system_info = SystemInfo(ql, 0, ql.os.heap.page_size, ql.loader.pe_image_address,
                             ql.loader.dll_address + ql.loader.dll_size, 0x3, 0x4, 0x24a, ql.os.heap.page_size * 10,
                             0x6, 0x4601)
    system_info.write(pointer)
    return 0


# void GetLocalTime(
#   LPSYSTEMTIME lpSystemTime
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetLocalTime(ql, address, params):
    import datetime
    ptr = params['lpSystemTime']
    d = datetime.datetime.now()
    system_time = SystemTime(ql, d.year, d.month, d.isoweekday(), d.day, d.hour, d.minute, d.second,
                             d.microsecond * 1000)
    system_time.write(ptr)
    return 0


# void GetSystemTimeAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSystemTimeAsFileTime(ql, address, params):
    # TODO
    pass


# DWORD GetTickCount(
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetTickCount(ql, address, params):
    ret = 200000
    return ret


# UINT GetWindowsDirectoryW(
#   LPWSTR lpBuffer,
#   UINT   uSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetWindowsDirectoryW(ql, address, params):
    dst = params["lpBuffer"]
    value = (ql.os.windir + "\x00").encode("utf-16le")
    ql.mem.write(dst, value)
    return len(value) - 2

# UINT GetSystemWindowsDirectoryW(
#   LPWSTR lpBuffer,
#   UINT   uSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSystemWindowsDirectoryW(ql, address, params):
    return hook_GetWindowsDirectoryW.__wrapped__(ql, address, params)

# void GetNativeSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetNativeSystemInfo(ql, address, params):
    pointer = params["lpSystemInfo"]
    system_info = SystemInfo(ql, 0, ql.os.heap.page_size, ql.loader.pe_image_address,
                             ql.loader.dll_address + ql.loader.dll_size, 0x3, 0x4, 0x24a, ql.os.heap.page_size * 10,
                             0x6, 0x4601)
    system_info.write(pointer)
    return 0


# typedef struct _FILETIME {
#   DWORD dwLowDateTime;
#   DWORD dwHighDateTime;
# } FILETIME, *PFILETIME, *LPFILETIME;

# void GetSystemTimePreciseAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSystemTimePreciseAsFileTime(ql, address, params):
    # todo check if the value is correct
    dt = datetime.now().microsecond.to_bytes(8, byteorder="little")
    pointer = params["lpSystemTimeAsFileTime"]
    ql.mem.write(pointer, dt)
    return 0

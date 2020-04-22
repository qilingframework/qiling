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


# NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion(
# );
@winapi(cc=STDCALL, params={})
def hook_GetVersion(ql, address, params):
    ret = 0x0004
    ret = ret << 16
    ret = ret | 0x0004
    return ret


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
#   LPOSVERSIONINFOA lpVersionInformation
# );
@winapi(cc=STDCALL, params={
    "lpVersionInformation": STRING

})
def hook_GetVersionExA(ql, address, params):
    return 1


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExW(
#   LPOSVERSIONINFOW lpVersionInformation
# );
@winapi(cc=STDCALL, params={
    "lpVersionInformation": STRING

})
def hook_GetVersionExW(ql, address, params):
    return 1


# typedef struct _SYSTEM_INFO {
#   union {
#     DWORD dwOemId;
#     struct {
#       WORD wProcessorArchitecture;
#       WORD wReserved;
#     } DUMMYSTRUCTNAME;
#   } DUMMYUNIONNAME;
#   DWORD     dwPageSize;
#   LPVOID    lpMinimumApplicationAddress;
#   LPVOID    lpMaximumApplicationAddress;
#   DWORD_PTR dwActiveProcessorMask;
#   DWORD     dwNumberOfProcessors;
#   DWORD     dwProcessorType;
#   DWORD     dwAllocationGranularity;
#   WORD      wProcessorLevel;
#   WORD      wProcessorRevision;
# } SYSTEM_INFO, *LPSYSTEM_INFO;


# void GetSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winapi(cc=STDCALL, params={
    "lpSystemInfo": POINTER
})
def hook_GetSystemInfo(ql, address, params):
    pointer = params["lpSystemInfo"]
    system_info = {"dummy": 0x0.to_bytes(length=2 * 2 + 4, byteorder='little'),
                   "dwPageSize": ql.os.heap.page_size.to_bytes(length=4, byteorder='little'),
                   "lpMinimumApplicationAddress": ql.loader.PE_IMAGE_BASE.to_bytes(length=ql.pointersize, byteorder='little'),
                   "lpMaximumApplicationAddress": (ql.loader.DLL_BASE_ADDR + ql.loader.DLL_SIZE).to_bytes(length=ql.pointersize,
                                                                                            byteorder='little'),
                   "dwActiveProcessorMask": 0x3.to_bytes(length=ql.pointersize, byteorder='little'),
                   # TODO not sure from here, did not found variables inside the emulator
                   "dwNumberOfProcessors": 0x4.to_bytes(length=4, byteorder='little'),
                   "dwProcessorType": 0x24a.to_bytes(length=4, byteorder='little'),
                   "dwAllocationGranularity": (ql.os.heap.page_size * 10).to_bytes(length=4, byteorder='little'),
                   "wProcessorLevel": 0x6.to_bytes(length=2, byteorder='little'),
                   "wProcessorRevision": 0x4601.to_bytes(length=2, byteorder='little')
                   }
    values = b"".join(system_info.values())
    ql.mem.write(pointer, values)
    return 0


"""
typedef struct _SYSTEMTIME {
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;
"""


# void GetLocalTime(
#   LPSYSTEMTIME lpSystemTime
# );
@winapi(cc=STDCALL, params={
    "lpSystemTime": POINTER
})
def hook_GetLocalTime(ql, address, params):
    import datetime
    ptr = params['lpSystemTime']
    d = datetime.datetime.now()
    ql.mem.write(d.year.to_bytes(length=2, byteorder='little'), ptr)
    ql.mem.write(d.month.to_bytes(length=2, byteorder='little'), ptr + 2)
    ql.mem.write(d.isoweekday().to_bytes(length=2, byteorder='little'), ptr + 4)
    ql.mem.write(d.day.to_bytes(length=2, byteorder='little'), ptr + 6)
    ql.mem.write(d.hour.to_bytes(length=2, byteorder='little'), ptr + 8)
    ql.mem.write(d.minute.to_bytes(length=2, byteorder='little'), ptr + 10)
    ql.mem.write(d.second.to_bytes(length=2, byteorder='little'), ptr + 12)
    ql.mem.write((d.microsecond * 1000).to_bytes(length=2, byteorder='little'), ptr + 14)
    return 0


# void GetSystemTimeAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winapi(cc=STDCALL, params={
    "lpSystemTimeAsFileTime": POINTER
})
def hook_GetSystemTimeAsFileTime(ql, address, params):
    # TODO
    pass


# DWORD GetTickCount(
# );
@winapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    ret = 200000
    return ret


# UINT GetWindowsDirectoryW(
#   LPWSTR lpBuffer,
#   UINT   uSize
# );
@winapi(cc=STDCALL, params={
    "lpBuffer": POINTER,
    "uSize": UINT
})
def hook_GetWindowsDirectoryW(ql, address, params):
    dst = params["lpBuffer"]
    value = (ql.os.profile["PATHS"]["windir"] + "\x00").encode("utf-16le")
    ql.mem.write(dst, value)
    return len(value)-2


# void GetNativeSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winapi(cc=STDCALL, params={
    "lpSystemInfo": POINTER
})
def hook_GetNativeSystemInfo(ql, address, params):
    pointer = params["lpSystemInfo"]
    system_info = {"dummy": 0x0.to_bytes(length=8, byteorder='little'),
                   "dwPageSize": ql.os.heap.page_size.to_bytes(length=4, byteorder='little'),
                   "lpMinimumApplicationAddress": ql.loader.PE_IMAGE_BASE.to_bytes(length=ql.pointersize, byteorder='little'),
                   "lpMaximumApplicationAddress": (ql.loader.DLL_BASE_ADDR + ql.loader.DLL_SIZE).to_bytes(length=ql.pointersize,
                                                                                            byteorder='little'),
                   "dwActiveProcessorMask": 0x3.to_bytes(length=ql.pointersize, byteorder='little'),
                   # TODO not sure from here, did not found variables inside the emulator
                   "dwNumberOfProcessors": 0x4.to_bytes(length=4, byteorder='little'),
                   "dwProcessorType": 0x24a.to_bytes(length=4, byteorder='little'),
                   "dwAllocationGranularity": (ql.os.heap.page_size * 10).to_bytes(length=4, byteorder='little'),
                   "wProcessorLevel": 0x6.to_bytes(length=2, byteorder='little'),
                   "wProcessorRevision": 0x4601.to_bytes(length=2, byteorder='little')
                   }
    values = b"".join(system_info.values())
    ql.mem.write(pointer, values)
    return 0


# typedef struct _FILETIME {
#   DWORD dwLowDateTime;
#   DWORD dwHighDateTime;
# } FILETIME, *PFILETIME, *LPFILETIME;

# void GetSystemTimePreciseAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winapi(cc=STDCALL, params={
    "lpSystemTimeAsFileTime": POINTER
})
def hook_GetSystemTimePreciseAsFileTime(ql, address, params):
    # todo check if the value is correct
    dt = datetime.now().microsecond.to_bytes(8, byteorder="little")
    pointer = params["lpSystemTimeAsFileTime"]
    ql.mem.write(pointer, dt)
    return 0

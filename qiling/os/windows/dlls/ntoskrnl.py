#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# typedef struct _OSVERSIONINFOW {
#   ULONG dwOSVersionInfoSize;
#   ULONG dwMajorVersion;
#   ULONG dwMinorVersion;
#   ULONG dwBuildNumber;
#   ULONG dwPlatformId;
#   WCHAR szCSDVersion[128];
# }


# NTSYSAPI NTSTATUS RtlGetVersion(
#   PRTL_OSVERSIONINFOW lpVersionInformation
# );
@winapi(cc=CDECL, params={
    "lpVersionInformation": POINTER
})
def hook_RtlGetVersion(ql, address, params):
    pointer = params["lpVersionInformation"]
    size = int.from_bytes(ql.mem.read(pointer, 4), byteorder="little")
    os_version_info_asked = {"dwOSVersionInfoSize": size,
                             VER_MAJORVERSION: int.from_bytes(ql.mem.read(pointer + 4, 4), byteorder="little"),
                             VER_MINORVERSION: int.from_bytes(ql.mem.read(pointer + 8, 4), byteorder="little"),
                             VER_BUILDNUMBER: int.from_bytes(ql.mem.read(pointer + 12, 4), byteorder="little"),
                             VER_PLATFORMID: int.from_bytes(ql.mem.read(pointer + 16, 4), byteorder="little"),
                             "szCSDVersion": int.from_bytes(ql.mem.read(pointer + 20, 128), byteorder="little"),
                             }
    ql.mem.write(pointer + 4, ql.os.profile.getint("SYSTEM", "majorVersion").to_bytes(4, byteorder="little"))
    ql.mem.write(pointer + 8, ql.os.profile.getint("SYSTEM", "minorVersion").to_bytes(4, byteorder="little"))

    ql.dprint(D_RPRT, "[=] The sample is checking the windows Version!")
    return STATUS_SUCCESS


# NTSYSAPI NTSTATUS ZwSetInformationThread(
#   HANDLE          ThreadHandle,
#   THREADINFOCLASS ThreadInformationClass,
#   PVOID           ThreadInformation,
#   ULONG           ThreadInformationLength
# );
@winapi(cc=STDCALL, params={
    "ThreadHandle": HANDLE,
    "ThreadInformationClass": INT,
    "ThreadInformation": POINTER,
    "ThreadInformationLength": UINT,

})
def hook_ZwSetInformationThread(ql, address, params):
    thread = params["ThreadHandle"]
    information = params["ThreadInformationClass"]
    dst = params["ThreadInformation"]
    size = params["ThreadInformationLength"]

    if thread == ql.os.thread_manager.cur_thread.id:
        if size >= 100:
            return STATUS_INFO_LENGTH_MISMATCH
        if information == ThreadHideFromDebugger:
            ql.dprint(D_RPRT, "[=] Sample is checking debugger via SetInformationThread")
            if dst != 0:
                ql.mem.write(dst, 0x0.to_bytes(1, byteorder="little"))
        else:
            raise QlErrorNotImplemented("[!] API not implemented %d " % information)

    else:
        return STATUS_INVALID_HANDLE
    return STATUS_SUCCESS


# NTSYSAPI NTSTATUS ZwClose(
#   HANDLE Handle
# );
@winapi(cc=STDCALL, params={
    "Handle": HANDLE

})
def hook_ZwClose(ql, address, params):
    value = params["Handle"]
    handle = ql.os.handle_manager.get(value)
    if handle is None:
        return STATUS_INVALID_HANDLE
    return STATUS_SUCCESS

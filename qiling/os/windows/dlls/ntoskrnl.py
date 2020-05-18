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
from qiling.os.windows.structs import *


# NTSYSAPI NTSTATUS RtlGetVersion(
#   PRTL_OSVERSIONINFOW lpVersionInformation
# );
@winapi(cc=CDECL, params={
    "lpVersionInformation": POINTER
})
def hook_RtlGetVersion(ql, address, params):
    pointer = params["lpVersionInformation"]
    os = OsVersionInfoW(ql)
    os.read(pointer)
    os.major[0] = ql.os.profile.getint("SYSTEM", "majorVersion")
    os.minor[0] = ql.os.profile.getint("SYSTEM", "minorVersion")
    os.write(pointer)
    ql.dprint(D_RPRT, "[=] The target is checking the windows Version!")
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
            ql.dprint(D_RPRT, "[=] The target is checking debugger via SetInformationThread")
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

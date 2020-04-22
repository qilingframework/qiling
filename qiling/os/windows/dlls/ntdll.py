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


# void *memcpy(
#    void *dest,
#    const void *src,
#    size_t count
# );
@winapi(cc=CDECL, params={
    "dest": POINTER,
    "src": POINTER,
    "count": UINT
})
def hook_memcpy(ql, address, params):
    try:
        data = bytes(ql.mem.read(params['src'], params['count']))
        ql.mem.write(params['dest'], data)
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)
    return params['dest']


def _QueryInformationProcess(ql, address, params):
    flag = params["ProcessInformationClass"]
    dst = params["ProcessInformation"]
    pt_res = params["ReturnLength"]
    if flag == ProcessDebugFlags:
        value = b"\x01"*0x8
    elif flag == ProcessDebugObjectHandle or flag == ProcessDebugPort :
        value = b"\x00"*0x8
    else:
        ql.dprint(D_INFO, str(flag))
        raise QlErrorNotImplemented("[!] API not implemented")
    ql.dprint(D_RPRT, "[=] The sample is checking the debugger via QueryInformationProcess ")
    ql.mem.write(dst, value)
    if pt_res != 0:
        ql.mem.write(pt_res, 0x8.to_bytes(1, byteorder="little"))

    return STATUS_SUCCESS


# NTSTATUS WINAPI ZwQueryInformationProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _Out_     PVOID            ProcessInformation,
#   _In_      ULONG            ProcessInformationLength,
#   _Out_opt_ PULONG           ReturnLength
# );
@winapi(cc=STDCALL, params={
    "ProcessHandle": HANDLE,
    "ProcessInformationClass": INT,
    "ProcessInformation": POINTER,
    "ProcessInformationLength": UINT,
    "ReturnLength": POINTER
})
def hook_ZwQueryInformationProcess(ql, address, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(ql, address, params)


# __kernel_entry NTSTATUS NtQueryInformationProcess(
#   IN HANDLE           ProcessHandle,
#   IN PROCESSINFOCLASS ProcessInformationClass,
#   OUT PVOID           ProcessInformation,
#   IN ULONG            ProcessInformationLength,
#   OUT PULONG          ReturnLength
# );
@winapi(cc=STDCALL, params={
    "ProcessHandle": HANDLE,
    "ProcessInformationClass": INT,
    "ProcessInformation": POINTER,
    "ProcessInformationLength": UINT,
    "ReturnLength": POINTER
})
def hook_NtQueryInformationProcess(ql, address, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(ql, address, params)

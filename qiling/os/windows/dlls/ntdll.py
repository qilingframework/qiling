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
def hook_memcpy(self, address, params):
    try:
        data = bytes(self.ql.mem.read(params['src'], params['count']))
        self.ql.mem.write(params['dest'], data)
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)
    return params['dest']


def _QueryInformationProcess(self, address, params):
    flag = params["ProcessInformationClass"]
    dst = params["ProcessInformation"]
    pt_res = params["ReturnLength"]
    if flag == ProcessDebugFlags:
        value = b"\x01"*0x4
    elif flag == ProcessDebugPort:
        value = b"\x00"*0x4
    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET
    else:
        self.ql.dprint(D_INFO, str(flag))
        raise QlErrorNotImplemented("[!] API not implemented")
    self.ql.dprint(D_RPRT, "[=] The sample is checking the debugger via QueryInformationProcess ")
    self.ql.mem.write(dst, value)
    if pt_res != 0:
        self.ql.mem.write(pt_res, 0x4.to_bytes(1, byteorder="little"))

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
def hook_ZwQueryInformationProcess(self, address, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(self, address, params)


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
def hook_NtQueryInformationProcess(self, address, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(self, address, params)

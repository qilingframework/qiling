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


# NTSTATUS WINAPI ZwQueryInformationProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _Out_     PVOID            ProcessInformation,
#   _In_      ULONG            ProcessInformationLength,
#   _Out_opt_ PULONG           ReturnLength
# );
@winapi(cc=CDECL, params={
    "ProcessHandle": HANDLE,
    "ProcessInformationClass": INT,
    "ProcessInformation": POINTER,
    "ProcessInformationLength": ULONGLONG,
    "ReturnLength": POINTER
})
def hook_ZwQueryInformationProcess(self, address, params):
    # TODO have no idea if is cdecl or stdcall
    flag = params["ProcessInformationClass"]
    dst = params["ProcessInformation"]
    pt_res = params["ReturnLength"]
    if flag == ProcessDebugPort:
        self.ql.mem.write(dst, 0x0.to_bytes(1, byteorder="little"))
        self.ql.mem.write(pt_res, 0x1.to_bytes(1, byteorder="little"))
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return STATUS_SUCCESS

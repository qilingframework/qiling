#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.const import *


# HANDLE CreateToolhelp32Snapshot(
#   DWORD dwFlags,
#   DWORD th32ProcessID
# );
@winapi(cc=STDCALL, params={
    "dwFlags": DWORD,
    "th32ProcessID": DWORD

})
def hook_CreateToolhelp32Snapshot(ql, address, params):
    # TODO thinking about implementing an handler, gonna see if is really necessary
    flag = params["dwFlags"]
    if flag == TH32CS_SNAPPROCESS:
        ql.dprint(D_RPRT, "[=] The target is checking every process!")
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 0xD10C


# BOOL Process32FirstW(
#   HANDLE            hSnapshot,
#   LPPROCESSENTRY32W lppe
# );
@winapi(cc=STDCALL, params={
    "hSnapshot": HANDLE,
    "lppe": POINTER

})
def hook_Process32FirstW(ql, address, params):
    return 0x1


# BOOL Process32NextW(
#   HANDLE            hSnapshot,
#   LPPROCESSENTRY32W lppe
# );
@winapi(cc=STDCALL, params={
    "hSnapshot": HANDLE,
    "lppe": POINTER

})
def hook_Process32NextW(ql, address, params):
    # Return True if more process, 0 else
    if ql.os.syscall_count["Process32NextW"] >= 3:  # I don' know how many process the sample want's to cycle
        return 0x0
    return 0x1

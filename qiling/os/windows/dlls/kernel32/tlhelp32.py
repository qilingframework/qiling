#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
import logging
from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.const import *


dllname = 'kernel32_dll'

# HANDLE CreateToolhelp32Snapshot(
#   DWORD dwFlags,
#   DWORD th32ProcessID
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CreateToolhelp32Snapshot(ql, address, params):
    # TODO thinking about implementing an handler, gonna see if is really necessary
    flag = params["dwFlags"]
    if flag == TH32CS_SNAPPROCESS:
        logging.debug("[=] The target is checking every process!")
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 0xD10C


# BOOL Process32FirstW(
#   HANDLE            hSnapshot,
#   LPPROCESSENTRY32W lppe
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_Process32FirstW(ql, address, params):
    return 0x1


# BOOL Process32NextW(
#   HANDLE            hSnapshot,
#   LPPROCESSENTRY32W lppe
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_Process32NextW(ql, address, params):
    # Return True if more process, 0 else
    if ql.os.syscall_count["Process32NextW"] >= 3:  # I don' know how many process the sample want's to cycle
        return 0x0
    return 0x1

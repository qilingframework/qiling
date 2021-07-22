#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import TH32CS_SNAPPROCESS
from qiling.os.windows.fncc import *

# HANDLE CreateToolhelp32Snapshot(
#   DWORD dwFlags,
#   DWORD th32ProcessID
# );
@winsdkapi(cc=STDCALL, params={
    'dwFlags'       : DWORD,
    'th32ProcessID' : DWORD
})
def hook_CreateToolhelp32Snapshot(ql: Qiling, address: int, params):
    # TODO thinking about implementing an handler, gonna see if is really necessary
    flag = params["dwFlags"]

    if flag != TH32CS_SNAPPROCESS:
        raise QlErrorNotImplemented("API not implemented")

    ql.log.debug("The target is checking every process!")

    return 0xD10C

# BOOL Process32FirstW(
#   HANDLE            hSnapshot,
#   LPPROCESSENTRY32W lppe
# );
@winsdkapi(cc=STDCALL, params={
    'hSnapshot' : HANDLE,
    'lppe'      : LPPROCESSENTRY32W
})
def hook_Process32FirstW(ql: Qiling, address: int, params):
    return 1

# BOOL Process32NextW(
#   HANDLE            hSnapshot,
#   LPPROCESSENTRY32W lppe
# );
@winsdkapi(cc=STDCALL, params={
    'hSnapshot' : HANDLE,
    'lppe'      : LPPROCESSENTRY32W
})
def hook_Process32NextW(ql: Qiling, address: int, params):
    # Return True if more process, 0 else
    return int(ql.os.syscall_count["Process32NextW"] < 3)  # I don' know how many process the sample want's to cycle

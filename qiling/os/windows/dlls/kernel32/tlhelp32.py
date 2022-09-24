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
    global __call_count

    __call_count += 1

    # FIXME: this is an undocumented workaround, probably to satisfy one of
    # the samples. better implement that as an ad-hoc hook there
    return int(__call_count < 3)

__call_count = 0

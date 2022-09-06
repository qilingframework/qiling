#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# BOOL IsWow64Process(
#   HANDLE hProcess,
#   PBOOL  Wow64Process
# );
@winsdkapi(cc=STDCALL, params={
    'hProcess'     : HANDLE,
    'Wow64Process' : PBOOL
})
def hook_IsWow64Process(ql: Qiling, address: int, params):
    Wow64Process = params["Wow64Process"]

    if ql.archbit != 32:
        raise QlErrorNotImplemented("API not implemented")

    false = b'\x00'
    # true = b'\x01'

    ql.mem.write(Wow64Process, false)

    return 1

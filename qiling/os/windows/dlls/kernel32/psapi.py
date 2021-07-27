#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# BOOL GetModuleInformation(
#   HANDLE       hProcess,
#   HMODULE      hModule,
#   LPMODULEINFO lpmodinfo,
#   DWORD        cb
# );
@winsdkapi(cc=STDCALL, params={
    'hProcess'  : HANDLE,
    'hModule'   : HMODULE,
    'lpmodinfo' : LPMODULEINFO,
    'cb'        : DWORD
})
def hook_K32GetModuleInformation(ql: Qiling, address: int, params):
    # TODO
    return 0

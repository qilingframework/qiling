#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# UINT MsiGetComponentStateA(
#   MSIHANDLE    hInstall,
#   LPCSTR       szComponent,
#   INSTALLSTATE *piInstalled,
#   INSTALLSTATE *piAction
# );
@winsdkapi(cc=STDCALL, params={
    'hInstall'    : MSIHANDLE,
    'szComponent' : LPCSTR,
    'piInstalled' : INSTALLSTATE,
    'piAction'    : INSTALLSTATE
})
def hook_MsiGetComponentStateA(ql: Qiling, address: int, params):
    return ERROR_INVALID_HANDLE

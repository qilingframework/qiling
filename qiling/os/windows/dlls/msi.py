#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# UINT MsiGetComponentStateA(
#   MSIHANDLE    hInstall,
#   LPCSTR       szComponent,
#   INSTALLSTATE *piInstalled,
#   INSTALLSTATE *piAction
# );
@winapi(cc=STDCALL, params={
    "package": POINTER,
    "szComponent": STRING,
    "piInstalled": POINTER,
    "piAction": POINTER
})
def hook_MsiGetComponentStateA(ql, address, params):
    return 6  # INVALID_HANDLE

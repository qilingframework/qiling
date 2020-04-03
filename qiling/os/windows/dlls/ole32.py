#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.fncc import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# HRESULT OleInitialize(
#   IN LPVOID pvReserved
# );
@winapi(cc=STDCALL, params={
    "pvReserved": UINT
})
def hook_OleInitialize(ql, address, params):
    # I don't think we need to do anything, we hook every call for the COM library and manage them locally
    return S_OK

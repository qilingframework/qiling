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


# BSTR SysAllocStringLen(
#   const OLECHAR *strIn,
#   UINT          ui
# );
@winapi(cc=STDCALL, params={
    "strIn": STRING,
    "ui": UINT
})
def hook_SysAllocStringLen(ql, address, params):
    addr = ql.os.heap.alloc(params["ui"] + 1)
    if params["strIn"] != 0:
        ql.mem.write(addr, params["strIn"][params["ui"]])
    return addr


# void SysFreeString(
#   BSTR bstrString
# );
@winapi(cc=STDCALL, params={
    "strIn": STRING_ADDR,
})
def hook_SysFreeString(ql, address, params):
    addr = params["strIn"][0]
    if addr != 0:
        ql.os.heap.free(addr)
    return 0

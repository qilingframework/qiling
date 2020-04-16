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


# BOOL IsDebuggerPresent();
@winapi(cc=STDCALL, params={
})
def hook_IsDebuggerPresent(self, address, params):
    self.ql.dprint(D_RPRT, "[=] Sample is checking debugger!")
    return 0


# BOOL CheckRemoteDebuggerPresent(
#   HANDLE hProcess,
#   PBOOL  pbDebuggerPresent
# );
@winapi(cc=STDCALL, params={
    "hProcess": HANDLE,
    "pbDebuggerPresent": POINTER
})
def hook_CheckRemoteDebuggerPresent(self, address, params):
    self.ql.dprint(D_RPRT, "[=] Sample is checking debugger!")
    pointer = params["pbDebuggerPresent"]
    self.ql.mem.write(pointer, 0x0.to_bytes(1, byteorder="little"))
    return 1

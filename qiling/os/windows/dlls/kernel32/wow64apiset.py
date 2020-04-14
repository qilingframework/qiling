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


# BOOL IsWow64Process(
#   HANDLE hProcess,
#   PBOOL  Wow64Process
# );
@winapi(cc=STDCALL, params={
    "hProcess": HANDLE,
    "Wow64Process": POINTER
})
def hook_IsWow64Process(self, address, params):
    pointer = params["Wow64Process"]
    false = 0x0.to_bytes(length=1, byteorder='little')
    true = 0x1.to_bytes(length=1, byteorder='little')
    if self.ql.archbit == 32:
        self.ql.mem.write(pointer, false)
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1

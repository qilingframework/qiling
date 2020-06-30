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

dllname = 'kernel32_dll'

# BOOL IsWow64Process(
#   HANDLE hProcess,
#   PBOOL  Wow64Process
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_IsWow64Process(ql, address, params):
    pointer = params["Wow64Process"]
    false = 0x0.to_bytes(length=1, byteorder='little')
    true = 0x1.to_bytes(length=1, byteorder='little')
    if ql.archbit == 32:
        ql.mem.write(pointer, false)
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1

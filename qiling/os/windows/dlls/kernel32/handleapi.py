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


# BOOL DuplicateHandle(
#   HANDLE   hSourceProcessHandle,
#   HANDLE   hSourceHandle,
#   HANDLE   hTargetProcessHandle,
#   LPHANDLE lpTargetHandle,
#   DWORD    dwDesiredAccess,
#   BOOL     bInheritHandle,
#   DWORD    dwOptions
# );
@winapi(cc=STDCALL, params={
    "hSourceProcessHandle": POINTER,
    "hSourceHandle": POINTER,
    "hTargetProcessHandle": POINTER,
    "lpTargetHandle": POINTER,
    "dwDesiredAccess": DWORD,
    "bInheritHandle": BOOL,
    "dwOptions": DWORD
})
def hook_DuplicateHandle(ql, address, params):
    content = params["hSourceHandle"]
    dst = params["lpTargetHandle"]
    ql.mem.write(dst, content.to_bytes(length=ql.pointersize, byteorder='little'))
    return 1


# BOOL CloseHandle(
#   HANDLE hObject
# );
@winapi(cc=STDCALL, params={
    "hObject": HANDLE
})
def hook_CloseHandle(ql, address, params):
    ret = 0
    return ret

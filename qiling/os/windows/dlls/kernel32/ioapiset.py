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


# BOOL DeviceIoControl(
#   HANDLE       hDevice,
#   DWORD        dwIoControlCode,
#   LPVOID       lpInBuffer,
#   DWORD        nInBufferSize,
#   LPVOID       lpOutBuffer,
#   DWORD        nOutBufferSize,
#   LPDWORD      lpBytesReturned,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(cc=STDCALL, params={
    "hDevice": HANDLE,
    "dwIoControlCode": DWORD,
    "lpInBuffer": POINTER,
    "nInBufferSize": DWORD,
    "lpOutBuffer": POINTER,
    "nOutBufferSize": DWORD,
    "lpBytesReturned": POINTER,
    "lpOverlapped": POINTER
})
def hook_DeviceIoControl(ql, address, params):
    operation = params["dwIoControlCode"]
    data = params["lpInBuffer"]
    output = params["lpOutBuffer"]
    output_size = params["lpBytesReturned"]
    # TODO implement operations. Did not find controlCodes values
    return 1

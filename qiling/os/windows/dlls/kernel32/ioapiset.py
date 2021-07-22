#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

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
@winsdkapi(cc=STDCALL, params={
    'hDevice'         : HANDLE,
    'dwIoControlCode' : DWORD,
    'lpInBuffer'      : LPVOID,
    'nInBufferSize'   : DWORD,
    'lpOutBuffer'     : LPVOID,
    'nOutBufferSize'  : DWORD,
    'lpBytesReturned' : LPDWORD,
    'lpOverlapped'    : LPOVERLAPPED
})
def hook_DeviceIoControl(ql: Qiling, address: int, params):
    # operation = params["dwIoControlCode"]
    # data = params["lpInBuffer"]
    # output = params["lpOutBuffer"]
    # output_size = params["lpBytesReturned"]

    # TODO implement operations. Did not find controlCodes values
    return 1

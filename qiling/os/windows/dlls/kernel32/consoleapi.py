#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# BOOL WINAPI GetConsoleMode(
#   _In_  HANDLE  hConsoleHandle,
#   _Out_ LPDWORD lpMode
# );
@winsdkapi(cc=STDCALL, params={
    'hConsoleHandle' : HANDLE,
    'lpMode'         : LPDWORD
})
def hook_GetConsoleMode(ql: Qiling, address: int, params):
    return 1

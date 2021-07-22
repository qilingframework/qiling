#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import Handle

# HWND WINAPI GetConsoleWindow(void);
@winsdkapi(cc=STDCALL, params={})
def hook_GetConsoleWindow(ql: Qiling, address: int, params):
    handle = Handle(name="console_window")
    ql.os.handle_manager.append(handle)

    return handle.id

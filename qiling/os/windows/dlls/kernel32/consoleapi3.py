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


# HWND WINAPI GetConsoleWindow(void);
@winapi(cc=STDCALL, params={
})
def hook_GetConsoleWindow(ql, address, params):
    handle = Handle(name="console_window")
    ql.os.handle_manager.append(handle)
    return handle.id

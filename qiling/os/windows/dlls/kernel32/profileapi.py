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


# BOOL QueryPerformanceCounter(
#   LARGE_INTEGER *lpPerformanceCount
# );
@winapi(cc=STDCALL, params={
    "lpPerformanceCount": POINTER
})
def hook_QueryPerformanceCounter(ql, address, params):
    ret = 0
    return ret

#BOOL QueryPerformanceFrequency(
#  LARGE_INTEGER *lpFrequency
#);
@winapi(cc=STDCALL, params={
    "lpFrequency": POINTER    
})
def hook_QueryPerformanceFrequency(ql, address, params):
    ql.mem.write(params['lpFrequency'], (10000000).to_bytes(length=8, byteorder='little'))
    return 1

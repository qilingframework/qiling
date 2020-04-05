#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# void *memcpy(
#    void *dest,
#    const void *src,
#    size_t count
# );
@winapi(cc=CDECL, params={
    "dest": POINTER,
    "src": POINTER,
    "count": UINT
})
def hook_memcpy(ql, address, params):
    try:
        data = bytes(ql.mem.read(params['src'], params['count']))
        ql.mem.write(params['dest'], data)
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)
    return params['dest']

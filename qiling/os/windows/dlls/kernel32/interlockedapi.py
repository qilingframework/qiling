#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import Handle

# void InitializeSListHead(
#   PSLIST_HEADER ListHead
# );
@winsdkapi(cc=STDCALL, params={
    'ListHead' : PSLIST_HEADER
})
def hook_InitializeSListHead(ql: Qiling, address: int, params):
    ListHead = params["ListHead"]

    handle = Handle(obj=[], id=ListHead)
    ql.os.handle_manager.append(handle)

    return 0

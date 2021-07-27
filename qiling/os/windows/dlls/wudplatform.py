#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

@winsdkapi(cc=STDCALL, params={})
def hook_WudfIsUserDebuggerPresent(ql: Qiling, address: int, params):
    return 0


@winsdkapi(cc=STDCALL, params={})
def hook_WudfIsAnyDebuggerPresent(ql: Qiling, address: int, params):
    return 0


@winsdkapi(cc=STDCALL, params={})
def hook_WudfIsKernelDebuggerPresent(ql: Qiling, address: int, params):
    return 0

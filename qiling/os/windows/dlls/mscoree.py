#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# void STDMETHODCALLTYPE CorExitProcess (
#   int  exitCode
# );
@winsdkapi(cc=STDCALL, params={
    'exitCode' : INT
})
def hook_CorExitProcess(ql: Qiling, address: int, params):
    ql.emu_stop()
    ql.os.PE_RUN = False

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct
import base64
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.handle import *
from qiling.os.windows.const import *


# void STDMETHODCALLTYPE CorExitProcess (
#   int  exitCode
# );
@winapi(cc=STDCALL, params={
    "exitCode": DWORD
})
def hook_CorExitProcess(self, address, params):
    self.uc.emu_stop()
    self.PE_RUN = False


# __int32 STDMETHODCALLTYPE _CorExeMain ();
@winapi(cc=STDCALL, params={
})
def hook__CorExeMain(self, address, params):
    # TODO implement + check call type
    pass
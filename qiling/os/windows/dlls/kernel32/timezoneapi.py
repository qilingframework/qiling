#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# DWORD GetTimeZoneInformation(
#   [out] LPTIME_ZONE_INFORMATION lpTimeZoneInformation
# );
@winsdkapi(cc=STDCALL, params={
    'lpTimeZoneInformation' : LPTIME_ZONE_INFORMATION
})
def hook_GetTimeZoneInformation(ql: Qiling, address: int, params):
    # TODO: implement this later. fail for now
    return TIME_ZONE_ID_INVALID

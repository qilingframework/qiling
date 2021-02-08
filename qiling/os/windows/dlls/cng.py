#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

dllname = 'cng_dll'

# typedef struct _OSVERSIONINFOW {
#   ULONG dwOSVersionInfoSize;
#   ULONG dwMajorVersion;
#   ULONG dwMinorVersion;
#   ULONG dwBuildNumber;
#   ULONG dwPlatformId;
#   WCHAR szCSDVersion[128];
# }
# NTSYSAPI NTSTATUS RtlGetVersion(
#   PRTL_OSVERSIONINFOW lpVersionInformation
# );
@winsdkapi(cc=CDECL, dllname=dllname, replace_params={"lpVersionInformation": POINTER})
def hook_RtlGetVersion(ql, address, params):
    pointer = params["lpVersionInformation"]
    size = int.from_bytes(ql.mem.read(pointer, 4), byteorder="little")
    os_version_info_asked = {
        "dwOSVersionInfoSize":
        size,
        VER_MAJORVERSION:
        int.from_bytes(ql.mem.read(pointer + 4, 4), byteorder="little"),
        VER_MINORVERSION:
        int.from_bytes(ql.mem.read(pointer + 8, 4), byteorder="little"),
        VER_BUILDNUMBER:
        int.from_bytes(ql.mem.read(pointer + 12, 4), byteorder="little"),
        VER_PLATFORMID:
        int.from_bytes(ql.mem.read(pointer + 16, 4), byteorder="little"),
        "szCSDVersion":
        int.from_bytes(ql.mem.read(pointer + 20, 128), byteorder="little"),
    }
    ql.mem.write(
        pointer + 4,
        ql.os.profile.getint("SYSTEM",
                             "majorVersion").to_bytes(4, byteorder="little"))
    ql.mem.write(
        pointer + 8,
        ql.os.profile.getint("SYSTEM",
                             "minorVersion").to_bytes(4, byteorder="little"))

    ql.log.debug("The sample is checking the windows Version!")
    return STATUS_SUCCESS

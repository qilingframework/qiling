#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.const import *


# LPCSTR PathFindExtensionA(
#   LPCSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": POINTER
})
def hook_PathFindExtensionA(self, address, params):
    # Must return the address of the dot
    pointer = params["pszPath"]
    pathname = read_cstring(self, pointer)
    size_before_dot = len(pathname.split(".")[0])
    pointer_dot = pointer + size_before_dot
    return pointer_dot


# LPCSTR PathFindFileNameA(
#   LPCSTR pszPath
# );
@winapi(cc=STDCALL, params={
    "pszPath": POINTER
})
def hook_PathFindFileNameA(self, address, params):
    # Must return the address of the start of the filename
    pointer = params["pszPath"]
    pathname = read_cstring(self, pointer)
    size_before_last_slash = len("".join(pathname.split("\\")[:-1])) + pathname.count("\\")
    pointer_start = pointer + size_before_last_slash
    return pointer

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

dllname = 'oleaut32_dll'

# TODO this file is VERY experimental.

# BSTR SysAllocStringLen(
#   const OLECHAR *strIn,
#   UINT          ui
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SysAllocStringLen(ql, address, params):
    addr = ql.os.heap.alloc(params["ui"] + 1)
    if params["strIn"] != 0:
        ql.mem.write(addr, params["strIn"][:params["ui"]].encode("utf-16le"))
    return addr


# void SysFreeString(
#   BSTR bstrString
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SysFreeString(ql, address, params):
    addr = params["strIn"]
    if addr != 0:
        ql.os.heap.free(addr)
        content = ql.os.read_wstring(addr)

        params["strIn"] = content
    return 0


# UINT SysStringLen(
#   BSTR pbstr
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SysStringLen(ql, address, params):
    string = params["pbstr"]
    if string != 0:
        return len(string)
    return 0


# INT SysReAllocStringLen(
#   BSTR          *pbstr,
#   const OLECHAR *psz,
#   unsigned int  len
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SysReAllocStringLen(ql, address, params):
    content = params["psz"]
    size = params["len"]
    addr = ql.os.heap.alloc(size + 1)
    ql.mem.write(addr, content[:size].encode("utf-16le"))
    ql.mem.write(params["pbstr"], addr.to_bytes(ql.pointersize, byteorder="little"))
    return 1


# BSTR SysAllocString(
#   const OLECHAR *psz
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SysAllocString(ql, address, params):
    string = params["psz"]
    if string == 0:
        return 0
    size = len(string)
    addr = ql.os.heap.alloc(size + 1)
    ql.mem.write(addr, string.encode("utf-16le"))
    return addr

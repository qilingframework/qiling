#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# TODO this file is VERY experimental.

# BSTR SysAllocStringLen(
#   const OLECHAR *strIn,
#   UINT          ui
# );
@winsdkapi(cc=STDCALL, params={
    'strIn' : POINTER, # OLECHAR
    'ui'    : UINT
})
def hook_SysAllocStringLen(ql: Qiling, address: int, params):
    strIn = params["strIn"]
    ui = params["ui"]

    addr = ql.os.heap.alloc(ui + 1)

    if strIn:
        ql.mem.write(addr, strIn[:ui].encode("utf-16le"))

    return addr

# void SysFreeString(
#   BSTR bstrString
# );
@winsdkapi(cc=STDCALL, params={
    'bstrString' : POINTER # BSTR
})
def hook_SysFreeString(ql: Qiling, address: int, params):
    bstrString = params["bstrString"]

    if bstrString:
        # params["strIn"] = ql.os.utils.read_wstring(bstrString)

        ql.os.heap.free(bstrString)

# UINT SysStringLen(
#   BSTR pbstr
# );
@winsdkapi(cc=STDCALL, params={
    'pbstr' : BSTR
})
def hook_SysStringLen(ql: Qiling, address: int, params):
    string = params["pbstr"]

    return 0 if string == 0 else len(string)

# INT SysReAllocStringLen(
#   BSTR          *pbstr,
#   const OLECHAR *psz,
#   unsigned int  len
# );
@winsdkapi(cc=STDCALL, params={
    'pbstr' : POINTER,
    'psz'   : OLECHAR,
    'len'   : UINT
})
def hook_SysReAllocStringLen(ql: Qiling, address: int, params):
    content = params["psz"]
    size = params["len"]
    addr = ql.os.heap.alloc(size + 1)

    ql.mem.write(addr, content[:size].encode("utf-16le"))
    ql.mem.write(params["pbstr"], ql.pack(addr))

    return 1

# BSTR SysAllocString(
#   const OLECHAR *psz
# );
@winsdkapi(cc=STDCALL, params={
    'psz' : OLECHAR
})
def hook_SysAllocString(ql: Qiling, address: int, params):
    string = params["psz"]

    if not string:
        return 0

    addr = ql.os.heap.alloc(len(string) + 1)
    ql.mem.write(addr, string.encode("utf-16le"))

    return addr

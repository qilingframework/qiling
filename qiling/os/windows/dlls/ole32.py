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


# HRESULT OleInitialize(
#   IN LPVOID pvReserved
# );
@winapi(cc=STDCALL, params={
    "pvReserved": UINT
})
def hook_OleInitialize(ql, address, params):
    # I don't think we need to do anything, we hook every call for the COM library and manage them locally
    return S_OK


# HRESULT CoRegisterMessageFilter(
#   LPMESSAGEFILTER lpMessageFilter,
#   LPMESSAGEFILTER *lplpMessageFilter
# );
@winapi(cc=STDCALL, params={
    "lpMessageFilter": POINTER,
    "lplpMessageFilter": POINTER
})
def hook_CoRegisterMessageFilter(ql, address, params):
    return S_OK


# HRESULT CoInitializeEx(
#   LPVOID pvReserved,
#   DWORD  dwCoInit
# );
@winapi(cc=STDCALL, params={
    "pvReserved": POINTER,
    "dwCoInit": DWORD
})
def hook_CoInitializeEx(ql, address, params):
    return S_OK

# HRESULT CoInitializeSecurity(
#   PSECURITY_DESCRIPTOR        pSecDesc,
#   LONG                        cAuthSvc,
#   SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
#   void                        *pReserved1,
#   DWORD                       dwAuthnLevel,
#   DWORD                       dwImpLevel,
#   void                        *pAuthList,
#   DWORD                       dwCapabilities,
#   void                        *pReserved3
# );
@winapi(cc=STDCALL, params={
    "pSecDesc": POINTER,
    "cAuthSvc": ULONGLONG,
    "asAuthSvc": POINTER,
    "pReserved1": POINTER,
    "dwAuthnLevel": DWORD,
    "dwImpLevel": DWORD,
    "pAuthList": POINTER,
    "dwCapabilities": DWORD,
    "pReserved3": POINTER
})
def hook_CoInitializeSecurity(ql, address, params):
    return S_OK


# HRESULT CoCreateInstance(
#   REFCLSID  rclsid,
#   LPUNKNOWN pUnkOuter,
#   DWORD     dwClsContext,
#   REFIID    riid,
#   LPVOID    *ppv
# );
@winapi(cc=STDCALL, params={
    "rclsid": POINTER,
    "pUnkOuter": POINTER,
    "dwClsContext": DWORD,
    "riid": POINTER,
    "ppv": POINTER
})
def hook_CoCreateInstance(ql, address, params):
    # FIXME: probably this needs implementation
    return S_OK
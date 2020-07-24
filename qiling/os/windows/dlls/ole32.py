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

dllname = 'ole32_dll'

# HRESULT OleInitialize(
#   IN LPVOID pvReserved
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_OleInitialize(ql, address, params):
    # I don't think we need to do anything, we hook every call for the COM library and manage them locally
    return S_OK


# HRESULT CoRegisterMessageFilter(
#   LPMESSAGEFILTER lpMessageFilter,
#   LPMESSAGEFILTER *lplpMessageFilter
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CoRegisterMessageFilter(ql, address, params):
    return S_OK


# HRESULT CoInitializeEx(
#   LPVOID pvReserved,
#   DWORD  dwCoInit
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CoInitializeSecurity(ql, address, params):
    return S_OK


# HRESULT CoCreateInstance(
#   REFCLSID  rclsid,
#   LPUNKNOWN pUnkOuter,
#   DWORD     dwClsContext,
#   REFIID    riid,
#   LPVOID    *ppv
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CoCreateInstance(ql, address, params):
    # FIXME: probably this needs implementation
    return S_OK
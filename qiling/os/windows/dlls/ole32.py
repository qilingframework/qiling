#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# HRESULT OleInitialize(
#   IN LPVOID pvReserved
# );
@winsdkapi(cc=STDCALL, params={
    'pvReserved' : LPVOID
})
def hook_OleInitialize(ql: Qiling, address: int, params):
    # I don't think we need to do anything, we hook every call for the COM library and manage them locally
    return S_OK

# HRESULT CoRegisterMessageFilter(
#   LPMESSAGEFILTER lpMessageFilter,
#   LPMESSAGEFILTER *lplpMessageFilter
# );
@winsdkapi(cc=STDCALL, params={
    'lpMessageFilter'   : LPMESSAGEFILTER,
    'lplpMessageFilter' : LPMESSAGEFILTER
})
def hook_CoRegisterMessageFilter(ql: Qiling, address: int, params):
    return S_OK

# HRESULT CoInitializeEx(
#   LPVOID pvReserved,
#   DWORD  dwCoInit
# );
@winsdkapi(cc=STDCALL, params={
    'pvReserved' : LPVOID,
    'dwCoInit'   : DWORD
})
def hook_CoInitializeEx(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'pSecDesc'       : PSECURITY_DESCRIPTOR,
    'cAuthSvc'       : LONG,
    'asAuthSvc'      : POINTER,
    'pReserved1'     : PVOID,
    'dwAuthnLevel'   : DWORD,
    'dwImpLevel'     : DWORD,
    'pAuthList'      : PVOID,
    'dwCapabilities' : DWORD,
    'pReserved3'     : PVOID
})
def hook_CoInitializeSecurity(ql: Qiling, address: int, params):
    return S_OK

# HRESULT CoCreateInstance(
#   REFCLSID  rclsid,
#   LPUNKNOWN pUnkOuter,
#   DWORD     dwClsContext,
#   REFIID    riid,
#   LPVOID    *ppv
# );
@winsdkapi(cc=STDCALL, params={
    'rclsid'       : REFCLSID,
    'pUnkOuter'    : LPUNKNOWN,
    'dwClsContext' : DWORD,
    'riid'         : REFIID,
    'ppv'          : LPVOID
})
def hook_CoCreateInstance(ql: Qiling, address: int, params):
    # FIXME: probably this needs implementation
    return S_OK
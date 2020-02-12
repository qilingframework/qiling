#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.handle import *
from qiling.os.windows.const import *


# LSTATUS RegOpenKeyExA(
#   HKEY   hKey,
#   LPCSTR lpSubKey,
#   DWORD  ulOptions,
#   REGSAM samDesired,
#   PHKEY  phkResult
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": STRING,
    "ulOptions": DWORD,
    "samDesired": POINTER,
    "phkResult": POINTER
})
def hook_RegOpenKeyExA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    phkResult = params["phkResult"]

    if hKey not in REG_KEYS:
        return 2
    else:
        s_hKey = REG_KEYS[hKey]
        params["hKey"] = s_hKey

    if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
        return 2

    # new handle
    if ret == ERROR_SUCCESS:
        new_handle = Handle(regkey=s_hKey+"\\"+s_lpSubKey)
        ql.handle_manager.append(new_handle)
        if phkResult != 0:
            ql.mem_write(phkResult, ql.pack(new_handle.id))
    else:
        new_handle = 0

    return ret


# LSTATUS RegOpenKeyW(
#   HKEY    hKey,
#   LPCWSTR lpSubKey,
#   PHKEY   phkResult
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": WSTRING,
    "phkResult": POINTER
})
def hook_RegOpenKeyW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = w2cstring(params["lpSubKey"])
    phkResult = params["phkResult"]

    if not (hKey in REG_KEYS):
        return 2
    else:
        s_hKey = REG_KEYS[hKey]
        params["hKey"] = s_hKey

    if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
        return 2

    # new handle
    if ret == ERROR_SUCCESS:
        new_handle = Handle(regkey=s_hKey+"\\"+s_lpSubKey)
        ql.handle_manager.append(new_handle)
        if phkResult != 0:
            ql.mem_write(phkResult, ql.pack(new_handle.id))
    else:
        new_handle = 0

    return ret



# LSTATUS RegQueryValueExA(
#   HKEY    hKey,
#   LPCSTR  lpValueName,
#   LPDWORD lpReserved,
#   LPDWORD lpType,
#   LPBYTE  lpData,
#   LPDWORD lpcbData
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpValueName": STRING,
    "lpReserved": POINTER,
    "lpType": POINTER,
    "lpData": POINTER,
    "lpcbData": POINTER
})
def hook_RegQueryValueExA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = params["lpValueName"]
    lpType = params["lpType"]
    lpData = params["lpData"]
    lpcbData = params["lpcbData"]

    s_hKey = ql.handle_manager.get(hKey).regkey
    params["hKey"] = s_hKey

    # read reg_type
    if lpType != 0:
        reg_type = ql.unpack(ql.mem_read(lpType, 4))
    else:
        reg_type = Registry.RegNone

    # read registy
    reg_type, value = ql.registry_manager.read(s_hKey, s_lpValueName, reg_type)

    # error key
    if reg_type is None or value is None:
        return 2
    else:
        # set lpData
        length = ql.registry_manager.write_reg_value_into_mem(value, reg_type, lpData)
        # set lpcbData
        ql.mem_write(lpcbData, ql.pack(length))

    return ret


# LSTATUS RegCloseKey(
#   HKEY hKey
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE
})
def hook_RegCloseKey(ql, address, params):
    ret = ERROR_SUCCESS
    hKey = params["hKey"]
    ql.handle_manager.delete(hKey)
    return ret


# LSTATUS RegCreateKeyA(
#   HKEY   hKey,
#   LPCSTR lpSubKey,
#   PHKEY  phkResult
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": STRING,
    "phkResult": POINTER
})
def hook_RegCreateKeyA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    phkResult = params["phkResult"]

    if not (hKey in REG_KEYS):
        return 2
    else:
        s_hKey = REG_KEYS[hKey]
        params["hKey"] = s_hKey
        if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
            ret = ERROR_SUCCESS
            ql.registry_manager.create(s_hKey + "\\" + s_lpSubKey)

    # new handle
    if ret == ERROR_SUCCESS:
        new_handle = Handle(regkey=s_hKey+"\\"+s_lpSubKey)
        ql.handle_manager.append(new_handle)
        if phkResult != 0:
            ql.mem_write(phkResult, ql.pack(new_handle.id))
    else:
        new_handle = 0

    return ret


# LSTATUS RegSetValueA(
#   HKEY   hKey,
#   LPCSTR lpSubKey,
#   DWORD  dwType,
#   LPCSTR lpData,
#   DWORD  cbData
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": STRING,
    "dwType": DWORD,
    "lpData": STRING,
    "cbData": DWORD
})
def hook_RegSetValueA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    dwType = params["dwType"]
    s_lpData = params["lpData"]
    cbData = params["cbData"]

    s_hKey = ql.handle_manager.get(hKey).regkey
    params["hKey"] = s_hKey

    ql.registry_manager.write(s_hKey, s_lpSubKey, dwType, s_lpData)

    return ret


# LSTATUS RegSetValueExW(
#   HKEY       hKey,
#   LPCWSTR    lpValueName,
#   DWORD      Reserved,
#   DWORD      dwType,
#   const BYTE *lpData,
#   DWORD      cbData
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpValueName": WSTRING,
    "Reserved": DWORD,
    "dwType": DWORD,
    "lpData": WSTRING,
    "cbData": DWORD
})
def hook_RegSetValueExW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = w2cstring(params["lpValueName"])
    dwType = params["dwType"]
    s_lpData = w2cstring(params["lpData"])
    cbData = params["cbData"]

    s_hKey = ql.handle_manager.get(hKey).regkey
    params["hKey"] = s_hKey

    ql.registry_manager.write(s_hKey, s_lpValueName, dwType, s_lpData)

    return ret


# LSTATUS RegDeleteKeyA(
#   HKEY   hKey,
#   LPCSTR lpSubKey
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": STRING,
})
def hook_RegDeleteKeyA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]

    s_hKey = ql.handle_manager.get(hKey).regkey
    params["hKey"] = s_hKey

    ql.registry_manager.delete(s_hKey, s_lpSubKey)

    return ret


# LSTATUS RegDeleteValueW(
#   HKEY    hKey,
#   LPCWSTR lpValueName
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpValueName": WSTRING,
})
def hook_RegDeleteValueW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = w2cstring(params["lpValueName"])

    s_hKey = ql.handle_manager.get(hKey).regkey
    params["hKey"] = s_hKey

    ql.registry_manager.delete(s_hKey, s_lpValueName)

    return ret

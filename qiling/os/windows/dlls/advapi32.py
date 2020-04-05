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


def _RegOpenKey(ql, address, params):

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    phkResult = params["phkResult"]

    if hKey not in REG_KEYS:
        ql.dprint(0, "[!] Key %s %s not present" % (hKey, s_lpSubKey))
        return ERROR_FILE_NOT_FOUND
    else:
        s_hKey = REG_KEYS[hKey]
    if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
        ql.dprint(0, "[!] Value key %s\%s not present" % (s_hKey, s_lpSubKey))
        return ERROR_FILE_NOT_FOUND

    # new handle
    new_handle = Handle(regkey=s_hKey + "\\" + s_lpSubKey)
    ql.handle_manager.append(new_handle)
    if phkResult != 0:
        ql.mem.write(phkResult, ql.pack(new_handle.id))
    return ERROR_SUCCESS


def RegQueryValue(ql, address, params):
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
        reg_type = ql.unpack(ql.mem.read(lpType, 4))
    else:
        reg_type = Registry.RegNone

    # read registy
    reg_type, value = ql.registry_manager.read(s_hKey, s_lpValueName, reg_type)

    # error key
    if reg_type is None or value is None:
        ql.dprint(0, "[!] Key value not found")
        return ERROR_FILE_NOT_FOUND
    else:
        # set lpData
        length = ql.registry_manager.write_reg_value_into_mem(value, reg_type, lpData)
        # set lpcbData
        max_size = int.from_bytes(ql.mem.read(lpcbData, 4), byteorder="little")
        ql.mem.write(lpcbData, ql.pack(length))
        if max_size < length:
            ret = ERROR_MORE_DATA

    return ret


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
    return _RegOpenKey(ql, address, params)


# LSTATUS RegOpenKeyExW(
#   HKEY    hKey,
#   LPCWSTR lpSubKey,
#   DWORD   ulOptions,
#   REGSAM  samDesired,
#   PHKEY   phkResult
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": WSTRING,
    "ulOptions": DWORD,
    "samDesired": POINTER,
    "phkResult": POINTER
})
def hook_RegOpenKeyExW(ql, address, params):
    return _RegOpenKey(ql, address, params)


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
    return _RegOpenKey(ql, address, params)


# LSTATUS RegOpenKeyA(
#   HKEY    hKey,
#   LPCWSTR lpSubKey,
#   PHKEY   phkResult
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": STRING,
    "phkResult": POINTER
})
def hook_RegOpenKeyA(ql, address, params):
    return _RegOpenKey(ql, address, params)


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
    return RegQueryValue(ql, address, params)


# LSTATUS RegQueryValueExW(
#   HKEY    hKey,
#   LPCWSTR lpValueName,
#   LPDWORD lpReserved,
#   LPDWORD lpType,
#   LPBYTE  lpData,
#   LPDWORD lpcbData
# );
@winapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpValueName": WSTRING,
    "lpReserved": POINTER,
    "lpType": POINTER,
    "lpData": POINTER,
    "lpcbData": POINTER
})
def hook_RegQueryValueExW(ql, address, params):
    return RegQueryValue(ql, address, params)


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
        new_handle = Handle(regkey=s_hKey + "\\" + s_lpSubKey)
        ql.handle_manager.append(new_handle)
        if phkResult != 0:
            ql.mem.write(phkResult, ql.pack(new_handle.id))
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
    s_lpValueName = params["lpValueName"]
    dwType = params["dwType"]
    s_lpData = params["lpData"]
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
    "lpValueName": WSTRING
})
def hook_RegDeleteValueW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = params["lpValueName"]

    s_hKey = ql.handle_manager.get(hKey).regkey
    params["hKey"] = s_hKey

    ql.registry_manager.delete(s_hKey, s_lpValueName)

    return ret


# BOOL GetTokenInformation(
#   HANDLE                  TokenHandle,
#   TOKEN_INFORMATION_CLASS TokenInformationClass,
#   LPVOID                  TokenInformation,
#   DWORD                   TokenInformationLength,
#   PDWORD                  ReturnLength
# );
@winapi(cc=STDCALL, params={
    "TokenHandle": HANDLE,
    "TokenInformationClass": DWORD,
    "TokenInformation": POINTER,
    "TokenInformationLength": DWORD,
    "ReturnLength": POINTER
})
def hook_GetTokenInformation(ql, address, params):
    id = params["TokenHandle"]
    information = params["TokenInformationClass"]
    max_size = params["TokenInformationLength"]
    return_point = params["ReturnLength"]
    dst = params["TokenInformation"]
    token = ql.handle_manager.get(id).token
    information_value = token.get(information)
    ql.mem.write(return_point, len(information_value).to_bytes(4, byteorder="little"))
    return_size = int.from_bytes(ql.mem.read(return_point, 4), byteorder="little")
    if return_size > max_size:
        ql.commos.last_error  = ERROR_INSUFFICIENT_BUFFER
        return 0
    if dst != 0:
        ql.mem.write(dst, information_value)
        return 1
    else:
        raise QlErrorNotImplemented("[!] API not implemented")


# PUCHAR GetSidSubAuthorityCount(
#   PSID pSid
# );
@winapi(cc=STDCALL, params={
    "pSid": HANDLE
})
def hook_GetSidSubAuthorityCount(ql, address, params):
    sid = ql.handle_manager.get(params["pSid"]).sid
    addr_authority_count = sid.addr + 1  # +1 because the first byte is revision
    return addr_authority_count


# PDWORD GetSidSubAuthority(
#   PSID  pSid,
#   DWORD nSubAuthority
# );
@winapi(cc=STDCALL, params={
    "pSid": HANDLE,
    "nSubAuthority": INT
})
def hook_GetSidSubAuthority(ql, address, params):
    num = params["nSubAuthority"]
    sid = ql.handle_manager.get(params["pSid"]).sid
    addr_authority = sid.addr + 8 + (ql.pointersize * num)
    return addr_authority

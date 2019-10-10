#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.handle import *
from qiling.os.windows.const import *


# SC_HANDLE OpenSCManagerA(
#   LPCSTR lpMachineName,
#   LPCSTR lpDatabaseName,
#   DWORD  dwDesiredAccess
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_OpenSCManagerA(ql, address):
    lpMachineName, lpDatabaseName, dwDesiredAccess = ql.get_params(3)
    ql.nprint('0x%0.2x: OpenSCManagerA(0x%0.2x, 0x%0.2x, 0x%0.2x)' %
         (address, lpMachineName, lpDatabaseName, dwDesiredAccess))


# SC_HANDLE OpenServiceA(
#   SC_HANDLE hSCManager,
#   LPCSTR    lpServiceName,
#   DWORD     dwDesiredAccess
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_OpenServiceA(ql, address):
    hSCManager, lpServiceName, dwDesiredAccess = ql.get_params(3)
    ql.nprint('0x%0.2x: OpenServiceA(0x%0.2x, 0x%0.2x, 0x%0.2x)' %
         (address, hSCManager, lpServiceName, dwDesiredAccess))


# BOOL ChangeServiceConfig2A(
#   SC_HANDLE hService,
#   DWORD     dwInfoLevel,
#   LPVOID    lpInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_ChangeServiceConfig2A(ql, address):
    ret = 1
    hService, dwInfoLevel, lpInfo = ql.get_params(3)
    ql.nprint('0x%0.2x: ChangeServiceConfig2A(0x%0.2x, 0x%0.2x, 0x%0.2x) = %d' %
         (address, hService, dwInfoLevel, lpInfo, ret))
    return ret


# BOOL CloseServiceHandle(
#   SC_HANDLE hSCObject
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_CloseServiceHandle(ql, address):
    ret = 1
    hSCObject = ql.get_params(1)
    ql.nprint('0x%0.2x: CloseServiceHandle(0x%0.2x) = %d' % (address, hSCObject, ret))
    return ret


# LSTATUS RegOpenKeyExA(
#   HKEY   hKey,
#   LPCSTR lpSubKey,
#   DWORD  ulOptions,
#   REGSAM samDesired,
#   PHKEY  phkResult
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_RegOpenKeyExA(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey, ulOptions, samDesired, phkResult = ql.get_params(5)

    s_lpSubKey = read_cstring(ql, lpSubKey)

    if hKey not in REG_KEYS:
        ret = 2
    else:
        s_hKey = REG_KEYS[hKey]

    if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
        ret = 2

    ql.nprint('0x%0.2x: RegOpenKeyExA(%s, "%s", 0x%0.2x, 0x%0.2x, 0x%0.2x) = %d' % \
        (address, s_hKey, s_lpSubKey, ulOptions, samDesired, phkResult, ret))

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
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_RegOpenKeyW(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey, phkResult = ql.get_params(3)

    s_lpSubKey = w2cstring(read_wstring(ql, lpSubKey))

    if not (hKey in REG_KEYS):
        ret = 2
    else:
        s_hKey = REG_KEYS[hKey]

    if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
        ret = 2

    ql.nprint('0x%0.2x: RegOpenKeyW(%s, "%s", 0x%0.2x) = %d' % \
        (address, s_hKey, s_lpSubKey, phkResult, ret))

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
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=6)
def hook_RegQueryValueExA(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpValueName, lpReserved, lpType, lpData, lpcbData = ql.get_params(6)
    s_hKey = ql.handle_manager.get(hKey).regkey
    s_lpValueName = read_cstring(ql, lpValueName)

    # read reg_type
    if lpType != 0:
        reg_type = ql.unpack(ql.mem_read(lpType, 4))
    else:
        reg_type = Registry.RegNone

    # read registy
    reg_type, value = ql.registry_manager.read(s_hKey, s_lpValueName, reg_type)

    # error key
    if reg_type is None or value is None:
        ret = 2
    else:
        # set lpData
        length = ql.registry_manager.write_reg_value_into_mem(value, reg_type, lpData)
        # set lpcbData
        ql.mem_write(lpcbData, ql.pack(length))

    ql.nprint('0x%0.2x: RegQueryValueExA(%s, "%s", 0x%0.2x, 0x%0.2x, 0x%0.2x, 0x%0.2x) = %d' % \
        (address, s_hKey, s_lpValueName, lpReserved, lpType, lpData, lpcbData, ret))
    return ret


# LSTATUS RegCloseKey(
#   HKEY hKey
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_RegCloseKey(ql, address):
    ret = ERROR_SUCCESS
    hKey = ql.get_params(1)
    ql.handle_manager.delete(hKey)
    ql.nprint('0x%0.2x: RegCloseKey(0x%0.2x) = %d' % (address, hKey, ret))
    return ret


# LSTATUS RegCreateKeyA(
#   HKEY   hKey,
#   LPCSTR lpSubKey,
#   PHKEY  phkResult
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_RegCreateKeyA(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey, phkResult = ql.get_params(3)

    s_lpSubKey = read_cstring(ql, lpSubKey)

    if not (hKey in REG_KEYS):
        ret = 2
    else:
        s_hKey = REG_KEYS[hKey]
        if not ql.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
            ret = ERROR_SUCCESS
            ql.registry_manager.create(s_hKey + "\\" + s_lpSubKey)

    ql.nprint('0x%0.2x: RegCreateKeyA(%s, "%s", 0x%0.2x) = %d' % \
        (address, s_hKey, s_lpSubKey, phkResult, ret))

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
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_RegSetValueA(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey, dwType, lpData, cbData = ql.get_params(5)
    s_hKey = ql.handle_manager.get(hKey).regkey
    s_lpSubKey = read_cstring(ql, lpSubKey)
    s_lpData = read_cstring(ql, lpData)

    ql.registry_manager.write(s_hKey, s_lpSubKey, dwType, s_lpData)

    ql.nprint('0x%0.2x: RegSetValueA(%s, "%s", 0x%0.2x, "%s", 0x%0.2x) = %d' % \
        (address, s_hKey, s_lpSubKey, dwType, s_lpData, cbData, ret))
    return ret


# LSTATUS RegSetValueExW(
#   HKEY       hKey,
#   LPCWSTR    lpValueName,
#   DWORD      Reserved,
#   DWORD      dwType,
#   const BYTE *lpData,
#   DWORD      cbData
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=6)
def hook_RegSetValueExW(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey, Reserved, dwType, lpData, cbData = ql.get_params(6)
    s_hKey = ql.handle_manager.get(hKey).regkey
    s_lpSubKey = w2cstring(read_wstring(ql, lpSubKey))
    s_lpData = w2cstring(read_wstring(ql, lpData))

    ql.registry_manager.write(s_hKey, s_lpSubKey, dwType, s_lpData)

    ql.nprint('0x%0.2x: RegSetValueA(%s, "%s", 0x%0.2x, 0x%0.2x, "%s", 0x%0.2x) = %d' % \
        (address, s_hKey, s_lpSubKey, Reserved, dwType, s_lpData, cbData, ret))
    return ret


# LSTATUS RegDeleteKeyA(
#   HKEY   hKey,
#   LPCSTR lpSubKey
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_RegDeleteKeyA(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey = ql.get_params(2)
    s_hKey = ql.handle_manager.get(hKey).regkey
    s_lpSubKey = read_cstring(ql, lpSubKey)

    ql.registry_manager.delete(s_hKey, s_lpSubKey)

    ql.nprint('0x%0.2x: RegDeleteKeyA(%s, "%s") = %d' % \
        (address, s_hKey, s_lpSubKey, ret))
    return ret    


# LSTATUS RegDeleteValueW(
#   HKEY    hKey,
#   LPCWSTR lpValueName
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_RegDeleteValueW(ql, address):
    ret = ERROR_SUCCESS
    hKey, lpSubKey = ql.get_params(2)
    s_hKey = ql.handle_manager.get(hKey).regkey
    s_lpSubKey = w2cstring(read_wstring(ql, lpSubKey))

    ql.registry_manager.delete(s_hKey, s_lpSubKey)

    ql.nprint('0x%0.2x: RegDeleteValueW(%s, "%s") = %d' % \
        (address, s_hKey, s_lpSubKey, ret))
    return ret    
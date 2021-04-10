#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import struct

from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.handle import *
from qiling.os.windows.const import *
from qiling.os.windows.structs import *

dllname = 'advapi32_dll'

def _RegOpenKey(ql, address, params):
    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    phkResult = params["phkResult"]
    ql.log.debug("Key %s %s" % (hKey, s_lpSubKey))

    if hKey not in REG_KEYS:
        ql.log.debug("Key %s %s not present" % (hKey, s_lpSubKey))
        return ERROR_FILE_NOT_FOUND
    else:
        s_hKey = REG_KEYS[hKey]
    key = s_hKey + "\\" + s_lpSubKey

    # Keys in the profile are saved as KEY\PARAM = VALUE, so i just want to check that the key is the same
    keys_profile = [key.rsplit("\\", 1)[0] for key in ql.os.profile["REGISTRY"].keys()]
    if key.lower() in keys_profile:
        ql.log.debug("Using profile for key of  %s" % key)
        ql.os.registry_manager.access(key)
    else:
        if not ql.os.registry_manager.exists(key):
            ql.log.debug("Value key %s not present" % key)
            return ERROR_FILE_NOT_FOUND

    # new handle
    new_handle = Handle(obj=key)
    ql.os.handle_manager.append(new_handle)
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
    s_hKey = ql.os.handle_manager.get(hKey).obj
    params["hKey"] = s_hKey
    # read reg_type
    reg_type = Registry.RegNone if lpType == 0 else ql.unpack32(ql.mem.read(lpType, 4))

    try:
        # Keys in the profile are saved as KEY\PARAM = VALUE, so i just want to check that the key is the same
        value = ql.os.profile["REGISTRY"][s_hKey + "\\" + s_lpValueName]
        ql.log.debug("Using profile for value of key %s" % (s_hKey + "\\" + s_lpValueName,))

        # TODO i have no fucking idea on how to set a None value, fucking configparser
        if value == "None":
            return ERROR_FILE_NOT_FOUND

        reg_type = Registry.RegSZ
        # set that the registry has been accessed
        ql.os.registry_manager.access(s_hKey, s_lpValueName, value, reg_type)

    except KeyError:
        # Read the registry
        reg_type, value = ql.os.registry_manager.read(s_hKey, s_lpValueName, reg_type)

    # error key
    if reg_type is None or value is None:
        ql.log.debug("Key value not found")
        return ERROR_FILE_NOT_FOUND
    else:
        # set lpData
        length = ql.os.registry_manager.write_reg_value_into_mem(value, reg_type, lpData)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegOpenKeyExA(ql, address, params):
    return _RegOpenKey(ql, address, params)


# LSTATUS RegOpenKeyExW(
#   HKEY    hKey,
#   LPCWSTR lpSubKey,
#   DWORD   ulOptions,
#   REGSAM  samDesired,
#   PHKEY   phkResult
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegOpenKeyExW(ql, address, params):
    return _RegOpenKey(ql, address, params)


# LSTATUS RegOpenKeyW(
#   HKEY    hKey,
#   LPCWSTR lpSubKey,
#   PHKEY   phkResult
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegOpenKeyW(ql, address, params):
    return _RegOpenKey(ql, address, params)


# LSTATUS RegOpenKeyA(
#   HKEY    hKey,
#   LPCSTR lpSubKey,
#   PHKEY   phkResult
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegQueryValueExW(ql, address, params):
    return RegQueryValue(ql, address, params)


# LSTATUS RegCloseKey(
#   HKEY hKey
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegCloseKey(ql, address, params):
    ret = ERROR_SUCCESS
    hKey = params["hKey"]
    ql.os.handle_manager.delete(hKey)
    return ret


# LSTATUS RegCreateKeyA(
#   HKEY   hKey,
#   LPCSTR lpSubKey,
#   PHKEY  phkResult
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegCreateKeyA(ql, address, params):
    return hook_RegCreateKeyW.__wrapped__(ql, address, params)


# LSTATUS RegCreateKeyW(
#   HKEY   hKey,
#   LPCWSTR lpSubKey,
#   PHKEY  phkResult
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegCreateKeyW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    phkResult = params["phkResult"]

    if not (hKey in REG_KEYS):
        return 2
    else:
        s_hKey = REG_KEYS[hKey]
        params["hKey"] = s_hKey
        if not ql.os.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
            ret = ERROR_SUCCESS
            ql.os.registry_manager.create(s_hKey + "\\" + s_lpSubKey)

    # new handle
    if ret == ERROR_SUCCESS:
        new_handle = Handle(obj=s_hKey + "\\" + s_lpSubKey)
        ql.os.handle_manager.append(new_handle)
        if phkResult != 0:
            ql.mem.write(phkResult, ql.pack(new_handle.id))
    else:
        new_handle = 0

    return ret


# LSTATUS RegCreateKeyExW(
#   HKEY                        hKey,
#   LPCWSTR                     lpSubKey,
#   DWORD                       Reserved,
#   LPWSTR                      lpClass,
#   DWORD                       dwOptions,
#   REGSAM                      samDesired,
#   const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   PHKEY                       phkResult,
#   LPDWORD                     lpdwDisposition
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'POINTER'})
def hook_RegCreateKeyExW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    phkResult = params["phkResult"]

    if not (hKey in REG_KEYS):
        return 2
    else:
        s_hKey = REG_KEYS[hKey]
        params["hKey"] = s_hKey
        if not ql.os.registry_manager.exists(s_hKey + "\\" + s_lpSubKey):
            ret = ERROR_SUCCESS
            ql.os.registry_manager.create(s_hKey + "\\" + s_lpSubKey)

    # new handle
    if ret == ERROR_SUCCESS:
        new_handle = Handle(obj=s_hKey + "\\" + s_lpSubKey)
        ql.os.handle_manager.append(new_handle)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegSetValueA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]
    dwType = params["dwType"]
    s_lpData = params["lpData"]
    cbData = params["cbData"]

    s_hKey = ql.os.handle_manager.get(hKey).obj
    # this is done so the print_function would print the correct value
    params["hKey"] = s_hKey

    ql.os.registry_manager.write(s_hKey, s_lpSubKey, dwType, s_lpData)

    return ret

# LSTATUS RegSetValueExA(
#   HKEY       hKey,
#   LPCSTR     lpValueName,
#   DWORD      Reserved,
#   DWORD      dwType,
#   const BYTE *lpData,
#   DWORD      cbData
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegSetValueExA(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = params["lpValueName"]
    dwType = params["dwType"]
    s_lpData = params["lpData"]
    cbData = params["cbData"]

    s_hKey = ql.os.handle_manager.get(hKey).obj
    params["hKey"] = s_hKey

    ql.os.registry_manager.write(s_hKey, s_lpValueName, dwType, s_lpData)

    return ret



# LSTATUS RegSetValueExW(
#   HKEY       hKey,
#   LPCWSTR    lpValueName,
#   DWORD      Reserved,
#   DWORD      dwType,
#   const BYTE *lpData,
#   DWORD      cbData
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegSetValueExW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = params["lpValueName"]
    dwType = params["dwType"]
    s_lpData = params["lpData"]
    cbData = params["cbData"]

    s_hKey = ql.os.handle_manager.get(hKey).obj
    # this is done so the print_function would print the correct value
    params["hKey"] = s_hKey

    ql.os.registry_manager.write(s_hKey, s_lpValueName, dwType, s_lpData)

    return ret


# LSTATUS RegDeleteKeyA(
#   HKEY   hKey,
#   LPCSTR lpSubKey
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegDeleteKeyA(ql, address, params):
    return hook_RegDeleteKeyW.__wrapped__(ql, address, params)


# LSTATUS RegDeleteKeyW(
#   HKEY   hKey,
#   LPCWSTR lpSubKey
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegDeleteKeyW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpSubKey = params["lpSubKey"]

    s_hKey = ql.os.handle_manager.get(hKey).obj
    params["hKey"] = s_hKey

    ql.os.registry_manager.delete(s_hKey, s_lpSubKey)

    return ret


# LSTATUS RegDeleteValueA(
#   HKEY    hKey,
#   LPCSTR lpValueName
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegDeleteValueA(ql, address, params):
    return hook_RegDeleteValueW.__wrapped__(ql, address, params)


# LSTATUS RegDeleteValueW(
#   HKEY    hKey,
#   LPCWSTR lpValueName
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegDeleteValueW(ql, address, params):
    ret = ERROR_SUCCESS

    hKey = params["hKey"]
    s_lpValueName = params["lpValueName"]

    s_hKey = ql.os.handle_manager.get(hKey).obj
    params["hKey"] = s_hKey

    ql.os.registry_manager.delete(s_hKey, s_lpValueName)

    return ret


# BOOL GetTokenInformation(
#   HANDLE                  TokenHandle,
#   TOKEN_INFORMATION_CLASS TokenInformationClass,
#   LPVOID                  TokenInformation,
#   DWORD                   TokenInformationLength,
#   PDWORD                  ReturnLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetTokenInformation(ql, address, params):
    id_token = params["TokenHandle"]
    information = params["TokenInformationClass"]
    max_size = params["TokenInformationLength"]
    return_point = params["ReturnLength"]
    dst = params["TokenInformation"]
    token = ql.os.handle_manager.get(id_token).obj
    information_value = token.get(information)
    ql.mem.write(return_point, len(information_value).to_bytes(4, byteorder="little"))
    return_size = int.from_bytes(ql.mem.read(return_point, 4), byteorder="little")
    ql.log.debug("The target is checking for its permissions")
    if return_size > max_size:
        ql.os.last_error = ERROR_INSUFFICIENT_BUFFER
        return 0
    if dst != 0:
        ql.mem.write(dst, information_value)
        return 1
    else:
        raise QlErrorNotImplemented("API not implemented")


# PUCHAR GetSidSubAuthorityCount(
#   PSID pSid
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSidSubAuthorityCount(ql, address, params):
    sid = ql.os.handle_manager.get(params["pSid"]).obj
    addr_authority_count = sid.addr + 1  # +1 because the first byte is revision
    return addr_authority_count


# PDWORD GetSidSubAuthority(
#   PSID  pSid,
#   DWORD nSubAuthority
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'INT'})
def hook_GetSidSubAuthority(ql, address, params):
    num = params["nSubAuthority"]
    sid = ql.os.handle_manager.get(params["pSid"]).obj
    addr_authority = sid.addr + 8 + (ql.pointersize * num)
    return addr_authority

# LSTATUS RegEnumValueA(
#   HKEY    hKey,
#   DWORD   dwIndex,
#   LPSTR   lpValueName,
#   LPDWORD lpcchValueName,
#   LPDWORD lpReserved,
#   LPDWORD lpType,
#   LPBYTE  lpData,
#   LPDWORD lpcbData
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegEnumValueA(ql, address, params):
    return 259 # ERROR_NO_MORE_ITEMS

# SC_HANDLE OpenSCManagerA(
#   LPCSTR lpMachineName,
#   LPCSTR lpDatabaseName,
#   DWORD  dwDesiredAccess
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_OpenSCManagerA(ql, address, params):
    lpMachineName = params["lpMachineName"]
    lpDatabaseName = params["lpDatabaseName"]
    sc_handle_name = "sc_%s_%s" % (lpMachineName, lpDatabaseName)
    new_handle = ql.os.handle_manager.search(sc_handle_name)
    if new_handle is None:
        new_handle = Handle(name=sc_handle_name)
        ql.os.handle_manager.append(new_handle)
    return new_handle.id

# SC_HANDLE CreateServiceA(
#   SC_HANDLE hSCManager,
#   LPCSTR    lpServiceName,
#   LPCSTR    lpDisplayName,
#   DWORD     dwDesiredAccess,
#   DWORD     dwServiceType,
#   DWORD     dwStartType,
#   DWORD     dwErrorControl,
#   LPCSTR    lpBinaryPathName,
#   LPCSTR    lpLoadOrderGroup,
#   LPDWORD   lpdwTagId,
#   LPCSTR    lpDependencies,
#   LPCSTR    lpServiceStartName,
#   LPCSTR    lpPassword
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "hSCManager":HANDLE,
    "lpServiceName": STRING,
    "lpDisplayName": STRING,
    "dwDesiredAccess": DWORD,
    "dwServiceType": DWORD,
    "dwStartType": DWORD,
    "dwErrorControl": DWORD,
    "lpBinaryPathName": STRING,
    "lpLoadOrderGroup": STRING,
    "lpdwTagId": POINTER,
    "lpDependencies": STRING,
    "lpServiceStartName": STRING,
    "lpPassword": STRING
    })
def hook_CreateServiceA(ql, address, params):
    hSCManager = params["hSCManager"]
    lpServiceName = params["lpServiceName"]
    lpBinaryPathName = params["lpBinaryPathName"]
    ql.os.services[lpServiceName] = lpBinaryPathName
    new_handle = Handle(obj=hSCManager, name=lpServiceName)
    ql.os.handle_manager.append(new_handle)
    return new_handle.id

# SC_HANDLE OpenServiceA(
#   SC_HANDLE hSCManager,
#   LPCSTR    lpServiceName,
#   DWORD     dwDesiredAccess
# );
@winsdkapi(cc=STDCALL, dllname=dllname,replace_params={
    "hSCManager":HANDLE,
    "lpServiceName": STRING,
    "dwDesiredAccess": DWORD    
})
def hook_OpenServiceA(ql, address, params):
    hSCManager = params["hSCManager"]
    lpServiceName = params["lpServiceName"]
    if lpServiceName in ql.os.services:
        new_handle = Handle(obj=hSCManager, name=lpServiceName)
        ql.os.handle_manager.append(new_handle)
        return new_handle.id
    else:
        return 0

# BOOL CloseServiceHandle(
#   SC_HANDLE hSCObject
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"hSCObject":HANDLE})
def hook_CloseServiceHandle(ql, address, params):
    hSCObject = params["hSCObject"]
    ql.os.handle_manager.delete(hSCObject)
    return 1

# BOOL StartServiceA(
#   SC_HANDLE hService,
#   DWORD     dwNumServiceArgs,
#   LPCSTR    *lpServiceArgVectors
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_StartServiceA(ql, address, params):
    return 1

# BOOL AllocateAndInitializeSid(
#   PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
#   BYTE                      nSubAuthorityCount,
#   DWORD                     nSubAuthority0,
#   DWORD                     nSubAuthority1,
#   DWORD                     nSubAuthority2,
#   DWORD                     nSubAuthority3,
#   DWORD                     nSubAuthority4,
#   DWORD                     nSubAuthority5,
#   DWORD                     nSubAuthority6,
#   DWORD                     nSubAuthority7,
#   PSID                      *pSid
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_AllocateAndInitializeSid(ql, address, params):
    count = params["nSubAuthorityCount"]
    subs = b""
    for i in range(count):
        sub = params["nSubAuthority" + str(i)]
        subs += sub.to_bytes(4, "little")
    sid = Sid(ql, revision=1, identifier=5, subs=subs, subs_count=count)
    sid_addr = ql.os.heap.alloc(sid.size)
    sid.write(sid_addr)
    handle = Handle(obj=sid, id=sid_addr)
    ql.os.handle_manager.append(handle)
    dest = params["pSid"]
    ql.mem.write(dest, ql.pack(sid_addr))
    return 1


# Some default Sids:
__adminsid = None # Administrators (S-1-5-32-544)
__userssid = None # All Users (S-1-5-32-545)
__guestssid = None # All Users (S-1-5-32-546)
__poweruserssid = None # Power Users (S-1-5-32-547)


def get_adminsid(ql):
    global __adminsid
    if __adminsid == None:
        # nSubAuthority0 = SECURITY_BUILTIN_DOMAIN_RID[0x20], nSubAuthority1 = DOMAIN_ALIAS_RID_ADMINS[0x220]
        subs = b"\x20\x00\x00\x00\x20\x02\x00\x00"
        __adminsid = Sid(ql, revision=1, identifier=5, subs=subs, subs_count=2)
    return __adminsid

def get_userssid(ql):
    global __userssid
    if __userssid == None:
        # nSubAuthority0 = SECURITY_BUILTIN_DOMAIN_RID[0x20], nSubAuthority1 = DOMAIN_ALIAS_RID_USERS[0x221]
        subs = b"\x20\x00\x00\x00\x21\x02\x00\x00"
        __userssid = Sid(ql, revision=1, identifier=5, subs=subs, subs_count=2)
    return __userssid

def get_guestssid(ql):
    global __guestssid
    if __guestssid == None:
        # nSubAuthority0 = SECURITY_BUILTIN_DOMAIN_RID[0x20], nSubAuthority1 = DOMAIN_ALIAS_RID_GUESTS[0x222]
        subs = b"\x20\x00\x00\x00\x22\x02\x00\x00"
        __guestssid = Sid(ql, revision=1, identifier=5, subs=subs, subs_count=2)
    return __guestssid

def get_poweruserssid(ql):
    global __poweruserssid
    if __poweruserssid == None:
        # nSubAuthority0 = SECURITY_BUILTIN_DOMAIN_RID[0x20], nSubAuthority1 = DOMAIN_ALIAS_RID_POWER_USERS[0x223]
        subs = b"\x20\x00\x00\x00\x23\x02\x00\x00"
        __poweruserssid = Sid(ql, revision=1, identifier=5, subs=subs, subs_count=2)
    return __poweruserssid


# BOOL WINAPI CheckTokenMembership(IN HANDLE TokenHandle,
#   IN PSID SidToCheck,
#   OUT PBOOL IsMember
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CheckTokenMembership(ql, address, params):
    token_handle = params["TokenHandle"]
    sid = ql.os.handle_manager.get(params["SidToCheck"]).obj
    # If TokenHandle is NULL, CheckTokenMembership uses the impersonation token of the calling thread.
    IsMember = 0
    if token_handle == 0:
        # For now, treat power users as admins
        if get_adminsid(ql) == sid or get_poweruserssid(ql) == sid:
            IsMember = 1 if ql.os.profile["SYSTEM"]["permission"] == "root" else 0
        elif get_userssid(ql) == sid:
            # FIXME: is this true for all tokens? probably not...
            IsMember = 1
        elif get_guestssid(ql) == sid:
            IsMember = 0
        else:
            assert False, 'unimplemented'
    else:
        assert False, 'unimplemented'
    ql.mem.write(params['IsMember'], ql.pack(IsMember))
    return 1


# PVOID FreeSid(
#   PSID pSid
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_FreeSid(ql, address, params):
    ql.os.heap.free(params["pSid"])
    return 0


# BOOL EqualSid(
#   PSID pSid1,
#   PSID pSid2
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_EqualSid(ql, address, params):
    # TODO once i have understood better how SID are wrote in memory. Fucking documentation
    # technically this one should be my SID that i created at the start. I said should, because when testing, it has a
    # different address. Why? No idea
    # sid1 = ql.os.handle_manager.get(params["pSid1"]).obj
    sid2 = ql.os.handle_manager.get(params["pSid2"]).obj
    # return sid1 == sid2
    return 0

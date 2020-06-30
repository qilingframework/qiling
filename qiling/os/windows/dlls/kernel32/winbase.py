#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.thread import *
from qiling.exception import *
from qiling.os.windows.structs import *

dllname = 'kernel32_dll'

# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_FatalExit(ql, address, params):
    ql.emu_stop()
    ql.os.PE_RUN = False


# PVOID EncodePointer(
#  _In_ PVOID Ptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Ptr": POINTER})
def hook_EncodePointer(ql, address, params):
    return params['Ptr']


# PVOID DecodePointer(
#  _In_ PVOID Ptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Ptr": POINTER})
def hook_DecodePointer(ql, address, params):
    return params['Ptr']


# UINT WinExec(
#   LPCSTR lpCmdLine,
#   UINT   uCmdShow
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_WinExec(ql, address, params):
    return 33


# DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
#   UINT   uFlags,
#   SIZE_T uBytes
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LocalAlloc(ql, address, params):
    ret = ql.os.heap.alloc(params["uBytes"])
    return ret


# DECLSPEC_ALLOCATOR HLOCAL LocalReAlloc(
#   _Frees_ptr_opt_ HLOCAL hMem,
#   SIZE_T                 uBytes,
#   UINT                   uFlags
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LocalReAlloc(ql, address, params):
    old_mem = params["hMem"]
    ql.os.heap.free(old_mem)
    ret = ql.os.heap.alloc(params["uBytes"])
    return ret


# HLOCAL LocalFree(
#   _Frees_ptr_opt_ HLOCAL hMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LocalFree(ql, address, params):
    old_mem = params["hMem"]
    ql.os.heap.free(old_mem)
    return 0


# UINT SetHandleCount(
#   UINT uNumber
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SetHandleCount(ql, address, params):
    uNumber = params["uNumber"]
    return uNumber


# LPVOID GlobalLock(
#  HGLOBAL hMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GlobalLock(ql, address, params):
    return params['hMem']


# LPVOID GlobalUnlock(
#  HGLOBAL hMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GlobalUnlock(ql, address, params):
    return 1


# DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
#  UINT   uFlags,
#  SIZE_T dwBytes
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'SIZE_T': 'UINT'})
def hook_GlobalAlloc(ql, address, params):
    return ql.os.heap.alloc(params["dwBytes"])


# HGLOBAL GlobalFree(
#   _Frees_ptr_opt_ HGLOBAL hMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GlobalFree(ql, address, params):
    old_mem = params["hMem"]
    ql.os.heap.free(old_mem)
    return 0


# HGLOBAL GlobalHandle(
#   LPCVOID pMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GlobalHandle(ql, address, params):
    return params["pMem"]


# LPSTR lstrcpynA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
#   int    iMaxLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcpynA(ql, address, params):
    # Copy String2 into String for max iMaxLength chars
    src = params["lpString2"]
    dst = params["lpString1"]
    max_length = params["iMaxLength"]
    if len(src) > max_length:
        src = src[:max_length]
    ql.mem.write(dst, src.encode())
    return dst


# LPSTR lstrcpynW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2,
#   int    iMaxLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcpynW(ql, address, params):
    # Copy String2 into String for max iMaxLength chars
    src = params["lpString2"]
    dst = params["lpString1"]
    max_length = params["iMaxLength"]
    if len(src) > max_length:
        src = src[:max_length]
    ql.mem.write(dst, src.encode("utf-16le"))
    return dst


# LPSTR lstrcpyA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcpyA(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    dst = params["lpString1"]
    ql.mem.write(dst, src.encode())
    return dst


# LPSTR lstrcpyW(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcpyW(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    dst = params["lpString1"]
    ql.mem.write(dst, src.encode("utf-16le"))
    return dst


# LPSTR lstrcatA(
#   LPSTR  lpString1,
#   LPCSTR lpString2
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcatA(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    pointer = params["lpString1"]
    string_base = ql.os.read_cstring(pointer)
    params["lpString1"] = string_base
    result = string_base + src + "\x00"
    ql.mem.write(pointer, result.encode())
    return pointer


# LPSTR lstrcatW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcatW(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    pointer = params["lpString1"]
    string_base = ql.os.read_wstring(pointer)
    params["lpString1"] = string_base
    result = string_base + src + "\x00"
    ql.mem.write(pointer, result.encode("utf-16le"))
    return pointer


# int lstrcmpiW(
#   LPCWSTR lpString1,
#   LPCWSTR lpString2
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcmpiW(ql, address, params):
    # Copy String2 into String
    str1 = params["lpString1"]
    str2 = params["lpString2"]
    if str1 == str2:
        return 0
    elif str1 > str2:
        return 1
    else:
        return -1


# int lstrcmpiA(
#   LPCSTR lpString1,
#   LPCSTR lpString2
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_lstrcmpiA(ql, address, params):
    return hook_lstrcmpiW.__wrapped__(ql, address, params)


# HRSRC FindResourceA(
#   HMODULE hModule,
#   LPCSTR  lpName,
#   LPCSTR  lpType
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_FindResourceA(ql, address, params):
    # Retrieve a resource
    # Name e Type can be int or strings, this can be a problem
    name = params["lpName"]
    type = params["lpType"]
    # TODO i don't know how to implement this, the return 0 is to simulate an error
    return 0


# BOOL IsBadReadPtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_IsBadReadPtr(ql, address, params):
    # Check read permission for size of memory
    ACCESS_TRUE = 0
    ACCESS_FALSE = 1
    return ACCESS_TRUE


# BOOL IsBadWritePtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_IsBadWritePtr(ql, address, params):
    # Check read permission for size of memory
    ACCESS_TRUE = 0
    ACCESS_FALSE = 1
    return ACCESS_TRUE


def compare(p1, operator, p2):
    if operator == "==":
        return p1 == p2
    elif operator == ">":
        return p1 > p2
    elif operator == ">=":
        return p1 >= p2
    elif operator == "<":
        return p1 < p2
    elif operator == "<=":
        return p1 <= p2
    else:
        raise QlErrorNotImplemented("[!] API not implemented")


# typedef struct _OSVERSIONINFOEXA {
#   DWORD dwOSVersionInfoSize;
#   DWORD dwMajorVersion;
#   DWORD dwMinorVersion;
#   DWORD dwBuildNumber;
#   DWORD dwPlatformId;
#   CHAR  szCSDVersion[128];
#   WORD  wServicePackMajor;
#   WORD  wServicePackMinor;
#   WORD  wSuiteMask;
#   BYTE  wProductType;
#   BYTE  wReserved;
# } OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;


# BOOL VerifyVersionInfoW(
#   LPOSVERSIONINFOEXW lpVersionInformation,
#   DWORD              dwTypeMask,
#   DWORDLONG          dwlConditionMask
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_VerifyVersionInfoW(ql, address, params):
    #  https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow2
    pointer = params["lpVersionInformation"]
    os_asked = OsVersionInfoExA(ql)
    os_asked.read(pointer)
    ConditionMask: dict = ql.os.hooks_variables["ConditionMask"]
    res = True
    for key, value in ConditionMask.items():
        if value == VER_EQUAL:
            operator = "=="
        elif value == VER_GREATER:
            operator = ">"
        elif value == VER_GREATER_EQUAL:
            operator = ">="
        elif value == VER_LESS:
            operator = "<"
        elif value == VER_LESS_EQUAL:
            operator = "<="
        else:
            raise QlErrorNotImplemented("[!] API not implemented with operator %d" % value)
        # Versions should be compared together
        if key == VER_MAJORVERSION or key == VER_MINORVERSION or key == VER_PRODUCT_TYPE:
            major_version_asked = os_asked.major[0]
            minor_version_asked = os_asked.minor[0]
            product_type = os_asked.product[0]
            concat = str(major_version_asked) + str(minor_version_asked) + str(product_type)

            # Just a print for analysts, will remove it from here in the future
            if key == VER_MAJORVERSION:
                ql.dprint(D_RPRT, "[=] The Target is checking the windows Version!")
                version_asked = SYSTEMS_VERSION.get(concat, None)
                if version_asked is None:
                    raise QlErrorNotImplemented("[!] API not implemented for version %s" % concat)
                else:
                    ql.dprint(D_RPRT, "[=] The target asks for version %s %s" % (operator, version_asked))
            # We can finally compare
            qiling_os = str(ql.os.profile.get("SYSTEM", "majorVersion")) + str(
                ql.os.profile.get("SYSTEM", "minorVersion")) + str(
                ql.os.profile.get("SYSTEM", "productType"))
            res = compare(int(qiling_os), operator, int(concat))
        elif key == VER_SERVICEPACKMAJOR:
            res = compare(ql.os.profile.getint("SYSTEM", "VER_SERVICEPACKMAJOR"), operator, os_asked.service_major[0])
        else:
            raise QlErrorNotImplemented("[!] API not implemented for key %s" % key)
        # The result is a AND between every value, so if we find a False we just exit from the loop
        if not res:
            ql.os.last_error = ERROR_OLD_WIN_VERSION
            return 0
    # reset mask
    ql.os.hooks_variables["ConditionMask"] = {}
    return res


# BOOL GetUserNameW(
#   LPWSTR  lpBuffer,
#   LPDWORD pcbBuffer
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"lpBuffer": POINTER, "pcbBuffer": POINTER})
def hook_GetUserNameW(ql, address, params):
    username = (ql.os.profile["USER"]["username"] + "\x00").encode("utf-16le")
    dst = params["lpBuffer"]
    max_size = params["pcbBuffer"]
    ql.mem.write(max_size, len(username).to_bytes(4, byteorder="little"))
    if len(username) > max_size:
        ql.os.last_error = ERROR_INSUFFICIENT_BUFFER
        return 0
    else:
        ql.mem.write(dst, username)
    return 1


# BOOL GetUserNameA(
#   LPCSTR  lpBuffer,
#   LPDWORD pcbBuffer
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetUserNameA(ql, address, params):
    username = (ql.os.profile["USER"]["username"] + "\x00").encode()
    dst = params["lpBuffer"]
    max_size = params["pcbBuffer"]
    ql.mem.write(max_size, len(username).to_bytes(4, byteorder="little"))
    if len(username) > max_size:
        ql.os.last_error = ERROR_INSUFFICIENT_BUFFER
        return 0
    else:
        ql.mem.write(dst, username)
    return 1


# BOOL GetComputerNameW(
#   LPWSTR  lpBuffer,
#   LPDWORD nSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetComputerNameW(ql, address, params):
    computer = (ql.os.profile["SYSTEM"]["computername"] + "\x00").encode("utf-16le")
    dst = params["lpBuffer"]
    max_size = params["nSize"]
    ql.mem.write(max_size, (len(computer) - 2).to_bytes(4, byteorder="little"))
    if len(computer) > max_size:
        ql.os.last_error = ERROR_BUFFER_OVERFLOW
        return 0
    else:
        ql.mem.write(dst, computer)
    return 1


# BOOL GetComputerNameA(
#   LPCSTR  lpBuffer,
#   LPDWORD nSize
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetComputerNameA(ql, address, params):
    computer = (ql.os.profile["SYSTEM"]["computername"] + "\x00").encode()
    dst = params["lpBuffer"]
    max_size = params["nSize"]
    ql.mem.write(max_size, (len(computer) - 2).to_bytes(4, byteorder="little"))
    if len(computer) > max_size:
        ql.os.last_error = ERROR_BUFFER_OVERFLOW
        return 0
    else:
        ql.mem.write(dst, computer)
    return 1

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.thread import *
from qiling.exception import *

# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );


@winapi(cc=STDCALL, params={
    "ExitCode": INT
})
def hook_FatalExit(ql, address, params):
    ql.emu_stop()
    ql.os.PE_RUN = False


# PVOID EncodePointer(
#  _In_ PVOID Ptr
# );
@winapi(cc=STDCALL, params={
    "Ptr": POINTER
})
def hook_EncodePointer(ql, address, params):
    return params['Ptr']


# PVOID DecodePointer(
#  _In_ PVOID Ptr
# );
@winapi(cc=STDCALL, params={
    "Ptr": POINTER
})
def hook_DecodePointer(ql, address, params):
    return params['Ptr']


# UINT WinExec(
#   LPCSTR lpCmdLine,
#   UINT   uCmdShow
# );
@winapi(cc=STDCALL, params={
    "lpCmdLine": STRING,
    "uCmdShow": UINT
})
def hook_WinExec(ql, address, params):
    return 33


# DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
#   UINT   uFlags,
#   SIZE_T uBytes
# );
@winapi(cc=STDCALL, params={
    "uFlags": UINT,
    "uBytes": SIZE_T
})
def hook_LocalAlloc(ql, address, params):
    ret = ql.os.heap.mem_alloc(params["uBytes"])
    return ret


# DECLSPEC_ALLOCATOR HLOCAL LocalReAlloc(
#   _Frees_ptr_opt_ HLOCAL hMem,
#   SIZE_T                 uBytes,
#   UINT                   uFlags
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER,
    "uBytes": SIZE_T,
    "uFlags": UINT
})
def hook_LocalReAlloc(ql, address, params):
    old_mem = params["hMem"]
    ql.os.heap.mem_free(old_mem)
    ret = ql.os.heap.mem_alloc(params["uBytes"])
    return ret


# HLOCAL LocalFree(
#   _Frees_ptr_opt_ HLOCAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_LocalFree(ql, address, params):
    old_mem = params["hMem"]
    ql.os.heap.mem_free(old_mem)
    return 0


# UINT SetHandleCount(
#   UINT uNumber
# );
@winapi(cc=STDCALL, params={
    "uNumber": UINT
})
def hook_SetHandleCount(ql, address, params):
    uNumber = params["uNumber"]
    return uNumber


# LPVOID GlobalLock(
#  HGLOBAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalLock(ql, address, params):
    return params['hMem']


# LPVOID GlobalUnlock(
#  HGLOBAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalUnlock(ql, address, params):
    return 1


# DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
#  UINT   uFlags,
#  SIZE_T dwBytes
# );
@winapi(cc=STDCALL, params={
    "uFlags": UINT,
    "dwBytes": UINT
})
def hook_GlobalAlloc(ql, address, params):
    return ql.os.heap.mem_alloc(params["dwBytes"])


# HGLOBAL GlobalFree(
#   _Frees_ptr_opt_ HGLOBAL hMem
# );
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalFree(ql, address, params):
    old_mem = params["hMem"]
    ql.os.heap.mem_free(old_mem)
    return 0


# HGLOBAL GlobalHandle(
#   LPCVOID pMem
# );
@winapi(cc=STDCALL, params={
    "pMem": POINTER
})
def hook_GlobalHandle(ql, address, params):
    return params["pMem"]


# LPSTR lstrcpynA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
#   int    iMaxLength
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": STRING,
    "iMaxLength": INT
})
def hook_lstrcpynA(ql, address, params):
    # Copy String2 into String for max iMaxLength chars
    src = params["lpString2"]
    dst = params["lpString1"]
    max_length = params["iMaxLength"]
    if len(src) > max_length:
        src = src[:max_length]
    ql.mem.write(dst, bytes(src, encoding="utf-16le"))
    return dst


# LPSTR lstrcpynW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2,
#   int    iMaxLength
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": WSTRING,
    "iMaxLength": INT
})
def hook_lstrcpynW(ql, address, params):
    # Copy String2 into String for max iMaxLength chars
    src = params["lpString2"]
    dst = params["lpString1"]
    max_length = params["iMaxLength"]
    if len(src) > max_length:
        src = src[:max_length]
    ql.mem.write(dst, bytes(src, encoding="utf-16le"))
    return dst


# LPSTR lstrcpyA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": STRING,
})
def hook_lstrcpyA(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    dst = params["lpString1"]
    ql.mem.write(dst, bytes(src, encoding="utf-16le"))
    return dst


# LPSTR lstrcatA(
#   LPSTR  lpString1,
#   LPCSTR lpString2
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": STRING,
})
def hook_lstrcatA(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    pointer = params["lpString1"]
    string_base = read_cstring(ql, pointer)
    result = string_base + src + "\x00"
    ql.mem.write(pointer, bytes(result, encoding="utf-16le"))
    return pointer


# LPSTR lstrcatW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2
# );
@winapi(cc=STDCALL, params={
    "lpString1": POINTER,
    "lpString2": WSTRING,
})
def hook_lstrcatW(ql, address, params):
    # Copy String2 into String
    src = params["lpString2"]
    pointer = params["lpString1"]
    string_base = read_wstring(ql, pointer)
    result = string_base + src + "\x00"
    ql.mem.write(pointer, bytes(result, encoding="utf-16le"))
    return pointer


# int lstrcmpiW(
#   LPCWSTR lpString1,
#   LPCWSTR lpString2
# );
@winapi(cc=STDCALL, params={
    "lpString1": WSTRING,
    "lpString2": WSTRING,
})
def hook_lstrcmpiW(ql, address, params):
    # Copy String2 into String
    str1 = params["lpString1"]
    str2 = params["lpString2"]
    if str1 == str2:
        return 0
    elif str1 > str2:
        return 1
    else:
        # TODO fix negative value
        return -1


# HRSRC FindResourceA(
#   HMODULE hModule,
#   LPCSTR  lpName,
#   LPCSTR  lpType
# );
@winapi(cc=STDCALL, params={
    "hModule": POINTER,
    "lpName": POINTER,
    "lpType": POINTER
})
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
@winapi(cc=STDCALL, params={
    "lp": POINTER,
    "ucb": POINTER
})
def hook_IsBadReadPtr(ql, address, params):
    # Check read permission for size of memory
    ACCESS_TRUE = 0
    ACCESS_FALSE = 1
    return ACCESS_TRUE


# BOOL IsBadWritePtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winapi(cc=STDCALL, params={
    "lp": POINTER,
    "ucb": POINTER
})
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
@winapi(cc=STDCALL, params={
    "lpVersionInformation": POINTER,
    "dwTypeMask": DWORD,
    "dwlConditionMask": ULONGLONG
})
def hook_VerifyVersionInfoW(ql, address, params):
    #  https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow2
    pointer = params["lpVersionInformation"]
    os_version_info_asked = {"dwOSVersionInfoSize": int.from_bytes(ql.mem.read(pointer, 4), byteorder="little"),
                             VER_MAJORVERSION: int.from_bytes(ql.mem.read(pointer + 4, 4), byteorder="little"),
                             VER_MINORVERSION: int.from_bytes(ql.mem.read(pointer + 8, 4), byteorder="little"),
                             VER_BUILDNUMBER: int.from_bytes(ql.mem.read(pointer + 12, 4), byteorder="little"),
                             VER_PLATFORMID: int.from_bytes(ql.mem.read(pointer + 16, 4), byteorder="little"),
                             "szCSDVersion": int.from_bytes(ql.mem.read(pointer + 20, 128), byteorder="little"),
                             VER_SERVICEPACKMAJOR: int.from_bytes(ql.mem.read(pointer + 20 + 128, 2),
                                                                  byteorder="little"),
                             VER_SERVICEPACKMINOR: int.from_bytes(ql.mem.read(pointer + 22 + 128, 2),
                                                                  byteorder="little"),
                             VER_SUITENAME: int.from_bytes(ql.mem.read(pointer + 152, 2), byteorder="little"),
                             VER_PRODUCT_TYPE: int.from_bytes(ql.mem.read(pointer + 154, 1), byteorder="little"),
                             "wReserved": int.from_bytes(ql.mem.read(pointer + 155, 1), byteorder="little"),
                             }
    ConditionMask: dict = ql.os.hooks_variables["ConditionMask"]
    res = True
    for key, value in ConditionMask.items():
        if value == VER_EQUAL:
            operator = "=="
        elif value == VER_GREATER:
            operator = ">"
        elif value == VER_GREATER_EQUAL:
            operator = ">="
        else:
            raise QlErrorNotImplemented("[!] API not implemented with operator %d" % value)
        # Versions should be compared together
        if key == VER_MAJORVERSION or key == VER_MINORVERSION or key == VER_PRODUCT_TYPE:
            major_version_asked = os_version_info_asked[VER_MAJORVERSION]
            minor_version_asked = os_version_info_asked[VER_MINORVERSION]
            product_type = os_version_info_asked[VER_PRODUCT_TYPE]
            concat = str(major_version_asked) + str(minor_version_asked) + str(product_type)

            # Just a print for analysts, will remove it from here in the future
            if key == VER_MAJORVERSION:
                ql.dprint(D_RPRT, "[=] The sample is checking the windows Version!")
                version_asked = SYSTEMS_VERSION.get(concat, None)
                if version_asked is None:
                    raise QlErrorNotImplemented("[!] API not implemented for version %s" % concat)
                else:
                    ql.dprint(D_RPRT, "[=] The sample asks for version %s %s" % (operator, version_asked))
            # We can finally compare
            qiling_os = str(ql.os.profile.get("SYSTEM", "majorVersion")) + \
                        str(ql.os.profile.get("SYSTEM", "minorVersion")) + str(ql.os.profile.get("SYSTEM", "productType"))
            res = compare(int(qiling_os), operator, int(concat))
        elif key == VER_SERVICEPACKMAJOR:
            res = compare(ql.os.profile.getint("SYSTEM", "VER_SERVICEPACKMAJOR"), operator, os_version_info_asked[key])
        else:
            raise QlErrorNotImplemented("[!] API not implemented for key %s" % key)
        # The result is a AND between every value, so if we find a False we just exit from the loop
        if not res:
            ql.os.last_error = ERROR_OLD_WIN_VERSION
            return 0
    return res


# BOOL GetUserNameW(
#   LPWSTR  lpBuffer,
#   LPDWORD pcbBuffer
# );
@winapi(cc=STDCALL, params={
    "lpBuffer": POINTER,
    "pcbBuffer": POINTER
})
def hook_GetUserNameW(ql, address, params):
    username = (ql.os.profile["USER"]["user"]+"\x00").encode("utf-16le")
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
@winapi(cc=STDCALL, params={
    "lpBuffer": POINTER,
    "nSize": POINTER
})
def hook_GetComputerNameW(ql, address, params):
    computer = (ql.os.profile["SYSTEM"]["computer_name"] + "\x00").encode("utf-16le")
    dst = params["lpBuffer"]
    max_size = params["nSize"]
    ql.mem.write(max_size, (len(computer)-2).to_bytes(4, byteorder="little"))
    if len(computer) > max_size:
        #ql.os.last_error = ERROR_BUFFER_OVERFLOW
        return 0
    else:
        ql.mem.write(dst, computer)
    return 1

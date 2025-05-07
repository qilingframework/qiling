#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import configparser

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.structs import make_os_version_info_ex
from qiling.os.windows.utils import cmp

# HFILE _lclose(
#   HFILE hFile
# );
@winsdkapi(cc=STDCALL, params={
    'hFile' : HFILE
})
def hook__lclose(ql: Qiling, address: int, params):
    fileno = params["hFile"]

    if fileno < 0:
        return HFILE_ERROR

    os.close(fileno)

    return fileno

# HFILE _lcreat(
#   LPCSTR lpPathName,
#   int    iAttribute
# );
@winsdkapi(cc=STDCALL, params={
    'lpPathName' : LPCSTR,
    'iAttribute' : INT
})
def hook__lcreat(ql: Qiling, address: int, params):
    s_lpPathName = params["lpPathName"]
    iAttribute = params["iAttribute"]

    # There are 4 access bits, we don't care about hidden or system
    mode = "w+b"
    if iAttribute & 2:
        mode += "r+b"

    try:
        f = ql.os.fs_mapper.open(s_lpPathName, mode)
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return -1

    # The file obj will be closed, dup the file handle to keep open
    return os.dup(f.fileno())

# HFILE _lopen(
#   LPCSTR lpPathName,
#   int    iReadWrite
# );
@winsdkapi(cc=STDCALL, params={
    'lpPathName' : LPCSTR,
    'iReadWrite' : INT
})
def hook__lopen(ql: Qiling, address: int, params):
    s_lpPathName = params["lpPathName"]
    iReadWrite = params["iReadWrite"]

    # access mask DesiredAccess
    mode = ""
    if iReadWrite & (OF_WRITE | OF_READWRITE):
        mode += "wb"
    else:
        mode += "r"

    try:
        f = ql.os.fs_mapper.open(s_lpPathName, mode)
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return -1

    # The file obj will be closed, dup the file handle to keep open
    return os.dup(f.fileno())

# UINT _lread(
#   HFILE  hFile,
#   LPVOID lpBuffer,
#   UINT   uBytes
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'    : HFILE,
    'lpBuffer' : LPVOID,
    'uBytes'   : UINT
})
def hook__lread(ql: Qiling, address: int, params):
    fileno = params["hFile"]
    lpBuffer = params["lpBuffer"]
    uBytes = params["uBytes"]

    if fileno < 0:
        return HFILE_ERROR

    data = os.read(fileno, uBytes)
    ql.mem.write(lpBuffer, data)

    return len(data)

# LONG _llseek(
#   HFILE hFile,
#   LONG  lOffset,
#   int   iOrigin
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'   : HFILE,
    'lOffset' : LONG,
    'iOrigin' : INT
})
def hook__llseek(ql: Qiling, address: int, params):
    fileno = params["hFile"]
    lOffset = params["lOffset"]
    iOrigin = params["iOrigin"]

    if fileno < 0:
        return HFILE_ERROR

    return os.lseek(fileno, lOffset, iOrigin)

# UINT _lwrite(
#   HFILE hFile,
#   LPCCH lpBuffer,
#   UINT  uBytes
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'    : HFILE,
    'lpBuffer' : LPCCH,
    'uBytes'   : UINT
})
def hook__lwrite(ql: Qiling, address: int, params):
    fileno = params["hFile"]
    lpBuffer = params["lpBuffer"]
    uBytes = params["uBytes"]

    if fileno < 0:
        return HFILE_ERROR

    wbuf = ql.mem.read(lpBuffer, uBytes)
    len = os.write(fileno, wbuf)

    return len

# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );
@winsdkapi(cc=STDCALL, params={
    'ExitCode' : INT
})
def hook_FatalExit(ql: Qiling, address: int, params):
    ql.emu_stop()

# UINT WinExec(
#   LPCSTR lpCmdLine,
#   UINT   uCmdShow
# );
@winsdkapi(cc=STDCALL, params={
    'lpCmdLine' : LPCSTR,
    'uCmdShow'  : UINT
})
def hook_WinExec(ql: Qiling, address: int, params):
    return 33

# DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
#   UINT   uFlags,
#   SIZE_T uBytes
# );
@winsdkapi(cc=STDCALL, params={
    'uFlags' : UINT,
    'uBytes' : SIZE_T
})
def hook_LocalAlloc(ql: Qiling, address: int, params):
    uBytes = params["uBytes"]

    return ql.os.heap.alloc(uBytes)

# DECLSPEC_ALLOCATOR HLOCAL LocalReAlloc(
#   _Frees_ptr_opt_ HLOCAL hMem,
#   SIZE_T                 uBytes,
#   UINT                   uFlags
# );
@winsdkapi(cc=STDCALL, params={
    'hMem'   : HLOCAL,
    'uBytes' : SIZE_T,
    'uFlags' : UINT
})
def hook_LocalReAlloc(ql: Qiling, address: int, params):
    LMEM_MODIFY = 0x80

    hMem = params["hMem"]
    uBytes = params["uBytes"]
    uFlags = params['uFlags']

    if uFlags & LMEM_MODIFY:
        raise QlErrorNotImplemented('')

    ql.os.heap.free(hMem)
    ret = ql.os.heap.alloc(uBytes)

    return ret

# HLOCAL LocalFree(
#   _Frees_ptr_opt_ HLOCAL hMem
# );
@winsdkapi(cc=STDCALL, params={
    'hMem' : HLOCAL
})
def hook_LocalFree(ql: Qiling, address: int, params):
    hMem = params["hMem"]

    ql.os.heap.free(hMem)

    return 0

# UINT SetHandleCount(
#   UINT uNumber
# );
@winsdkapi(cc=STDCALL, params={
    'uNumber' : UINT
})
def hook_SetHandleCount(ql: Qiling, address: int, params):
    return params['uNumber']

# LPVOID GlobalLock(
#  HGLOBAL hMem
# );
@winsdkapi(cc=STDCALL, params={
    'hMem' : HGLOBAL
})
def hook_GlobalLock(ql: Qiling, address: int, params):
    return params['hMem']

# LPVOID GlobalUnlock(
#  HGLOBAL hMem
# );
@winsdkapi(cc=STDCALL, params={
    'hMem' : HGLOBAL
})
def hook_GlobalUnlock(ql: Qiling, address: int, params):
    return 1

# DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
#  UINT   uFlags,
#  SIZE_T dwBytes
# );
@winsdkapi(cc=STDCALL, params={
    'uFlags'  : UINT,
    'dwBytes' : SIZE_T
})
def hook_GlobalAlloc(ql: Qiling, address: int, params):
    dwBytes = params['dwBytes']

    return ql.os.heap.alloc(dwBytes)

# HGLOBAL GlobalFree(
#   _Frees_ptr_opt_ HGLOBAL hMem
# );
@winsdkapi(cc=STDCALL, params={
    'hMem' : HGLOBAL
})
def hook_GlobalFree(ql: Qiling, address: int, params):
    hMem = params['hMem']

    ql.os.heap.free(hMem)

    return 0

# HGLOBAL GlobalHandle(
#   LPCVOID pMem
# );
@winsdkapi(cc=STDCALL, params={
    'pMem' : LPCVOID
})
def hook_GlobalHandle(ql: Qiling, address: int, params):
    return params["pMem"]

# LPSTR lstrcpynA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
#   int    iMaxLength
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1'  : LPSTR,
    'lpString2'  : LPCSTR,
    'iMaxLength' : INT
})
def hook_lstrcpynA(ql: Qiling, address: int, params):
    # Copy String2 into String for max iMaxLength chars
    dst: int = params["lpString1"]
    src: str = params["lpString2"]
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
@winsdkapi(cc=STDCALL, params={
    'lpString1'  : LPWSTR,
    'lpString2'  : LPCWSTR,
    'iMaxLength' : INT
})
def hook_lstrcpynW(ql: Qiling, address: int, params):
    # Copy String2 into String for max iMaxLength chars
    dst: int = params["lpString1"]
    src: str = params["lpString2"]
    max_length = params["iMaxLength"]

    if len(src) > max_length:
        src = src[:max_length]

    ql.mem.write(dst, src.encode("utf-16le"))

    return dst

# LPSTR lstrcpyA(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPSTR,
    'lpString2' : LPCSTR
})
def hook_lstrcpyA(ql: Qiling, address: int, params):
    # Copy String2 into String
    dst: int = params["lpString1"]
    src: str = params["lpString2"]

    ql.mem.write(dst, src.encode())

    return dst

# LPSTR lstrcpyW(
#   LPSTR  lpString1,
#   LPCSTR lpString2,
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPWSTR,
    'lpString2' : LPCWSTR
})
def hook_lstrcpyW(ql: Qiling, address: int, params):
    # Copy String2 into String
    dst: int = params["lpString1"]
    src: str = params["lpString2"]

    ql.mem.write(dst, src.encode("utf-16le"))

    return dst

# LPSTR lstrcatA(
#   LPSTR  lpString1,
#   LPCSTR lpString2
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPSTR,
    'lpString2' : LPCSTR
})
def hook_lstrcatA(ql: Qiling, address: int, params):
    # Copy String2 into String
    dst: int = params["lpString1"]
    src: str = params["lpString2"]

    string_base = ql.os.utils.read_cstring(dst)
    # params["lpString1"] = string_base

    result = f'{string_base}{src}\x00'
    ql.mem.write(dst, result.encode())

    return dst

# LPSTR lstrcatW(
#   LPWSTR  lpString1,
#   LPCWSTR lpString2
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPWSTR,
    'lpString2' : LPCWSTR
})
def hook_lstrcatW(ql: Qiling, address: int, params):
    # Copy String2 into String
    dst: int = params["lpString1"]
    src: str = params["lpString2"]

    string_base = ql.os.utils.read_wstring(dst)
    # params["lpString1"] = string_base

    result = f'{string_base}{src}\x00'
    ql.mem.write(dst, result.encode("utf-16le"))

    return dst

def __lstrlen(ql: Qiling, address: int, params):
    s = params["lpString"]

    return 0 if not s else len(s)

# int lstrlenA(
#   LPCSTR lpString
# );
@winsdkapi(cc=STDCALL, params={
    'lpString' : LPCSTR
})
def hook_lstrlenA(ql: Qiling, address: int, params):
    return __lstrlen(ql, address, params)

# int lstrlenW(
#   LPCWSTR lpString
# );
@winsdkapi(cc=STDCALL, params={
    'lpString' : LPCWSTR
})
def hook_lstrlenW(ql: Qiling, address: int, params):
    return __lstrlen(ql, address, params)

def __lstrcmp(ql: Qiling, address: int, params):
    str1 = params["lpString1"]
    str2 = params["lpString2"]

    return cmp(str1, str2)

def __lstrcmpi(ql: Qiling, address: int, params):
    str1 = params["lpString1"].lower()
    str2 = params["lpString2"].lower()

    return cmp(str1, str2)

# int lstrcmpiW(
#   LPCWSTR lpString1,
#   LPCWSTR lpString2
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPCWSTR,
    'lpString2' : LPCWSTR
})
def hook_lstrcmpiW(ql: Qiling, address: int, params):
    return __lstrcmpi(ql, address, params)

# int lstrcmpiA(
#   LPCSTR lpString1,
#   LPCSTR lpString2
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPCSTR,
    'lpString2' : LPCSTR
})
def hook_lstrcmpiA(ql: Qiling, address: int, params):
    return __lstrcmpi(ql, address, params)

# int lstrcmpW(
#   LPCWSTR lpString1,
#   LPCWSTR lpString2
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPCWSTR,
    'lpString2' : LPCWSTR
})
def hook_lstrcmpW(ql: Qiling, address: int, params):
    return __lstrcmp(ql, address, params)

# int lstrcmpA(
#   LPCSTR lpString1,
#   LPCSTR lpString2
# );
@winsdkapi(cc=STDCALL, params={
    'lpString1' : LPCSTR,
    'lpString2' : LPCSTR
})
def hook_lstrcmpA(ql: Qiling, address: int, params):
    return __lstrcmp(ql, address, params)

# HRSRC FindResourceA(
#   HMODULE hModule,
#   LPCSTR  lpName,
#   LPCSTR  lpType
# );
@winsdkapi(cc=STDCALL, params={
    'hModule' : HMODULE,
    'lpName'  : LPCSTR,
    'lpType'  : LPCSTR
})
def hook_FindResourceA(ql: Qiling, address: int, params):
    # Retrieve a resource
    # Name e Type can be int or strings, this can be a problem

    # TODO i don't know how to implement this, the return 0 is to simulate an error
    return 0

# BOOL IsBadReadPtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winsdkapi(cc=STDCALL, params={
    'lp'  : LPVOID,
    'ucb' : UINT_PTR
})
def hook_IsBadReadPtr(ql: Qiling, address: int, params):
    # Check read permission for size of memory
    return 0 # ACCESS_TRUE

# BOOL IsBadWritePtr(
#   const VOID *lp,
#   UINT_PTR   ucb
# );
@winsdkapi(cc=STDCALL, params={
    'lp'  : LPVOID,
    'ucb' : UINT_PTR
})
def hook_IsBadWritePtr(ql: Qiling, address: int, params):
    # Check write permission for size of memory
    return 0 # ACCESS_TRUE

# BOOL VerifyVersionInfoW(
#   LPOSVERSIONINFOEXW lpVersionInformation,
#   DWORD              dwTypeMask,
#   DWORDLONG          dwlConditionMask
# );
@winsdkapi(cc=STDCALL, params={
    'lpVersionInformation' : LPOSVERSIONINFOEXW,
    'dwTypeMask'           : DWORD,
    'dwlConditionMask'     : DWORDLONG
})
def hook_VerifyVersionInfoW(ql: Qiling, address: int, params):
    return __VerifyVersionInfo(ql, address, params, wide=True)

# BOOL VerifyVersionInfoA(
#   LPOSVERSIONINFOEXA lpVersionInformation,
#   DWORD              dwTypeMask,
#   DWORDLONG          dwlConditionMask
# );
@winsdkapi(cc=STDCALL, params={
    'lpVersionInformation' : LPOSVERSIONINFOEXA,
    'dwTypeMask'           : DWORD,
    'dwlConditionMask'     : DWORDLONG
})
def hook_VerifyVersionInfoA(ql: Qiling, address: int, params):
    return __VerifyVersionInfo(ql, address, params, wide=False)

def __VerifyVersionInfo(ql: Qiling, address: int, params, *, wide: bool):
    # see: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow

    lpVersionInformation = params['lpVersionInformation']
    dwTypeMask = params['dwTypeMask']
    dwlConditionMask = params['dwlConditionMask']

    oviex_struct = make_os_version_info_ex(ql.arch.bits, wide=wide)

    askedOsVersionInfo = oviex_struct.load_from(ql.mem, lpVersionInformation)

    # reading emulated os version info from profile
    # FIXME: read the necessary information from KUSER_SHARED_DATA instead
    osconfig = ql.os.profile['SYSTEM']

    emulOsVersionInfo = oviex_struct(
        dwMajorVersion      = osconfig.getint('majorVersion'),
        dwMinorVersion      = osconfig.getint('minorVersion'),
        dwBuildNumber       = 0,
        dwPlatformId        = 0,
        wServicePackMajor   = osconfig.getint('VER_SERVICEPACKMAJOR'),
        wServicePackMinor   = 0,
        wSuiteMask          = 0,
        wProductType        = osconfig.getint('productType')
    )

    # check criteria by the order they should be evaluated. the online microsoft
    # documentation only specify the first five, so not sure about the other three.
    #
    # each criteria is associated with the OSVERSIONINFOEX[A|W] it corresponds to.
    checks = (
        (1, 'dwMajorVersion'),      # VER_MAJORVERSION
        (0, 'dwMinorVersion'),      # VER_MINORVERSION
        (2, 'dwBuildNumber'),       # VER_BUILDNUMBER
        (5, 'wServicePackMajor'),   # VER_SERVICEPACKMAJOR
        (4, 'wServicePackMinor'),   # VER_SERVICEPACKMINOR
        (3, 'dwPlatformId'),        # VER_PLATFORMID
        (6, 'wSuiteMask'),          # VER_SUITENAME
        (7, 'wProductType')         # VER_PRODUCT_TYPE
    )

    res = True

    for bit, field in checks:
        if dwTypeMask & (1 << bit):
            asked = getattr(askedOsVersionInfo, field)
            emuld = getattr(emulOsVersionInfo, field)

            # extract the condition code for the required field
            cond = (dwlConditionMask >> (bit * VER_NUM_BITS_PER_CONDITION_MASK)) & VER_CONDITION_MASK

            # special case for VER_SUITENAME
            if bit == 6:
                cond_op = {
                    VER_AND : lambda a, b: (a & b) == b,  # all members of b must be present
                    VER_OR  : lambda a, b: (a & b) != 0   # at least one member of b must be present
                }[cond]

                res &= cond_op(emuld, asked)

            else:
                # cond operates as a bitmask, so multiple 'if' statements are appropriately
                # used here. do not turn this into an 'elif' construct.

                if (cond & VER_GREATER) and (emuld > asked):
                    return 1

                if (cond & VER_LESS) and (emuld < asked):
                    return 1

                if (cond & VER_EQUAL):
                    res &= (emuld == asked)

    if not res:
        ql.os.last_error = ERROR_OLD_WIN_VERSION

    return int(res)

def __GetUserName(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]
    pcbBuffer = params["pcbBuffer"]

    enc = "utf-16le" if wstring else "utf-8"
    username = f'{ql.os.profile["USER"]["username"]}\x00'.encode(enc)

    max_size = ql.mem.read_ptr(pcbBuffer, 4)
    ql.mem.write_ptr(pcbBuffer, len(username), 4)

    if len(username) > max_size:
        ql.os.last_error = ERROR_INSUFFICIENT_BUFFER
        return 0

    ql.mem.write(lpBuffer, username)
    return 1

# BOOL GetUserNameW(
#   LPWSTR  lpBuffer,
#   LPDWORD pcbBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer'  : LPWSTR,
    'pcbBuffer' : LPDWORD
})
def hook_GetUserNameW(ql: Qiling, address: int, params):
    return __GetUserName(ql, address, params, True)

# BOOL GetUserNameA(
#   LPCSTR  lpBuffer,
#   LPDWORD pcbBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer'  : LPSTR,
    'pcbBuffer' : LPDWORD
})
def hook_GetUserNameA(ql: Qiling, address: int, params):
    return __GetUserName(ql, address, params, False)

def __GetComputerName(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]
    nSize = params["nSize"]

    enc = "utf-16le" if wstring else "utf-8"
    computer = f'{ql.os.profile["SYSTEM"]["computername"]}\x00'.encode(enc)

    max_size = ql.mem.read_ptr(nSize, 4)
    ql.mem.write_ptr(nSize, len(computer), 4)

    if len(computer) > max_size:
        ql.os.last_error = ERROR_BUFFER_OVERFLOW
        return 0

    ql.mem.write(lpBuffer, computer)
    return 1

# BOOL GetComputerNameW(
#   LPWSTR  lpBuffer,
#   LPDWORD nSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPWSTR,
    'nSize'    : LPDWORD
})
def hook_GetComputerNameW(ql: Qiling, address: int, params):
    return __GetComputerName(ql, address, params, True)

# BOOL GetComputerNameA(
#   LPCSTR  lpBuffer,
#   LPDWORD nSize
# );
@winsdkapi(cc=STDCALL, params={
    'lpBuffer' : LPSTR,
    'nSize'    : LPDWORD
})
def hook_GetComputerNameA(ql: Qiling, address: int, params):
    return __GetComputerName(ql, address, params, False)

# DWORD GetPrivateProfileStringA(
#   LPCSTR lpAppName,
#   LPCSTR lpKeyName,
#   LPCSTR lpDefault,
#   LPSTR  lpReturnedString,
#   DWORD  nSize,
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpAppName'        : LPCSTR,
    'lpKeyName'        : LPCSTR,
    'lpDefault'        : LPCSTR,
    'lpReturnedString' : LPSTR,
    'nSize'            : DWORD,
    'lpFileName'       : LPCSTR
})
def hook_GetPrivateProfileStringA(ql: Qiling, address: int, params):
    lpAppName = params["lpAppName"]
    lpKeyName = params["lpKeyName"]
    lpDefault = params["lpDefault"]
    lpReturnedString = params["lpReturnedString"]
    nSize = params["nSize"]
    lpFileName = params['lpFileName']

    try:
        # TODO: this doesn't seem to be safe
        f = open(lpFileName)
    except:
        ql.os.last_error = ERROR_OLD_WIN_VERSION
        return 0

    config = configparser.ConfigParser()
    config.read_file(f)

    if lpAppName in config and lpKeyName in config[lpAppName]:
        value = config[lpAppName][lpKeyName].encode("utf-8")
    else:
        value = lpDefault

    write_len = min(len(value), nSize - 1)

    ql.mem.write(lpReturnedString, value[:write_len] + b"\x00")
    f.close()

    return write_len

# BOOL WritePrivateProfileStringA(
#   LPCSTR lpAppName,
#   LPCSTR lpKeyName,
#   LPCSTR lpString,
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpAppName'  : LPCSTR,
    'lpKeyName'  : LPCSTR,
    'lpString'   : LPCSTR,
    'lpFileName' : LPCSTR
})
def hook_WritePrivateProfileStringA(ql: Qiling, address: int, params):
    pass

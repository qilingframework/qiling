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
from qiling.os.windows.structs import OsVersionInfoExA
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
    ql.os.PE_RUN = False

# PVOID EncodePointer(
#  _In_ PVOID Ptr
# );
@winsdkapi(cc=STDCALL, params={
    'Ptr' : PVOID
})
def hook_EncodePointer(ql: Qiling, address: int, params):
    return params['Ptr']

# PVOID DecodePointer(
#  _In_ PVOID Ptr
# );
@winsdkapi(cc=STDCALL, params={
    'Ptr' : PVOID
})
def hook_DecodePointer(ql: Qiling, address: int, params):
    return params['Ptr']

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

def compare(p1: int, operator: int, p2: int) -> bool:
    op = {
        VER_EQUAL         : lambda a, b: a == b,
        VER_GREATER       : lambda a, b: a > b,
        VER_GREATER_EQUAL : lambda a, b: a >= b,
        VER_LESS          : lambda a, b: a < b,
        VER_LESS_EQUAL    : lambda a, b: a <= b
    }.get(operator)

    if not op:
        raise QlErrorNotImplemented('')

    return op(p1, p2)

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
    # https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow2
    pointer = params["lpVersionInformation"]

    os_asked = OsVersionInfoExA(ql)
    os_asked.read(pointer)

    ConditionMask: dict = ql.os.hooks_variables["ConditionMask"]
    res = True

    opstr = {
        VER_EQUAL         : '==',
        VER_GREATER       : '>',
        VER_GREATER_EQUAL : '>=',
        VER_LESS          : '<',
        VER_LESS_EQUAL    : '<='
    }

    for key, value in ConditionMask.items():
        if value not in opstr:
            raise QlErrorNotImplemented(f'API not implemented with operator {value}')

        # Versions should be compared together
        if key in (VER_MAJORVERSION, VER_MINORVERSION, VER_PRODUCT_TYPE):
            concat = f'{os_asked.major[0]}{os_asked.minor[0]}{os_asked.product[0]}'

            # Just a print for analysts, will remove it from here in the future
            if key == VER_MAJORVERSION:
                ql.log.debug("The Target is checking the windows Version!")
                version_asked = SYSTEMS_VERSION.get(concat, None)

                if version_asked is None:
                    raise QlErrorNotImplemented(f'API not implemented for version {concat}')

                ql.log.debug(f'The target asks for version {opstr[value]} {version_asked}')

            qiling_os = \
                f'{ql.os.profile.get("SYSTEM", "majorVersion")}' + \
                f'{ql.os.profile.get("SYSTEM", "minorVersion")}' + \
                f'{ql.os.profile.get("SYSTEM", "productType")}'

            # We can finally compare
            res = compare(int(qiling_os), value, int(concat))

        elif key == VER_SERVICEPACKMAJOR:
            res = compare(ql.os.profile.getint("SYSTEM", "VER_SERVICEPACKMAJOR"), value, os_asked.service_major[0])

        else:
            raise QlErrorNotImplemented("API not implemented for key %s" % key)

        # The result is a AND between every value, so if we find a False we just exit from the loop
        if not res:
            ql.os.last_error = ERROR_OLD_WIN_VERSION
            return 0

    # reset mask
    ql.os.hooks_variables["ConditionMask"] = {}

    return res

def __GetUserName(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]
    pcbBuffer = params["pcbBuffer"]

    enc = "utf-16le" if wstring else "utf-8"
    username = f'{ql.os.profile["USER"]["username"]}\x00'.encode(enc)

    max_size = ql.unpack32(ql.mem.read(pcbBuffer, 4))
    ql.mem.write(pcbBuffer, ql.pack32(len(username)))

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

    max_size = ql.unpack32(ql.mem.read(nSize, 4))
    ql.mem.write(nSize, ql.pack32(len(computer)))

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

# BOOL DeleteFileA(
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName' : LPCSTR
})
def hook_DeleteFileA(ql: Qiling, address: int, params):
    return 1

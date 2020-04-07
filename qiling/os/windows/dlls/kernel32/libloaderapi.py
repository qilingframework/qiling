#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.fncc import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from os.path import *


def _GetModuleHandle(ql, address, params):
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        lpModuleName = lpModuleName.lower()
        if not is_file_library(lpModuleName):
            lpModuleName += ".dll"
        if lpModuleName in ql.PE.dlls:
            ret = ql.PE.dlls[lpModuleName]
        else:
            ql.dprint(0, "[!] Library %s not imported" % lpModuleName)
            # Let's try to import it if the sample think is default dll and was imported at the start

            # Probably we can optimize here since load_dll already do a lot of checks, but not a real problem
            path = os.path.join(ql.rootfs, ql.dlls, lpModuleName)
            if is_file_library(lpModuleName) and os.path.exists(path):
                ret = ql.PE.load_dll(lpModuleName.encode())
            else:
                ql.dprint(0, "[!] Library %s not found" % lpModuleName)
                ret = 0
    return ret


# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winapi(cc=STDCALL, params={
    "lpModuleName": STRING
})
def hook_GetModuleHandleA(ql, address, params):
    return _GetModuleHandle(ql, address, params)


# HMODULE GetModuleHandleW(
#   LPCWSTR lpModuleName
# );
@winapi(cc=STDCALL, params={
    "lpModuleName": WSTRING
})
def hook_GetModuleHandleW(ql, address, params):
    return _GetModuleHandle(ql, address, params)


# DWORD GetModuleFileNameA(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winapi(cc=STDCALL, params={
    "hModule": HANDLE,
    "lpFilename": POINTER,
    "nSize": DWORD
})
def hook_GetModuleFileNameA(ql, address, params):
    ret = 0
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]

    # GetModuleHandle can return PE_IMAGE_BASE as handle, and GetModuleFileName will try to retrieve it.
    # Pretty much 0 and PE_IMAGE_BASE value should do the same operations
    if hModule == 0 or hModule == ql.PE.PE_IMAGE_BASE:
        filename = ql.PE.filepath
        filename_len = len(filename)
        if filename_len > nSize - 1:
            filename = ql.PE.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len
        ql.mem.write(lpFilename, filename + b"\x00")
    else:
        ql.dprint(0, "hModule %x" % hModule)
        raise QlErrorNotImplemented("[!] API not implemented")
    return ret


# DWORD GetModuleFileNameW(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winapi(cc=STDCALL, params={
    "hModule": HANDLE,
    "lpFilename": POINTER,
    "nSize": DWORD
})
def hook_GetModuleFileNameW(ql, address, params):
    ret = 0
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]
    # GetModuleHandle can return PE_IMAGE_BASE as handle, and GetModuleFileName will try to retrieve it.
    # Pretty much 0 and PE_IMAGE_BASE value should do the same operations
    if hModule == 0 or hModule == ql.PE.PE_IMAGE_BASE:
        filename = ql.PE.filepath.decode('ascii').encode('utf-16le')
        filename_len = len(filename)
        if filename_len > nSize - 1:
            filename = ql.PE.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len
        ql.mem.write(lpFilename, filename + b"\x00")
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return ret


# FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
# );
@winapi(cc=STDCALL, params={
    "hModule": POINTER,
    "lpProcName": STRING
})
def hook_GetProcAddress(ql, address, params):
    lpProcName = bytes(params["lpProcName"], 'ascii')
    # Check if dll is loaded
    try:
        dll_name = [key for key, value in ql.PE.dlls.items() if value == params['hModule']][0]
    except IndexError as ie:
        ql.nprint('[!] Failed to import function "%s" with handle 0x%X' % (lpProcName, params['hModule']))
        return 0

    if lpProcName in ql.PE.import_address_table[dll_name]:
        return ql.PE.import_address_table[dll_name][lpProcName]

    return 0


# HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
# );
@winapi(cc=STDCALL, params={
    "lpLibFileName": STRING
})
def hook_LoadLibraryA(ql, address, params):
    lpLibFileName = params["lpLibFileName"]
    dll_base = ql.PE.load_dll(lpLibFileName.encode())
    return dll_base


# HMODULE LoadLibraryExA(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
# );
@winapi(cc=STDCALL, params={
    "lpLibFileName": STRING,
    "hFile": POINTER,
    "dwFlags": DWORD
})
def hook_LoadLibraryExA(ql, address, params):
    lpLibFileName = params["lpLibFileName"]
    dll_base = ql.PE.load_dll(lpLibFileName.encode())
    return dll_base


# HMODULE LoadLibraryW(
#   LPCWSTR lpLibFileName
# );
@winapi(cc=STDCALL, params={
    "lpLibFileName": WSTRING
})
def hook_LoadLibraryW(ql, address, params):
    lpLibFileName = bytes(bytes(params["lpLibFileName"], 'ascii').decode('utf-16le'), 'ascii')
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base


# HMODULE LoadLibraryExW(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
# );
@winapi(cc=STDCALL, params={
    "lpLibFileName": WSTRING,
    "hFile": POINTER,
    "dwFlags": DWORD
})
def hook_LoadLibraryExW(ql, address, params):
    lpLibFileName = params["lpLibFileName"].encode()
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base


# DWORD SizeofResource(
#   HMODULE hModule,
#   HRSRC   hResInfo
# );
@winapi(cc=STDCALL, params={
    "hModule": POINTER,
    "hResInfo": POINTER
})
def hook_SizeofResource(ql, address, params):
    # Return size of resource
    # TODO set a valid value. More tests have to be made to find it.
    return 0x8


# HGLOBAL LoadResource(
#   HMODULE hModule,
#   HRSRC   hResInfo
# );
@winapi(cc=STDCALL, params={
    "hModule": POINTER,
    "hResInfo": POINTER
})
def hook_LoadResource(ql, address, params):
    pointer = params["hResInfo"]
    return pointer


# LPVOID LockResource(
#   HGLOBAL hResData
# );
@winapi(cc=STDCALL, params={
    "hResData": POINTER
})
def hook_LockResource(ql, address, params):
    pointer = params["hResData"]
    return pointer

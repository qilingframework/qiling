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
from qiling.os.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winapi(cc=STDCALL, params={
    "lpModuleName": STRING
})
def hook_GetModuleHandleA(ql, address, params):
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        if not lpModuleName.lower().endswith(".dll") and not lpModuleName.lower().endswith(".drv"):
            lpModuleName += ".dll"
        if lpModuleName.lower() in ql.PE.dlls:
            ret = ql.PE.dlls[lpModuleName.lower()]
        else:
            ret = 0
    return ret


# HMODULE GetModuleHandleW(
#   LPCWSTR lpModuleName
# );
@winapi(cc=STDCALL, params={
    "lpModuleName": WSTRING
})
def hook_GetModuleHandleW(ql, address, params):
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        lpModuleName = bytes(lpModuleName, "ascii").decode('utf-16le')
        if not lpModuleName.lower().endswith(".dll") and not lpModuleName.lower().endswith(".drv"):
            lpModuleName += ".dll"
        if lpModuleName.lower() in ql.PE.dlls:
            ret = ql.PE.dlls[lpModuleName.lower()]
        else:
            ret = 0
    return ret


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
    if hModule == 0:
        filename = ql.PE.filepath
        filename_len = len(filename)
        if filename_len > nSize - 1:
            filename = ql.PE.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len
        ql.uc.mem_write(lpFilename, filename + b"\x00")
    else:
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
    if hModule == 0:
        filename = ql.PE.filepath.decode('ascii').encode('utf-16le')
        filename_len = len(filename)
        if filename_len > nSize - 1:
            filename = ql.PE.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len
        ql.uc.mem_write(lpFilename, filename + b"\x00")
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

    return 1


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
    lpLibFileName = bytes(bytes(params["lpLibFileName"], "ascii").decode('utf-16le'), 'ascii')
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base

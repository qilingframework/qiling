#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os

from qiling.exception import *
from qiling.os.windows.const import *

from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *


def _GetModuleHandle(ql, address, params):
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.loader.pe_image_address
    else:
        lpModuleName = lpModuleName.lower()
        if not is_file_library(lpModuleName):
            lpModuleName += ".dll"
        if lpModuleName in ql.loader.dlls:
            ret = ql.loader.dlls[lpModuleName]
        else:
            ql.dprint(D_INFO, "[!] Library %s not imported" % lpModuleName)
            # Let's try to import it if the sample think is default dll and was imported at the start
            # Probably we can optimize here since load_dll already do a lot of checks, but not a real problem
            path = os.path.join(ql.rootfs, ql.dlls, lpModuleName)
            if is_file_library(lpModuleName) and os.path.exists(path):
                ret = ql.loader.load_dll(lpModuleName.encode())
            else:
                ql.dprint(D_INFO, "[!] Library %s not found" % lpModuleName)
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


# BOOL GetModuleHandleExW(
#   DWORD   dwFlags,
#   LPCWSTR lpModuleName,
#   HMODULE *phModule
# );
@winapi(cc=STDCALL, params={
    "dwFlags": DWORD,
    "lpModuleName": WSTRING,
    "phModule": HANDLE
})
def hook_GetModuleHandleExW(ql, address, params):
    res = _GetModuleHandle(ql, address, params)
    dst = params["phModule"]
    ql.mem.write(dst, res.to_bytes(4, byteorder="little"))
    return 1


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

    # GetModuleHandle can return pe_image_address as handle, and GetModuleFileName will try to retrieve it.
    # Pretty much 0 and pe_image_address value should do the same operations
    if hModule == 0 or hModule == ql.loader.pe_image_address:
        filename = ql.loader.filepath
        filename_len = len(filename)
        if filename_len > nSize - 1:
            filename = ql.loader.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len
        ql.mem.write(lpFilename, filename + b"\x00")
    else:
        ql.dprint(D_INFO, "hModule %x" % hModule)
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
    # GetModuleHandle can return pe_image_address as handle, and GetModuleFileName will try to retrieve it.
    # Pretty much 0 and pe_image_address value should do the same operations
    if hModule == 0 or hModule == ql.loader.pe_image_address:
        filename = ql.loader.filepath.decode('ascii').encode('utf-16le')
        filename_len = len(filename)
        if filename_len > nSize - 1:
            filename = ql.loader.filepath[:nSize - 1]
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
    "lpProcName": POINTER
})
def hook_GetProcAddress(ql, address, params):
    if params["lpProcName"] > MAXUSHORT:
        # Look up by name
        params["lpProcName"] = ql.os.read_cstring(params["lpProcName"])
        lpProcName = bytes(params["lpProcName"], "ascii")
    else:
        # Look up by ordinal
        lpProcName = params["lpProcName"]
    # TODO fix for gandcrab
    if params["lpProcName"] == "RtlComputeCrc32":
        return 0

    # Check if dll is loaded
    try:
        dll_name = [key for key, value in ql.loader.dlls.items() if value == params['hModule']][0]
    except IndexError as ie:
        ql.nprint('[!] Failed to import function "%s" with handle 0x%X' % (lpProcName, params['hModule']))
        return 0

    # Handle case where module is self
    if dll_name == os.path.basename(ql.loader.path):
        for addr, export in ql.loader.export_symbols.items():
            if export['name'] == lpProcName:
                return addr

    if lpProcName in ql.loader.import_address_table[dll_name]:
        return ql.loader.import_address_table[dll_name][lpProcName]

    return 0


# HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
# );
@winapi(cc=STDCALL, params={
    "lpLibFileName": STRING
})
def hook_LoadLibraryA(ql, address, params):
    lpLibFileName = params["lpLibFileName"]
    if lpLibFileName == ql.loader.filepath.decode():
        # Loading self
        return ql.loader.pe_image_address
    dll_base = ql.loader.load_dll(lpLibFileName.encode())
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
    dll_base = ql.loader.load_dll(lpLibFileName.encode())
    return dll_base


# HMODULE LoadLibraryW(
#   LPCWSTR lpLibFileName
# );
@winapi(cc=STDCALL, params={
    "lpLibFileName": WSTRING
})
def hook_LoadLibraryW(ql, address, params):
    lpLibFileName = params["lpLibFileName"].encode()
    dll_base = ql.loader.load_dll(lpLibFileName)
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
    dll_base = ql.loader.load_dll(lpLibFileName)
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


# BOOL DisableThreadLibraryCalls(
#  HMODULE hLibModule
# );
@winapi(cc=STDCALL, params={
    "hLibModule": POINTER
})
def hook_DisableThreadLibraryCalls(ql, address, params):
    return 1


# BOOL FreeLibrary(
#   HMODULE hLibModule
# );
@winapi(cc=STDCALL, params={
    "hLibModule": POINTER
})
def hook_FreeLibrary(ql, address, params):
    return 1


# BOOL SetDefaultDllDirectories(
#   DWORD DirectoryFlags
# );
@winapi(cc=STDCALL, params={
    "DirectoryFlags": DWORD
})
def hook_SetDefaultDllDirectories(ql, address, params):
    value = params["DirectoryFlags"]
    if value == LOAD_LIBRARY_SEARCH_USER_DIRS:
        # TODO we have to probably set an handler for this, since it can be a not default value.
        #  And we have to change the default path of load
        raise QlErrorNotImplemented("[!] API not implemented")

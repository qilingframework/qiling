#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *

def _GetModuleHandle(ql: Qiling, address: int, params):
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
            ql.log.debug("Library %s not imported" % lpModuleName)
            ret = 0

    return ret

# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winsdkapi(cc=STDCALL, params={
    'lpModuleName' : LPCSTR
})
def hook_GetModuleHandleA(ql: Qiling, address: int, params):
    return _GetModuleHandle(ql, address, params)

# HMODULE GetModuleHandleW(
#   LPCWSTR lpModuleName
# );
@winsdkapi(cc=STDCALL, params={
    'lpModuleName' : LPCWSTR
})
def hook_GetModuleHandleW(ql: Qiling, address: int, params):
    return _GetModuleHandle(ql, address, params)

# BOOL GetModuleHandleExW(
#   DWORD   dwFlags,
#   LPCWSTR lpModuleName,
#   HMODULE *phModule
# );
@winsdkapi(cc=STDCALL, params={
    'dwFlags'      : DWORD,
    'lpModuleName' : LPCWSTR,
    'phModule'     : HMODULE
})
def hook_GetModuleHandleExW(ql: Qiling, address: int, params):
    res = _GetModuleHandle(ql, address, params)
    dst = params["phModule"]

    ql.mem.write(dst, ql.pack32(res))

    return 1

# DWORD GetModuleFileNameA(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpFilename' : LPSTR,
    'nSize'      : DWORD
})
def hook_GetModuleFileNameA(ql: Qiling, address: int, params):
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]
    ret = 0

    # GetModuleHandle can return pe_image_address as handle, and GetModuleFileName will try to retrieve it.
    # Pretty much 0 and pe_image_address value should do the same operations
    if not ql.code and (hModule == 0 or hModule == ql.loader.pe_image_address):
        filename = ql.loader.filepath
        filename_len = len(filename)

        if filename_len > nSize - 1:
            filename = ql.loader.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len

        ql.mem.write(lpFilename, filename + b"\x00")

    else:
        ql.log.debug("hModule %x" % hModule)
        raise QlErrorNotImplemented("API not implemented")

    return ret

# DWORD GetModuleFileNameW(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpFilename' : LPWSTR,
    'nSize'      : DWORD
})
def hook_GetModuleFileNameW(ql: Qiling, address: int, params):
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]
    ret = 0

    # GetModuleHandle can return pe_image_address as handle, and GetModuleFileName will try to retrieve it.
    # Pretty much 0 and pe_image_address value should do the same operations
    if not ql.code and (hModule == 0 or hModule == ql.loader.pe_image_address):
        filename = ql.loader.filepath.decode('ascii').encode('utf-16le')
        filename_len = len(filename)

        if filename_len > nSize - 1:
            filename = ql.loader.filepath[:nSize - 1]
            ret = nSize
        else:
            ret = filename_len

        ql.mem.write(lpFilename, filename + b"\x00")

    else:
        ql.log.debug("hModule %x" % hModule)
        raise QlErrorNotImplemented("API not implemented")

    return ret

# FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpProcName' : POINTER # LPCSTR
})
def hook_GetProcAddress(ql: Qiling, address: int, params):
    if params["lpProcName"] > MAXUSHORT:
        # Look up by name
        params["lpProcName"] = ql.os.utils.read_cstring(params["lpProcName"])
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
        ql.log.info('Failed to import function "%s" with handle 0x%X' % (lpProcName, params['hModule']))
        return 0

    # Handle case where module is self
    if dll_name == os.path.basename(ql.loader.path):
        for addr, export in ql.loader.export_symbols.items():
            if export['name'] == lpProcName:
                return addr

    if lpProcName in ql.loader.import_address_table[dll_name]:
        return ql.loader.import_address_table[dll_name][lpProcName]

    return 0

def _LoadLibrary(ql: Qiling, address: int, params):
    lpLibFileName = params["lpLibFileName"]

    if not ql.code and lpLibFileName == ql.loader.filepath.decode():
        # Loading self
        return ql.loader.pe_image_address

    return ql.loader.load_dll(lpLibFileName.encode())

def _LoadLibraryEx(ql: Qiling, address: int, params):
    lpLibFileName = params["lpLibFileName"]

    return ql.loader.load_dll(lpLibFileName.encode())

# HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCSTR
})
def hook_LoadLibraryA(ql: Qiling, address: int, params):
    return _LoadLibrary(ql, address, params)

# HMODULE LoadLibraryExA(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCSTR,
    'hFile'         : HANDLE,
    'dwFlags'       : DWORD
})
def hook_LoadLibraryExA(ql: Qiling, address: int, params):
    return _LoadLibraryEx(ql, address, params)

# HMODULE LoadLibraryW(
#   LPCWSTR lpLibFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCWSTR
})
def hook_LoadLibraryW(ql: Qiling, address: int, params):
    return _LoadLibrary(ql, address, params)

# HMODULE LoadLibraryExW(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCWSTR,
    'hFile'         : HANDLE,
    'dwFlags'       : DWORD
})
def hook_LoadLibraryExW(ql: Qiling, address: int, params):
    return _LoadLibraryEx(ql, address, params)

# DWORD SizeofResource(
#   HMODULE hModule,
#   HRSRC   hResInfo
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'  : HMODULE,
    'hResInfo' : HRSRC
})
def hook_SizeofResource(ql: Qiling, address: int, params):
    # Return size of resource
    # TODO set a valid value. More tests have to be made to find it.
    return 0x8

# HGLOBAL LoadResource(
#   HMODULE hModule,
#   HRSRC   hResInfo
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'  : HMODULE,
    'hResInfo' : HRSRC
})
def hook_LoadResource(ql: Qiling, address: int, params):
    pointer = params["hResInfo"]

    return pointer

# LPVOID LockResource(
#   HGLOBAL hResData
# );
@winsdkapi(cc=STDCALL, params={
    'hResData' : HGLOBAL
})
def hook_LockResource(ql: Qiling, address: int, params):
    pointer = params["hResData"]

    return pointer

# BOOL DisableThreadLibraryCalls(
#  HMODULE hLibModule
# );
@winsdkapi(cc=STDCALL, params={
    'hLibModule' : HMODULE
})
def hook_DisableThreadLibraryCalls(ql: Qiling, address: int, params):
    return 1

# BOOL FreeLibrary(
#   HMODULE hLibModule
# );
@winsdkapi(cc=STDCALL, params={
    'hLibModule' : HMODULE
})
def hook_FreeLibrary(ql: Qiling, address: int, params):
    return 1

# BOOL SetDefaultDllDirectories(
#   DWORD DirectoryFlags
# );
@winsdkapi(cc=STDCALL, params={
    'DirectoryFlags' : DWORD
})
def hook_SetDefaultDllDirectories(ql: Qiling, address: int, params):
    value = params["DirectoryFlags"]

    if value == LOAD_LIBRARY_SEARCH_USER_DIRS:
        # TODO we have to probably set an handler for this, since it can be a not default value.
        #  And we have to change the default path of load
        raise QlErrorNotImplemented("API not implemented")

    return 1

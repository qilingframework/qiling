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
from qiling.os.windows.utils import has_lib_ext

def _GetModuleHandle(ql: Qiling, address: int, params):
    lpModuleName = params["lpModuleName"]

    if lpModuleName == 0:
        ret = ql.loader.pe_image_address
    else:
        if not has_lib_ext(lpModuleName):
            lpModuleName = f'{lpModuleName}.dll'

        image = ql.loader.get_image_by_name(lpModuleName, casefold=True)

        if image:
            ret = image.base
        else:
            ql.log.debug(f'Library "{lpModuleName}" not imported')
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

    ql.mem.write_ptr(dst, res)

    return res

def __GetModuleFileName(ql: Qiling, address: int, params, *, wide: bool):
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]

    if not hModule:
        if ql.code:
            raise QlErrorNotImplemented('cannot retrieve module file name in shellcode mode')

        hModule = ql.loader.pe_image_address

    hpath = next((image.path for image in ql.loader.images if image.base == hModule), None)

    if hpath is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0

    encname = 'utf-16le' if wide else 'latin'
    vpath = ql.os.path.host_to_virtual_path(hpath)
    truncated = vpath[:nSize - 1] + '\x00'
    encoded = truncated.encode(encname)

    if len(vpath) + 1 > nSize:
        ql.os.last_error = ERROR_INSUFFICIENT_BUFFER

    ql.mem.write(lpFilename, encoded)

    return min(len(vpath), nSize)

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
    return __GetModuleFileName(ql, address, params, wide=False)

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
    return __GetModuleFileName(ql, address, params, wide=True)

# FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpProcName' : POINTER # LPCSTR
})
def hook_GetProcAddress(ql: Qiling, address: int, params):
    hModule = params['hModule']
    lpProcName = params['lpProcName']

    procname = None
    ordinal = None

    # if lpProcName is a short integer, it is an ordinal. otherwise, that is a function name.
    if lpProcName > MAXUSHORT:
        procname = ql.os.utils.read_cstring(lpProcName)

        # let log output reflect a human-readable procname
        params["lpProcName"] = procname

        procname = procname.encode('latin1')

    else:
        ordinal = lpProcName

    # get dll name by handle (module base)
    dll_name = next((os.path.basename(image.path).casefold() for image in ql.loader.images if image.base == hModule), None)

    if dll_name is None:
        ql.log.info(f'Failed to import function "{lpProcName}" with handle {hModule:#x}')
        return 0

    # Handle case where module is self
    if dll_name == os.path.basename(ql.loader.path).casefold():
        if procname is not None:
            search_func = lambda entry: entry['name'] == procname

        elif ordinal is not None:
            search_func = lambda entry: entry['ord'] == ordinal

        else:
            raise AssertionError

        return next((addr for addr, entry in ql.loader.export_symbols.items() if search_func(entry)), 0)

    # in any other case, look through the import address table for that dll
    iat = ql.loader.import_address_table[dll_name]

    return iat.get(procname or ordinal, 0)

def _LoadLibrary(ql: Qiling, address: int, params):
    lpLibFileName = params["lpLibFileName"]

    # TODO: this searches only by basename; do we need to search by full path as well?
    dll = ql.loader.get_image_by_name(lpLibFileName, casefold=True)

    if dll is not None:
        return dll.base

    return ql.loader.load_dll(lpLibFileName)

def _LoadLibraryEx(ql: Qiling, address: int, params):
    lpLibFileName = params["lpLibFileName"]

    return ql.loader.load_dll(lpLibFileName)

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

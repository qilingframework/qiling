#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ntpath
import os

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

from qiling.os.windows.handle import Handle
from qiling.os.windows.thread import QlWindowsThread, THREAD_STATUS
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.structs import make_shellex_info

def _SHGetFileInfo(ql: Qiling, address: int, params) -> int:
    uFlags = params["uFlags"]

    if uFlags == SHGFI_LARGEICON:
        # TODO: is this a valid DWORD_PTR ?
        return 1

    ql.log.debug(uFlags)
    raise QlErrorNotImplemented("API not implemented")

# DWORD_PTR SHGetFileInfoA(
#   LPCSTR     pszPath,
#   DWORD       dwFileAttributes,
#   SHFILEINFOW *psfi,
#   UINT        cbFileInfo,
#   UINT        uFlags
# );
@winsdkapi(cc=STDCALL, params={
    'pszPath'          : LPCSTR,
    'dwFileAttributes' : DWORD,
    'psfi'             : POINTER,
    'cbFileInfo'       : UINT,
    'uFlags'           : UINT
})
def hook_SHGetFileInfoA(ql: Qiling, address: int, params):
    return _SHGetFileInfo(ql, address, params)

# DWORD_PTR SHGetFileInfoW(
#   LPCWSTR     pszPath,
#   DWORD       dwFileAttributes,
#   SHFILEINFOW *psfi,
#   UINT        cbFileInfo,
#   UINT        uFlags
# );
@winsdkapi(cc=STDCALL, params={
    'pszPath'          : LPCWSTR,
    'dwFileAttributes' : DWORD,
    'psfi'             : POINTER,
    'cbFileInfo'       : UINT,
    'uFlags'           : UINT
})
def hook_SHGetFileInfoW(ql: Qiling, address: int, params):
    return _SHGetFileInfo(ql, address, params)

def _ShellExecute(ql: Qiling, shellex_obj, *, wide: bool):
    read_str = ql.os.utils.read_wstring if wide else ql.os.utils.read_cstring

    def __read_str(ptr: int):
        return read_str(ptr) if ptr else ''

    ql.log.debug(f'Target executed a shell command!')
    ql.log.debug(f' | Operation  : "{__read_str(shellex_obj.lpVerb)}"')
    ql.log.debug(f' | File       : "{__read_str(shellex_obj.lpFile)}"')
    ql.log.debug(f' | Parameters : "{__read_str(shellex_obj.lpParameters)}"')
    ql.log.debug(f' | Directory  : "{__read_str(shellex_obj.lpDirectory)}"')

    if shellex_obj.nShow == SW_HIDE:
        ql.log.debug(' | With an hidden window')

    process = QlWindowsThread(ql, status=THREAD_STATUS.READY)
    handle = Handle(obj=process)
    ql.os.handle_manager.append(handle)

    return handle

# BOOL ShellExecuteExW(
#   SHELLEXECUTEINFOA *pExecInfo
# );
@winsdkapi(cc=STDCALL, params={
    'pExecInfo' : POINTER
})
def hook_ShellExecuteExW(ql: Qiling, address: int, params):
    pExecInfo = params['pExecInfo']

    shellex_struct = make_shellex_info(ql.arch.bits)

    with shellex_struct.ref(ql.mem, pExecInfo) as shellex_obj:
        handle = _ShellExecute(ql, shellex_obj, wide=True)

        # Write results
        shellex_obj.hInstApp = 33
        shellex_obj.hProcess = handle.id

    return 1

# HINSTANCE ShellExecuteW(
#   HWND    hwnd,
#   LPCWSTR lpOperation,
#   LPCWSTR lpFile,
#   LPCWSTR lpParameters,
#   LPCWSTR lpDirectory,
#   INT     nShowCmd
# );
@winsdkapi(cc=STDCALL, params={
    'hwnd'         : HWND,
    'lpOperation'  : POINTER, # LPCWSTR
    'lpFile'       : POINTER, # LPCWSTR
    'lpParameters' : POINTER, # LPCWSTR
    'lpDirectory'  : POINTER, # LPCWSTR
    'nShowCmd'     : INT
})
def hook_ShellExecuteW(ql: Qiling, address: int, params):
    shellex_struct = make_shellex_info(ql.arch.bits)

    shellex_obj = shellex_struct(
        hwnd         = params['hwnd'],
        lpVerb       = params['lpOperation'],
        lpFile       = params['lpFile'],
        lpParameters = params['lpParameters'],
        lpDirectory  = params['lpDirectory'],
        nShow        = params['nShowCmd']
    )

    _ShellExecute(ql, shellex_obj, wide=True)

    return 33

# BOOL SHGetSpecialFolderPathW(
#   HWND   hwnd,
#   LPWSTR pszPath,
#   int    csidl,
#   BOOL   fCreate
# );
@winsdkapi(cc=STDCALL, params={
    'hwnd'    : HWND,
    'pszPath' : LPWSTR,
    'csidl'   : INT,
    'fCreate' : BOOL
})
def hook_SHGetSpecialFolderPathW(ql: Qiling, address: int, params):
    directory_id = params["csidl"]
    dst = params["pszPath"]

    if directory_id == CSIDL_COMMON_APPDATA:
        path = ntpath.join(ql.os.userprofile, "AppData\\")
        # We always create the directory
        appdata_dir = path.split("C:\\")[1].replace("\\", "/")
        ql.log.debug("dir path: %s" % path)

        path_emulated = os.path.join(ql.rootfs, appdata_dir)
        ql.log.debug("emulated path: %s" % path_emulated)

        ql.mem.write(dst, (path + "\x00").encode("utf-16le"))

        # FIXME: Somehow winodws path is wrong
        if not os.path.exists(path_emulated):
            try:
                os.makedirs(path_emulated, 0o755)
            except OSError:
                ql.log.debug("os.makedirs failed")
            else:
                ql.log.debug("os.makedirs completed")
    else:
        raise QlErrorNotImplemented("API not implemented")

    return 1

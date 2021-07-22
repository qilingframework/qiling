#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from typing import Sequence

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

from qiling.os.windows.handle import Handle
from qiling.os.windows.thread import QlWindowsThread
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.structs import ShellExecuteInfoA

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

def _ShellExecute(ql: Qiling, obj: ShellExecuteInfoA):
    def __wstr(shellex: Sequence):
        return ql.os.utils.read_wstring(shellex[0]) if shellex[0] else ''

    ql.log.debug(f'Target executed a shell command!')
    ql.log.debug(f' | Operation  : "{__wstr(obj.verb)}"')
    ql.log.debug(f' | Parameters : "{__wstr(obj.params)}"')
    ql.log.debug(f' | File       : "{__wstr(obj.file)}"')
    ql.log.debug(f' | Directory  : "{__wstr(obj.dir)}"')

    if obj.show[0] == SW_HIDE:
        ql.log.debug(" | With an hidden window")

    process = QlWindowsThread(ql, status=0, isFake=True)
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
    pointer = params["pExecInfo"]

    shellInfo = ShellExecuteInfoA(ql)
    shellInfo.read(pointer)

    handle = _ShellExecute(ql, shellInfo)

    # Write results
    shellInfo.instApp[0] = 0x21
    shellInfo.process[0] = handle.id
    shellInfo.write(pointer)

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
    _ShellExecute(ql, ShellExecuteInfoA(
        ql,
        hwnd=params["hwnd"],
        lpVerb=params["lpOperation"],
        lpFile=params["lpFile"],
        lpParams=params["lpParameters"],
        lpDir=params["lpDirectory"],
        show=params["nShowCmd"]
    ))

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
        path = str(ql.os.userprofile + "AppData\\")
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
                ql.log.debug("os.makedirs completed")
            except OSError:
                ql.log.debug("os.makedirs failed")
    else:
        raise QlErrorNotImplemented("API not implemented")

    return 1

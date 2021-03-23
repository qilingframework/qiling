#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct, time, os


from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.structs import *
from qiling.const import *

dllname = 'shell32_dll'

# DWORD_PTR SHGetFileInfoA(
#   LPCSTR     pszPath,
#   DWORD       dwFileAttributes,
#   SHFILEINFOW *psfi,
#   UINT        cbFileInfo,
#   UINT        uFlags
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SHGetFileInfoA(ql, address, params):
    return hook_SHGetFileInfoW.__wrapped__(ql, address, params)


# DWORD_PTR SHGetFileInfoW(
#   LPCWSTR     pszPath,
#   DWORD       dwFileAttributes,
#   SHFILEINFOW *psfi,
#   UINT        cbFileInfo,
#   UINT        uFlags
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SHGetFileInfoW(ql, address, params):
    flags = params["uFlags"]
    if flags == SHGFI_LARGEICON:
        return 1
    else:
        ql.log.debug(flags)
        raise QlErrorNotImplemented("API not implemented")


def _ShellExecute(ql, obj: ShellExecuteInfoA):

    operation = ql.os.utils.read_wstring(obj.verb[0]) if obj.verb[0] != 0 else ""
    params = ql.os.utils.read_wstring(obj.params[0]) if obj.params[0] != 0 else ""
    file = ql.os.utils.read_wstring(obj.file[0]) if obj.file[0] != 0 else ""
    directory = ql.os.utils.read_wstring(obj.dir[0]) if obj.dir[0] != 0 else ""

    ql.log.debug("Target executed a shell command!")
    ql.log.debug("Operation: %s " % operation)
    ql.log.debug("Parameters: %s " % params)
    ql.log.debug("File: %s " % file)
    ql.log.debug("Directory: %s " % directory)
    if obj.show[0] == SW_HIDE:
        ql.log.debug("With an hidden window")
    process = QlWindowsThread(ql, status=0, isFake=True)
    handle = Handle(obj=process)
    ql.os.handle_manager.append(handle)
    return handle


# BOOL ShellExecuteExW(
#   SHELLEXECUTEINFOA *pExecInfo
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_ShellExecuteExW(ql, address, params):
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCWSTR': 'POINTER'})
def hook_ShellExecuteW(ql, address, params):
    shellInfo = ShellExecuteInfoA(ql, hwnd=params["hwnd"], lpVerb=params["lpOperation"], lpFile=params["lpFile"],
                                  lpParams=params["lpParameters"], lpDir=params["lpDirectory"], show=params["nShowCmd"])
    _ = _ShellExecute(ql, shellInfo)
    return 33


# BOOL SHGetSpecialFolderPathW(
#   HWND   hwnd,
#   LPWSTR pszPath,
#   int    csidl,
#   BOOL   fCreate
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SHGetSpecialFolderPathW(ql, address, params):
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
                ql.log.debug("os.makedirs fail")
    else:
        raise QlErrorNotImplemented("API not implemented")
    return 1

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

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


# DWORD_PTR SHGetFileInfoA(
#   LPCSTR     pszPath,
#   DWORD       dwFileAttributes,
#   SHFILEINFOW *psfi,
#   UINT        cbFileInfo,
#   UINT        uFlags
# );
@winapi(cc=STDCALL, params={
    "pszPath": STRING,
    "dwFileAttributes": DWORD,
    "psfi": POINTER,
    "cbFileInfo": UINT,
    "uFlags": UINT
})
def hook_SHGetFileInfoA(ql, address, params):
    return hook_SHGetFileInfoW.__wrapped__(ql, address, params)


# DWORD_PTR SHGetFileInfoW(
#   LPCWSTR     pszPath,
#   DWORD       dwFileAttributes,
#   SHFILEINFOW *psfi,
#   UINT        cbFileInfo,
#   UINT        uFlags
# );
@winapi(cc=STDCALL, params={
    "pszPath": WSTRING,
    "dwFileAttributes": DWORD,
    "psfi": POINTER,
    "cbFileInfo": UINT,
    "uFlags": UINT
})
def hook_SHGetFileInfoW(ql, address, params):
    flags = params["uFlags"]
    if flags == SHGFI_LARGEICON:
        return 1
    else:
        ql.dprint(D_INFO, flags)
        raise QlErrorNotImplemented("[!] API not implemented")


def _ShellExecute(ql, obj: ShellExecuteInfoA):

    operation = ql.os.read_wstring(obj.verb[0]) if obj.verb[0] != 0 else ""
    params = ql.os.read_wstring(obj.params[0]) if obj.params[0] != 0 else ""
    file = ql.os.read_wstring(obj.file[0]) if obj.file[0] != 0 else ""
    directory = ql.os.read_wstring(obj.dir[0]) if obj.dir[0] != 0 else ""

    ql.dprint(D_RPRT, "[=] Target executed a shell command!")
    ql.dprint(D_RPRT, "[-] Operation: %s " % operation)
    ql.dprint(D_RPRT, "[-] Parameters: %s " % params)
    ql.dprint(D_RPRT, "[-] File: %s " % file)
    ql.dprint(D_RPRT, "[-] Directory: %s " % directory)
    if obj.show[0] == SW_HIDE:
        ql.dprint(D_RPRT, "[=] With an hidden window")
    process = QlWindowsThread(ql, status=0, isFake=True)
    handle = Handle(obj=process)
    ql.os.handle_manager.append(handle)
    return handle


# BOOL ShellExecuteExW(
#   SHELLEXECUTEINFOA *pExecInfo
# );
@winapi(cc=STDCALL, params={
    "pExecInfo": POINTER
})
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
@winapi(cc=STDCALL, params={
    "hwnd": HANDLE,
    "lpVerb": POINTER,
    "lpFile": POINTER,
    "lpParameters": POINTER,
    "lpDirectory": POINTER,
    "nShow": INT
})
def hook_ShellExecuteW(ql, address, params):
    shellInfo = ShellExecuteInfoA(ql, hwnd=params["hwnd"], lpVerb=params["lpVerb"], lpFile=params["lpFile"],
                                  lpParams=params["lpParameters"], lpDir=params["lpDirectory"], show=params["nShow"])
    _ = _ShellExecute(ql, shellInfo)
    return 33


# BOOL SHGetSpecialFolderPathW(
#   HWND   hwnd,
#   LPWSTR pszPath,
#   int    csidl,
#   BOOL   fCreate
# );
@winapi(cc=STDCALL, params={
    "hwnd": HANDLE,
    "pszPath": POINTER,
    "csidl": INT,
    "fCreate": BOOL
})
def hook_SHGetSpecialFolderPathW(ql, address, params):
    directory_id = params["csidl"]
    dst = params["pszPath"]
    if directory_id == CSIDL_COMMON_APPDATA:
        path = str(ql.os.userprofile + "AppData\\")
        # We always create the directory
        appdata_dir = path.split("C:\\")[1].replace("\\", "/")
        ql.dprint(D_INFO, "[+] dir path: %s" % path)
        path_emulated = os.path.join(ql.rootfs, appdata_dir)
        ql.dprint(D_INFO, "[!] emulated path: %s" % path_emulated)
        ql.mem.write(dst, (path + "\x00").encode("utf-16le"))
        # FIXME: Somehow winodws path is wrong
        if not os.path.exists(path_emulated):
            try:
                os.makedirs(path_emulated, 0o755)
                ql.dprint(D_INFO, "[!] os.makedirs completed")
            except OSError:
                ql.dprint(D_INFO, "[!] os.makedirs fail")
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1

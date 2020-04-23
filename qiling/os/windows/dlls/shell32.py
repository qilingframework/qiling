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
from qiling.const import *

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


def _ShellExecute(ql, dic: dict):
    handle_window = int.from_bytes(dic["hwnd"], byteorder="little") if not isinstance(dic["hwnd"], int) else dic["hwnd"]
    pt_operation = int.from_bytes(dic["lpVerb"], byteorder="little") if not isinstance(dic["lpVerb"], int) \
        else dic["lpVerb"]
    pt_file = int.from_bytes(dic["lpFile"], byteorder="little") if not isinstance(dic["lpFile"], int) else dic["lpFile"]
    pt_params = int.from_bytes(dic["lpParameters"], byteorder="little") if not isinstance(dic["lpParameters"], int) \
        else dic["lpParameters"]
    pt_directory = int.from_bytes(dic["lpDirectory"], byteorder="little") if not isinstance(dic["lpDirectory"], int) \
        else dic["lpDirectory"]

    operation = read_wstring(ql, pt_operation) if pt_operation != 0 else ""
    params = read_wstring(ql, pt_params) if pt_params != 0 else ""
    file = read_wstring(ql, pt_file) if pt_file != 0 else ""
    directory = read_wstring(ql, pt_file) if pt_directory != 0 else ""
    show = int.from_bytes(dic["nShow"], byteorder="little") if not isinstance(dic["nShow"], int) else dic["nShow"]

    ql.dprint(D_RPRT, "[=] Sample executed a shell command!")
    ql.dprint(D_RPRT, "[-] Operation: %s " % operation)
    ql.dprint(D_RPRT, "[-] Parameters: %s " % params)
    ql.dprint(D_RPRT, "[-] File: %s " % file)
    ql.dprint(D_RPRT, "[-] Directory: %s " % directory)
    if show == SW_HIDE:
        ql.dprint(D_RPRT, "[=] Sample is creating a hidden window!")
    if operation == "runas":
        ql.dprint(D_RPRT, "[=] Sample is executing shell command as administrator!")
    process = QlWindowsThread(ql, status=0, isFake=True)
    handle = Handle(obj=process)
    ql.os.handle_manager.append(handle)
    return handle


# typedef struct _SHELLEXECUTEINFOA {
#   DWORD     cbSize;
#   ULONG     fMask;
#   HWND      hwnd;
#   LPCSTR    lpVerb;
#   LPCSTR    lpFile;
#   LPCSTR    lpParameters;
#   LPCSTR    lpDirectory;
#   int       nShow;
#   HINSTANCE hInstApp;
#   void      *lpIDList;
#   LPCSTR    lpClass;
#   HKEY      hkeyClass;
#   DWORD     dwHotKey;
#   union {
#     HANDLE hIcon;
#     HANDLE hMonitor;
#   } DUMMYUNIONNAME;
#   HANDLE    hProcess;
# } SHELLEXECUTEINFOA, *LPSHELLEXECUTEINFOA;


# BOOL ShellExecuteExW(
#   SHELLEXECUTEINFOA *pExecInfo
# );
@winapi(cc=STDCALL, params={
    "pExecInfo": POINTER
})
def hook_ShellExecuteExW(ql, address, params):
    pointer = params["pExecInfo"]

    shell_execute_info = {"cbSize": ql.mem.read(pointer, 4),
                          "fMask": ql.mem.read(pointer + 4, 4),
                          "hwnd": ql.mem.read(pointer + 8, ql.pointersize),
                          "lpVerb": ql.mem.read(pointer + 8 + ql.pointersize, ql.pointersize),
                          "lpFile": ql.mem.read(pointer + 8 + ql.pointersize * 2, ql.pointersize),
                          "lpParameters": ql.mem.read(pointer + 8 + ql.pointersize * 3, ql.pointersize),
                          "lpDirectory": ql.mem.read(pointer + 8 + ql.pointersize * 4, ql.pointersize),
                          "nShow": ql.mem.read(pointer + 8 + ql.pointersize * 5, 4),
                          "hInstApp": ql.mem.read(pointer + 12 + ql.pointersize * 5, 4),  # Must be > 32 for success
                          "lpIDList": ql.mem.read(pointer + 16 + ql.pointersize * 5, ql.pointersize),
                          "lpClass": ql.mem.read(pointer + 16 + ql.pointersize * 6, ql.pointersize),
                          "hkeyClass": ql.mem.read(pointer + 16 + ql.pointersize * 7, ql.pointersize),
                          "dwHotKey": ql.mem.read(pointer + 16 + ql.pointersize * 8, 4),
                          "dummy": ql.mem.read(pointer + 20 + ql.pointersize * 8, ql.pointersize),
                          "hprocess": ql.mem.read(pointer + 20 + ql.pointersize * 9, ql.pointersize),
                          }

    handle = _ShellExecute(ql, shell_execute_info)

    # Write results
    shell_execute_info["hInstApp"] = 0x21.to_bytes(4, byteorder="little")
    shell_execute_info["hprocess"] = ql.pack(handle.id)
    # Check everything is correct
    values = b"".join(shell_execute_info.values())
    assert len(values) == shell_execute_info["cbSize"][0]

    # Rewrite memory
    ql.mem.write(pointer, values)
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
    _ = _ShellExecute(ql, params)
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
        path = str(ql.os.profile["PATH"]["appdata"])
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
            except:
                ql.dprint(D_INFO, "[!] os.makedirs fail")    
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1

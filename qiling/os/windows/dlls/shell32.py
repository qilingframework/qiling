#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.fncc import *
from qiling.os.utils import *
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
def hook_SHGetFileInfoW(self, address, params):
    flags = params["uFlags"]
    if flags == SHGFI_LARGEICON:
        return 1
    else:
        self.dprint(D_INFO, flags)
        raise QlErrorNotImplemented("[!] API not implemented")


def _ShellExecute(self, dic: dict):
    handle_window = int.from_bytes(dic["hwnd"], byteorder="little") if not isinstance(dic["hwnd"], int) else dic["hwnd"]
    pt_operation = int.from_bytes(dic["lpVerb"], byteorder="little") if not isinstance(dic["lpVerb"], int) \
        else dic["lpVerb"]
    pt_file = int.from_bytes(dic["lpFile"], byteorder="little") if not isinstance(dic["lpFile"], int) else dic["lpFile"]
    pt_params = int.from_bytes(dic["lpParameters"], byteorder="little") if not isinstance(dic["lpParameters"], int) \
        else dic["lpParameters"]
    pt_directory = int.from_bytes(dic["lpDirectory"], byteorder="little") if not isinstance(dic["lpDirectory"], int) \
        else dic["lpDirectory"]

    operation = read_wstring(self.ql, pt_operation) if pt_operation != 0 else ""
    params = read_wstring(self.ql, pt_params) if pt_params != 0 else ""
    file = read_wstring(self.ql, pt_file) if pt_file != 0 else ""
    directory = read_wstring(self.ql, pt_file) if pt_directory != 0 else ""
    show = int.from_bytes(dic["nShow"], byteorder="little") if not isinstance(dic["nShow"], int) else dic["nShow"]

    self.ql.dprint(D_RPRT, "[=] Sample executed a shell command!")
    self.ql.dprint(D_RPRT, "[-] Operation: %s " % operation)
    self.ql.dprint(D_RPRT, "[-] Parameters: %s " % params)
    self.ql.dprint(D_RPRT, "[-] File: %s " % file)
    self.ql.dprint(D_RPRT, "[-] Directory: %s " % directory)
    if show == SW_HIDE:
        self.ql.dprint(D_RPRT, "[=] Sample is creating a hidden window!")
    if operation == "runas":
        self.ql.dprint(D_RPRT, "[=] Sample is executing shell command as administrator!")
    process = QlWindowsThread(self, status=0, isFake=True)
    handle = Handle(thread=process)
    self.handle_manager.append(handle)
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
def hook_ShellExecuteExW(self, address, params):
    pointer = params["pExecInfo"]

    shell_execute_info = {"cbSize": self.mem.read(pointer, 4),
                          "fMask": self.mem.read(pointer + 4, 4),
                          "hwnd": self.mem.read(pointer + 8, self.pointersize),
                          "lpVerb": self.mem.read(pointer + 8 + self.pointersize, self.pointersize),
                          "lpFile": self.mem.read(pointer + 8 + self.pointersize * 2, self.pointersize),
                          "lpParameters": self.mem.read(pointer + 8 + self.pointersize * 3, self.pointersize),
                          "lpDirectory": self.mem.read(pointer + 8 + self.pointersize * 4, self.pointersize),
                          "nShow": self.mem.read(pointer + 8 + self.pointersize * 5, 4),
                          "hInstApp": self.mem.read(pointer + 12 + self.pointersize * 5, 4),  # Must be > 32 for success
                          "lpIDList": self.mem.read(pointer + 16 + self.pointersize * 5, self.pointersize),
                          "lpClass": self.mem.read(pointer + 16 + self.pointersize * 6, self.pointersize),
                          "hkeyClass": self.mem.read(pointer + 16 + self.pointersize * 7, self.pointersize),
                          "dwHotKey": self.mem.read(pointer + 16 + self.pointersize * 8, 4),
                          "dummy": self.mem.read(pointer + 20 + self.pointersize * 8, self.pointersize),
                          "hprocess": self.mem.read(pointer + 20 + self.pointersize * 9, self.pointersize),
                          }

    handle = _ShellExecute(self, shell_execute_info)

    # Write results
    shell_execute_info["hInstApp"] = 0x21.to_bytes(4, byteorder="little")
    shell_execute_info["hprocess"] = self.pack(handle.id)
    # Check everything is correct
    values = b"".join(shell_execute_info.values())
    assert len(values) == shell_execute_info["cbSize"][0]

    # Rewrite memory
    self.mem.write(pointer, values)
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
def hook_ShellExecuteW(self, address, params):
    _ = _ShellExecute(self, params)
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
def hook_SHGetSpecialFolderPathW(self, address, params):
    directory_id = params["csidl"]
    dst = params["pszPath"]
    if directory_id == CSIDL_COMMON_APPDATA:
        path = self.profile["PATHS"]["appdata"]
        # We always create the directory
        appdata_dir = path.split("C:\\")[1].replace("\\", "/")
        self.ql.dprint(D_INFO, "[+] dir path: %s" % path)
        path_emulated = os.path.join(self.ql.rootfs, appdata_dir)
        self.ql.dprint(D_INFO, "[!] emulated path: %s" % path_emulated)
        self.ql.mem.write(dst, (path + "\x00").encode("utf-16le"))
        # FIXME: Somehow winodws path is wrong
        if not os.path.exists(path_emulated):
            try:
                os.makedirs(path_emulated, 0o755)
                self.ql.dprint(D_INFO, "[!] os.makedirs completed")
            except:
                self.ql.dprint(D_INFO, "[!] os.makedirs fail")    
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1

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
        ql.dprint(flags)
        raise QlErrorNotImplemented("[!] API not implemented")


# BOOL ShellExecuteExW(
#   SHELLEXECUTEINFOA *pExecInfo
# );
@winapi(cc=STDCALL, params={
    "pExecInfo": POINTER
})
def hook_ShellExecuteExW(ql, address, params):
    pointer = params["pExecInfo"]

    shell_execute_info = {"cbSize": ql.uc.mem_read(pointer, 4),
                          "fMask": ql.uc.mem_read(pointer + 4, 4),
                          "hwnd": ql.uc.mem_read(pointer + 8, ql.pointersize),
                          "lpVerb": ql.uc.mem_read(pointer + 8 + ql.pointersize, ql.pointersize),
                          "lpFile": ql.uc.mem_read(pointer + 8 + ql.pointersize * 2, ql.pointersize),
                          "lpParameters": ql.uc.mem_read(pointer + 8 + ql.pointersize * 3, ql.pointersize),
                          "lpDirectory": ql.uc.mem_read(pointer + 8 + ql.pointersize * 4, ql.pointersize),
                          "nShow": ql.uc.mem_read(pointer + 8 + ql.pointersize * 5, 4),
                          "hInstApp": ql.uc.mem_read(pointer + 12 + ql.pointersize * 5, 4),  # Must be 0x20 for success
                          "lpIDList": ql.uc.mem_read(pointer + 16 + ql.pointersize * 5, ql.pointersize),
                          "lpClass": ql.uc.mem_read(pointer + 16 + ql.pointersize * 6, ql.pointersize),
                          "hkeyClass": ql.uc.mem_read(pointer + 16 + ql.pointersize * 7, ql.pointersize),
                          "dwHotKey": ql.uc.mem_read(pointer + 16 + ql.pointersize * 8, 4),
                          "dummy": ql.uc.mem_read(pointer + 20 + ql.pointersize * 8, ql.pointersize),
                          "hprocess": ql.uc.mem_read(pointer + 20 + ql.pointersize * 9, ql.pointersize),
                          }

    # Some useful values in this struct
    handle_window = int.from_bytes(shell_execute_info["hwnd"], byteorder="little")
    pt_operation = int.from_bytes(shell_execute_info["lpVerb"], byteorder="little")
    pt_file = int.from_bytes(shell_execute_info["lpFile"], byteorder="little")
    pt_params = int.from_bytes(shell_execute_info["lpParameters"], byteorder="little")
    pt_directory = int.from_bytes(shell_execute_info["lpDirectory"], byteorder="little")

    handle_key = int.from_bytes(shell_execute_info["hkeyClass"], byteorder="little")
    operation = read_wstring(ql, pt_operation) if pt_operation != 0 else ""
    params = read_wstring(ql, pt_params) if pt_params != 0 else ""
    file = read_wstring(ql, pt_file) if pt_file != 0 else ""
    directory = read_wstring(ql, pt_file) if pt_directory != 0 else ""
    show = int.from_bytes(shell_execute_info["nShow"], byteorder="little")
    ql.dprint("[!] Binary is executing a shell command!")
    ql.dprint("[-] Operation: %s " % operation)
    ql.dprint("[-] Parameters: %s " % params)
    ql.dprint("[-] File: %s " % file)
    ql.dprint("[-] Directory: %s " % directory)
    ql.dprint("[-] Show: %s " % show)
    if show == SW_HIDE:
        ql.dprint("[!] Binary is creating a hidden window!")

    # TODO create new process
    process_handle = 0x123456
    # Set values
    shell_execute_info["hInstApp"] = 0x20.to_bytes(4, byteorder="little")
    shell_execute_info["hprocess"] = process_handle.to_bytes(ql.pointersize, byteorder="little")
    # Check everything is correct
    values = b"".join(shell_execute_info.values())
    assert len(values) == shell_execute_info["cbSize"][0]

    # Rewrite memory
    ql.uc.mem_write(pointer, values)
    return 1

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

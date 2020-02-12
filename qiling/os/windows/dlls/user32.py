#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *


# INT_PTR DialogBoxParamA(
#   HINSTANCE hInstance,
#   LPCSTR    lpTemplateName,
#   HWND      hWndParent,
#   DLGPROC   lpDialogFunc,
#   LPARAM    dwInitParam
# );
@winapi(cc=STDCALL, params={
    "hInstance": HANDLE,
    "lpTemplateName": POINTER,
    "hWndParent": HANDLE,
    "lpDialogFunc": POINTER,
    "dwInitParam": POINTER
})
def hook_DialogBoxParamA(ql, address, params):
    ret = 0
    return ret


# UINT GetDlgItemTextA(
# 	HWND  hDlg,
# 	int   nIDDlgItem,
# 	LPSTR lpString,
# 	int   cchMax
# );
@winapi(cc=STDCALL, params={
    "hDlg": HANDLE,
    "nIDDlgItem": INT,
    "lpString": POINTER,
    "cchMax": INT
})
def hook_GetDlgItemTextA(ql, address, params):
    ret = 0
    hDlg = params["hDlg"]
    nIDDlgItem = params["nIDDlgItem"]
    lpString = params["lpString"]
    cchMax = params["cchMax"]

    ql.stdout.write(b"Input DlgItemText :\n")
    string = ql.stdin.readline().strip()[:cchMax]
    ret = len(string)
    ql.uc.mem_write(lpString, string)

    return ret


# int MessageBoxA(
#     HWND   hWnd,
#     LPCSTR lpText,
#     LPCSTR lpCaption,
#     UINT   uType
#     );
@winapi(cc=STDCALL, params={
    "hWnd": HANDLE,
    "lpText": STRING,
    "lpCaption": STRING,
    "uType": UINT
})
def hook_MessageBoxA(ql, address, params):
    ret = 2
    return ret


# BOOL EndDialog(
#   HWND    hDlg,
#   INT_PTR nResult
# );
@winapi(cc=STDCALL, params={
    "hDlg": HANDLE,
    "nResult": POINTER
})
def hook_EndDialog(ql, address, params):
    ret = 1
    return ret


# HWND GetDesktopWindow((
# );
@winapi(cc=STDCALL, params={})
def hook_GetDesktopWindow(ql, address, params):
    pass

#BOOL OpenClipboard(
#  HWND hWndNewOwner
#);
@winapi(cc=STDCALL, params={
    "hWndNewOwner": HANDLE
})
def hook_OpenClipboard(ql, address, params):
    return ql.clipboard.open(params['hWndNewOwner'])

#BOOL CloseClipboard();
@winapi(cc=STDCALL, params={})
def hook_CloseClipboard(ql, address, params):
    return ql.clipboard.close()

#HANDLE SetClipboardData(
#  UINT   uFormat,
#  HANDLE hMem
#);
@winapi(cc=STDCALL, params={
    "uFormat": UINT,
    "hMem": STRING
})
def hook_SetClipboardData(ql, address, params):
    try:
        data = bytes(params['hMem'], 'ascii')
    except:
        data = b""
    return ql.clipboard.set_data(params['uFormat'], data)

#HANDLE GetClipboardData(
#  UINT uFormat
#);
@winapi(cc=STDCALL, params={
    "uFormat": UINT
})
def hook_GetClipboardData(ql, address, params):
    data = ql.clipboard.get_data(params['uFormat'])
    if data:
        addr = ql.heap.mem_alloc(len(data))
        ql.uc.mem_write(addr, data)
        return addr
    else:
        ql.dprint('Failed to get clipboard data')
        return 0

#BOOL IsClipboardFormatAvailable(
#  UINT format
#);
@winapi(cc=STDCALL, params={
    "uFormat": UINT
})
def hook_IsClipboardFormatAvailable(ql, address, params):
    rtn = ql.clipboard.format_available(params['uFormat'])
    return rtn

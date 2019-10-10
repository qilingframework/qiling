#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *


# INT_PTR DialogBoxParamA(
#   HINSTANCE hInstance,
#   LPCSTR    lpTemplateName,
#   HWND      hWndParent,
#   DLGPROC   lpDialogFunc,
#   LPARAM    dwInitParam
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_DialogBoxParamA(ql, address):
    ret = 0
    hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = ql.get_params(5)
    ql.nprint('0x%0.2x: DialogBoxParamA(0x%0.2x, 0x%0.2x, 0x%0.2x, 0x%0.2x, 0x%0.2x) = %d' %
         (address, hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam, ret))
    return ret


# UINT GetDlgItemTextA(
# 	HWND  hDlg,
# 	int   nIDDlgItem,
# 	LPSTR lpString,
# 	int   cchMax
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=4)
def hook_GetDlgItemTextA(ql, address):
    ret = 0
    hDlg, nIDDlgItem, lpString, cchMax = ql.get_params(4)
    ql.stdout.write(b"Input DlgItemText :\n")
    string = ql.stdin.readline().strip()[:cchMax]
    ret = len(string)
    ql.uc.mem_write(lpString, string)
    ql.nprint('0x%0.2x: GetDlgItemTextA(0x%0.2x, 0x%0.2x, 0x%0.2x, 0x%0.2x) = %d' %
        (address, hDlg, nIDDlgItem, lpString, cchMax, ret))
    return ret


# int MessageBoxA(
#     HWND   hWnd,
#     LPCSTR lpText,
#     LPCSTR lpCaption,
#     UINT   uType
#     );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=4)
def hook_MessageBoxA(ql, address):
    ret = 2
    hWnd, lpText, lpCaption, uType = ql.get_params(4)
    s_lpText = read_cstring(ql, lpText)
    s_lpCaption = read_cstring(ql, lpCaption)
    ql.nprint('0x%0.2x: MessageBoxA(0x%0.2x, "%s", "%s", 0x%0.2x) = %d' %
         (address, hWnd, s_lpText, s_lpCaption, uType, ret))
    return ret


# BOOL EndDialog(
#   HWND    hDlg,
#   INT_PTR nResult
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_EndDialog(ql, address):
    ret = 1
    hDlg, nResult = ql.get_params(2)
    ql.nprint('0x%0.2x: EndDialog(0x%0.2x, 0x%0.2x) = %d' %
        (address, hDlg, nResult, ret))
    return ret
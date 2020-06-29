#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.const import *
from qiling.const import *
from qiling.os.windows.structs import *

dllname = 'user32_dll'

# INT_PTR DialogBoxParamA(
#   HINSTANCE hInstance,
#   LPCSTR    lpTemplateName,
#   HWND      hWndParent,
#   DLGPROC   lpDialogFunc,
#   LPARAM    dwInitParam
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCSTR': 'POINTER'})
def hook_DialogBoxParamA(ql, address, params):
    ret = 0
    return ret


# UINT GetDlgItemTextA(
# 	HWND  hDlg,
# 	int   nIDDlgItem,
# 	LPSTR lpString,
# 	int   cchMax
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetDlgItemTextA(ql, address, params):
    ret = 0
    hDlg = params["hDlg"]
    nIDDlgItem = params["nIDDlgItem"]
    lpString = params["lpString"]
    cchMax = params["cchMax"]

    ql.os.stdout.write(b"Input DlgItemText :\n")
    string = ql.os.stdin.readline().strip()[:cchMax]
    ret = len(string)
    ql.mem.write(lpString, string)

    return ret


# BOOL EndDialog(
#   HWND    hDlg,
#   INT_PTR nResult
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_EndDialog(ql, address, params):
    ret = 1
    return ret


# HWND GetDesktopWindow((
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetDesktopWindow(ql, address, params):
    pass


# BOOL OpenClipboard(
#  HWND hWndNewOwner
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_OpenClipboard(ql, address, params):
    return ql.os.clipboard.open(params['hWndNewOwner'])


# BOOL CloseClipboard();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CloseClipboard(ql, address, params):
    return ql.os.clipboard.close()


# HANDLE SetClipboardData(
#  UINT   uFormat,
#  HANDLE hMem
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_SetClipboardData(ql, address, params):
    try:
        data = bytes(params['hMem'], 'ascii', 'ignore')
    except (UnicodeEncodeError, TypeError):
        data = b""
    return ql.os.clipboard.set_data(params['uFormat'], data)


# HANDLE GetClipboardData(
#  UINT uFormat
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetClipboardData(ql, address, params):
    data = ql.os.clipboard.get_data(params['uFormat'])
    if data:
        addr = ql.os.heap.alloc(len(data))
        ql.mem.write(addr, data)
        return addr
    else:
        ql.dprint(D_INFO, 'Failed to get clipboard data')
        return 0


# BOOL IsClipboardFormatAvailable(
#  UINT format
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_IsClipboardFormatAvailable(ql, address, params):
    rtn = ql.os.clipboard.format_available(params['uFormat'])
    return rtn


# UINT MapVirtualKeyW(
#   UINT uCode,
#   UINT uMapType
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_MapVirtualKeyW(ql, address, params):
    map_value = params["uMapType"]
    code_value = params["uCode"]
    map_dict = MAP_VK.get(map_value, None)
    if map_dict is not None:
        code = map_dict.get(code_value, None)
        if code is not None:
            return code
        else:
            ql.dprint(D_INFO, "Code value %x" % code_value)
            raise QlErrorNotImplemented("[!] API not implemented")
    else:
        ql.dprint(D_INFO, "Map value %x" % map_value)
        raise QlErrorNotImplemented("[!] API not implemented")


# SHORT GetKeyState(
#   int nVirtKey
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'int': 'UINT'})
def hook_GetKeyState(ql, address, params):
    let = chr(params["nVirtKey"])
    ql.dprint(0, let)
    UP = 2
    DOWN = 0
    return UP


# UINT RegisterWindowMessageA(
#   LPCSTR lpString
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegisterWindowMessageA(ql, address, params):
    return hook_RegisterWindowMessageW.__wrapped__(ql, address, params)


# UINT RegisterWindowMessageW(
#   LPCWSTR lpString
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_RegisterWindowMessageW(ql, address, params):
    # maybe some samples really use this and we need to have a real implementation
    return 0xD10C


# HWND GetActiveWindow();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetActiveWindow(ql, address, params):
    # maybe some samples really use this and we need to have a real implementation
    return 0xD10C


# HWND GetLastActivePopup(
#   HWND hWnd
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetLastActivePopup(ql, address, params):
    hwnd = params["hWnd"]
    return hwnd


# BOOL GetPhysicalCursorPos(
#   LPPOINT lpPoint
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetPhysicalCursorPos(ql, address, params):
    return 1


# int GetSystemMetrics(
#   int nIndex
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSystemMetrics(ql, address, params):
    info = params["nIndex"]
    if info == SM_CXICON or info == SM_CYICON:
        # Size of icon
        return 32
    elif info == SM_CXVSCROLL:
        return 4
    elif info == SM_CYHSCROLL:
        return 300
    else:
        ql.dprint(D_INFO, "Info value %x" % info)
        raise QlErrorNotImplemented("[!] API not implemented")


# HDC GetDC(
#   HWND hWnd
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetDC(ql, address, params):
    handler = params["hWnd"]
    # Maybe we should really emulate the handling of screens and windows. Is going to be a pain
    return 0xD10C


# int GetDeviceCaps(
#   HDC hdc,
#   int index
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetDeviceCaps(ql, address, params):
    # Maybe we should really emulate the handling of screens and windows. Is going to be a pain
    return 1


# int ReleaseDC(
#   HWND hWnd,
#   HDC  hDC
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HWND': 'POINTER'})
def hook_ReleaseDC(ql, address, params):
    return 1


# DWORD GetSysColor(
#   int nIndex
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSysColor(ql, address, params):
    info = params["nIndex"]
    return 0


# HBRUSH GetSysColorBrush(
#   int nIndex
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetSysColorBrush(ql, address, params):
    info = params["nIndex"]
    return 0xd10c


# HCURSOR LoadCursorA(
#   HINSTANCE hInstance,
#   LPCSTR    lpCursorName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HINSTANCE': 'POINTER', 'LPCSTR': 'INT'})
def hook_LoadCursorA(ql, address, params):
    return 0xd10c


# HCURSOR LoadCursorFromFileA(
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LoadCursorFromFileA(ql, address, params):
    return hook_LoadCursorFromFileW.__wrapped__(ql, address, params)


# HCURSOR LoadCursorFromFileW(
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_LoadCursorFromFileW(ql, address, params):
    handle = Handle()
    ql.os.handle_manager.append(handle)
    return handle.id


# UINT GetOEMCP();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetOEMCP(ql, address, params):
    return OEM_US


# int LoadStringW(
#   HINSTANCE hInstance,
#   UINT      uID,
#   LPSTR     lpBuffer,
#   int       cchBufferMax
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HINSTANCE': 'POINTER'})
def hook_LoadStringW(ql, address, params):
    dst = params["lpBuffer"]
    max_len = params["cchBufferMax"]
    # FIXME, should not be hardcoded
    string = "AAAABBBBCCCCDDDD" + "\x00"
    if max_len == 0:
        if len(string) >= max_len:
            string[max_len] = "\x00"
            string = string[:max_len]
        ql.mem.write(dst, string.encode("utf-16le"))
    # should not count the \x00 byte
    return len(string) - 1


# int LoadStringA(
#   HINSTANCE hInstance,
#   UINT      uID,
#   LPSTR     lpBuffer,
#   int       cchBufferMax
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HINSTANCE': 'POINTER'})
def hook_LoadStringA(ql, address, params):
    dst = params["lpBuffer"]
    max_len = params["cchBufferMax"]
    # FIXME, should not be hardcoded
    string = "AAAABBBBCCCCDDDD" + "\x00"
    if max_len == 0:
        if len(string) >= max_len:
            string[max_len] = "\x00"
            string = string[:max_len]
        ql.mem.write(dst, string.encode())
    # should not count the \x00 byte
    return len(string) - 1


# BOOL MessageBeep(
#   UINT uType
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_MessageBeep(ql, address, params):
    return 1


# HHOOK SetWindowsHookExA(
#   int       idHook,
#   HOOKPROC  lpfn,
#   HINSTANCE hmod,
#   DWORD     dwThreadId
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HINSTANCE': 'POINTER'})
def hook_SetWindowsHookExA(ql, address, params):
    # Should hook a procedure to a dll
    hook = params["lpfn"]
    return hook


# BOOL UnhookWindowsHookEx(
#   HHOOK hhk
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_UnhookWindowsHookEx(ql, address, params):
    return 1


# BOOL ShowWindow(
#   HWND hWnd,
#   int  nCmdShow
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HWND': 'POINTER'})
def hook_ShowWindow(ql, address, params):
    # return value depends on sample goal (evasion on just display error)
    return 0x1


# HICON LoadIconA(
#   HINSTANCE hInstance,
#   LPCSTR    lpIconName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HINSTANCE': 'POINTER', 'LPCSTR': 'UINT'})
def hook_LoadIconA(ql, address, params):
    return hook_LoadIconW(ql, address, params)


# HICON LoadIconW(
#   HINSTANCE hInstance,
#   LPCWSTR    lpIconName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HINSTANCE': 'POINTER', 'LPCWSTR': 'UINT'})
def hook_LoadIconW(ql, address, params):
    handle = Handle()
    ql.os.handle_manager.append(handle)
    return handle.id


# BOOL IsWindow(
#   HWND hWnd
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HWND': 'POINTER'})
def hook_IsWindow(ql, address, params):
    # return value depends on sample  goal (evasion on just display error)
    return 0x1


# LRESULT SendMessageA(
#   HWND   hWnd,
#   UINT   Msg,
#   WPARAM wParam,
#   LPARAM lParam
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HWND': 'POINTER', 'LPARAM': 'UINT'})
def hook_SendMessageA(ql, address, params):
    # TODO don't know how to get right return value
    return 0xD10C


# LRESULT LRESULT DefWindowProcA(
#   HWND   hWnd,
#   UINT   Msg,
#   WPARAM wParam,
#   LPARAM lParam
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'HWND': 'POINTER', 'LPARAM': 'UINT'})
def hook_DefWindowProcA(ql, address, params):
    # TODO don't know how to get right return value
    return 0xD10C


# LPWSTR CharNextW(
#   LPCWSTR lpsz
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCWSTR': 'POINTER'})
def hook_CharNextW(ql, address, params):
    # Return next char if is different from \x00
    point = params["lpsz"][0]
    string = ql.os.read_wstring(point)
    params["lpsz"] = string
    if len(string) == 0:
        return point
    else:
        return point + 1


# LPWSTR CharNextA(
#   LPCSTR lpsz
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CharNextA(ql, address, params):
    # Return next char if is different from \x00
    point = params["lpsz"][0]
    string = ql.os.read_cstring(point)
    params["lpsz"] = string
    if len(string) == 0:
        return point
    else:
        return point + 1


# LPWSTR CharPrevW(
#   LPCWSTR lpszStart,
#   LPCWSTR lpszCurrent
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCWSTR': 'POINTER'})
def hook_CharPrevW(ql, address, params):
    # Return next char if is different from \x00
    current = params["lpszCurrent"]
    strcur = ql.os.read_wstring(current)
    start = params["lpszStart"]
    strstart = ql.os.read_wstring(start)
    params["lpszStart"] = strstart
    params["lpszCurrent"] = strcur

    if start == current:
        return start
    return current - 1


# LPWSTR CharPrevA(
#   LPCSTR lpszStart,
#   LPCSTR lpszCurrent
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCSTR': 'POINTER'})
def hook_CharPrevA(ql, address, params):
    # Return next char if is different from \x00
    current = params["lpszCurrent"]
    strcur = ql.os.read_cstring(current)
    start = params["lpszStart"]
    strstart = ql.os.read_cstring(start)
    params["lpszStart"] = strstart
    params["lpszCurrent"] = strcur

    if start == current:
        return start
    return current - 1


# int WINAPIV wsprintfW(
#   LPWSTR  ,
#   LPCWSTR ,
#   ...
# );
@winsdkapi(cc=CDECL, dllname=dllname, param_num=3)
def hook_wsprintfW(ql, address, params):
    dst, p_format = ql.os.get_function_param(2)

    sp = ql.reg.esp if ql.archtype == QL_ARCH.X86 else ql.reg.rsp
    p_args = sp + ql.pointersize * 3
    format_string = ql.os.read_wstring(p_format)
    size, string = ql.os.printf(address, format_string, p_args, "wsprintfW", wstring=True)

    count = format_string.count('%')
    if ql.archtype == QL_ARCH.X8664:
        # We must pop the stack correctly
        raise QlErrorNotImplemented("[!] API not implemented")

    ql.mem.write(dst, (string + "\x00").encode("utf-16le"))
    return size


# int WINAPIV sprintf(
#   LPWSTR  ,
#   LPCWSTR ,
#   ...
# );
@winsdkapi(cc=CDECL, dllname=dllname, param_num=3)
def hook_sprintf(ql, address, params):
    dst, p_format, p_args = ql.os.get_function_param(3)
    format_string = ql.os.read_wstring(p_format)
    size, string = ql.os.printf(address, format_string, p_args, "sprintf", wstring=True)

    count = format_string.count('%')
    if ql.archtype == QL_ARCH.X8664:
        # We must pop the stack correctly
        raise QlErrorNotImplemented("[!] API not implemented")

    ql.mem.write(dst, (string + "\x00").encode("utf-16le"))
    return size


# HWND GetForegroundWindow();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetForegroundWindow(ql, address, params):
    return 0xF02E620D  # Value so we can recognize inside dumps


# BOOL MoveWindow(
#   HWND hWnd,
#   int  X,
#   int  Y,
#   int  nWidth,
#   int  nHeight,
#   BOOL bRepaint
# )
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_MoveWindow(ql, address, params):
    return 1


# int GetKeyboardType(
#  int nTypeFlag
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'int': 'UINT'})
def hook_GetKeyboardType(ql, address, params):
    """
    See https://salsa.debian.org/wine-team/wine/-/blob/master/dlls/user32/input.c
    """
    _type = params['nTypeFlag']
    if _type == 0:  # 0: Keyboard Type, 1: Keyboard subtype, 2: num func keys
        return 7
    elif _type == 1:
        return 0
    elif _type == 2:
        return 12
    return 0


# int MessageBoxW(
#   HWND    hWnd,
#   LPCWSTR lpText,
#   LPCWSTR lpCaption,
#   UINT    uType
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_MessageBoxW(ql, address, params):
    # We always return a positive result
    type_box = params["uType"]
    if type_box == MB_OK or type_box == MB_OKCANCEL:
        return IDOK
    if type_box == MB_YESNO or type_box == MB_YESNOCANCEL:
        return IDYES
    else:
        ql.dprint(D_INFO, type_box)
        raise QlErrorNotImplemented("[!] API not implemented")


# int MessageBoxA(
#   HWND    hWnd,
#   LPCWSTR lpText,
#   LPCWSTR lpCaption,
#   UINT    uType
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_MessageBoxA(ql, address, params):
    return hook_MessageBoxW.__wrapped__(ql, address, params)


# BOOL GetCursorPos(
#   LPPOINT lpPoint
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetCursorPos(ql, address, params):
    # TODO maybe we can add it to the profile too
    p = Point(ql, 50, 50)
    dest = params["lpPoint"]
    p.write(dest)
    return 0


# HANDLE CreateActCtxW(
#   PCACTCTXW pActCtx
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CreateActCtxW(ql, address, params):
    # TODo maybe is necessary to really create this
    addr = params["pActCtx"]
    handle = Handle(name="actctx")
    ql.os.handle_manager.append(handle)
    return handle.id


# DWORD GetWindowThreadProcessId(
#   HWND    hWnd,
#   LPDWORD lpdwProcessId
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetWindowThreadProcessId(ql, address, params):
    target = params["hWnd"]
    if target == ql.os.profile.getint("KERNEL", "pid") or target == ql.os.profile.getint("KERNEL", "shell_pid"):
        pid = ql.os.profile.getint("KERNEL", "parent_pid")
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    dst = params["lpdwProcessId"]
    if dst != 0:
        ql.mem.write(dst, pid.to_bytes(4, "little"))
    return pid


# HWND GetShellWindow();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetShellWindow(ql, address, params):
    return ql.os.profile.getint("KERNEL", "shell_pid")

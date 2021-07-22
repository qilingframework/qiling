#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.structs import *
from .const import *

#ATOM RegisterClassExA(
#  const WNDCLASSEXA *Arg1
#);
@winsdkapi(cc=STDCALL, params={
    'lpWndClass' : POINTER
})
def hook_RegisterClassExA(ql: Qiling, address: int, params):
    ret = 0
    return ret

#BOOL UpdateWindow(
#  HWND hWnd
#);
@winsdkapi(cc=STDCALL, params={
    'hWnd' : HWND
})
def hook_UpdateWindow(ql: Qiling, address: int, params):
    ret = 0
    return ret

# HWND CreateWindowExA(
#  DWORD     dwExStyle,
#  LPCSTR    lpClassName,
#  LPCSTR    lpWindowName,
#  DWORD     dwStyle,
#  int       X,
#  int       Y,
#  int       nWidth,
#  int       nHeight,
#  HWND      hWndParent,
#  HMENU     hMenu,
#  HINSTANCE hInstance,
#  LPVOID    lpParam
#);
@winsdkapi(cc=STDCALL, params={
    'dwExStyle'    : DWORD,
    'lpClassName'  : LPCSTR,
    'lpWindowName' : LPCSTR,
    'dwStyle'      : DWORD,
    'X'            : INT,
    'Y'            : INT,
    'nWidth'       : INT,
    'nHeight'      : INT,
    'hWndParent'   : HWND,
    'hMenu'        : POINTER,
    'hInstance'    : HINSTANCE,
    'lpParam'      : LPVOID
})
def hook_CreateWindowExA(ql: Qiling, address: int, params):
    return 0

@winsdkapi(cc=STDCALL, params={
    'dwExStyle'    : DWORD,
    'lpClassName'  : LPCWSTR,
    'lpWindowName' : LPCWSTR,
    'dwStyle'      : DWORD,
    'X'            : INT,
    'Y'            : INT,
    'nWidth'       : INT,
    'nHeight'      : INT,
    'hWndParent'   : HWND,
    'hMenu'        : POINTER,
    'hInstance'    : HINSTANCE,
    'lpParam'      : LPVOID
})
def hook_CreateWindowExW(ql: Qiling, address: int, params):
    return hook_CreateWindowExA.__wrapped__(ql, address, params)

# INT_PTR DialogBoxParamA(
#   HINSTANCE hInstance,
#   LPCSTR    lpTemplateName,
#   HWND      hWndParent,
#   DLGPROC   lpDialogFunc,
#   LPARAM    dwInitParam
# );
@winsdkapi(cc=STDCALL, params={
    'hInstance'      : HINSTANCE,
    'lpTemplateName' : POINTER,
    'hWndParent'     : HWND,
    'lpDialogFunc'   : DLGPROC,
    'dwInitParam'    : LPARAM
})
def hook_DialogBoxParamA(ql: Qiling, address: int, params):
    return 0

# UINT GetDlgItemTextA(
# 	HWND  hDlg,
# 	int   nIDDlgItem,
# 	LPSTR lpString,
# 	int   cchMax
# );
@winsdkapi(cc=STDCALL, params={
    'hDlg'       : HWND,
    'nIDDlgItem' : INT,
    'lpString'   : LPSTR,
    'cchMax'     : INT
})
def hook_GetDlgItemTextA(ql: Qiling, address: int, params):
    lpString = params["lpString"]
    cchMax = params["cchMax"]

    ql.os.stdout.write(b"Input DlgItemText :\n")
    string = ql.os.stdin.readline().strip()[:cchMax]
    ql.mem.write(lpString, string)

    return len(string)

# BOOL EndDialog(
#   HWND    hDlg,
#   INT_PTR nResult
# );
@winsdkapi(cc=STDCALL, params={
    'hDlg'    : HWND,
    'nResult' : INT_PTR
})
def hook_EndDialog(ql: Qiling, address: int, params):
    return 1

# HWND GetDesktopWindow();
@winsdkapi(cc=STDCALL, params={})
def hook_GetDesktopWindow(ql: Qiling, address: int, params):
    pass

# BOOL OpenClipboard(
#  HWND hWndNewOwner
# );
@winsdkapi(cc=STDCALL, params={
    'hWndNewOwner' : HWND
})
def hook_OpenClipboard(ql: Qiling, address: int, params):
    return ql.os.clipboard.open(params['hWndNewOwner'])

# BOOL CloseClipboard();
@winsdkapi(cc=STDCALL, params={})
def hook_CloseClipboard(ql: Qiling, address: int, params):
    return ql.os.clipboard.close()

# HANDLE SetClipboardData(
#  UINT   uFormat,
#  HANDLE hMem
# );
@winsdkapi(cc=STDCALL, params={
    'uFormat' : UINT,
    'hMem'    : HANDLE
})
def hook_SetClipboardData(ql: Qiling, address: int, params):
    try:
        data = bytes(params['hMem'], 'ascii', 'ignore')
    except (UnicodeEncodeError, TypeError):
        data = b""
        ql.log.debug('Failed to set clipboard data')

    return ql.os.clipboard.set_data(params['uFormat'], data)


# HANDLE GetClipboardData(
#  UINT uFormat
# );
@winsdkapi(cc=STDCALL, params={
    'uFormat' : UINT
})
def hook_GetClipboardData(ql: Qiling, address: int, params):
    data = ql.os.clipboard.get_data(params['uFormat'])

    if data:
        addr = ql.os.heap.alloc(len(data))
        ql.mem.write(addr, data)
    else:
        addr = 0
        ql.log.debug('Failed to get clipboard data')

    return addr

# BOOL IsClipboardFormatAvailable(
#  UINT format
# );
@winsdkapi(cc=STDCALL, params={
    'format' : UINT
})
def hook_IsClipboardFormatAvailable(ql: Qiling, address: int, params):
    return ql.os.clipboard.format_available(params['uFormat'])

# UINT MapVirtualKeyW(
#   UINT uCode,
#   UINT uMapType
# );
@winsdkapi(cc=STDCALL, params={
    'uCode'    : UINT,
    'uMapType' : UINT
})
def hook_MapVirtualKeyW(ql: Qiling, address: int, params):
    map_value = params["uMapType"]
    code_value = params["uCode"]

    map_dict = MAP_VK.get(map_value, None)

    if map_dict is None:
        ql.log.debug(f'Map value: {map_value:#x}')
        raise QlErrorNotImplemented("API not implemented")

    code = map_dict.get(code_value, None)

    if code is None:
        ql.log.debug(f'Code value {code_value:#x}')
        raise QlErrorNotImplemented("API not implemented")

    return code

# SHORT GetKeyState(
#   int nVirtKey
# );
@winsdkapi(cc=STDCALL, params={
    'nVirtKey' : UINT
})
def hook_GetKeyState(ql: Qiling, address: int, params):
    let = chr(params["nVirtKey"])
    ql.log.debug(f'Get key state of {let}')

    return 2 # DOWN=0, UP=2

# UINT RegisterWindowMessageA(
#   LPCSTR lpString
# );
@winsdkapi(cc=STDCALL, params={
    'lpString' : LPCSTR
})
def hook_RegisterWindowMessageA(ql: Qiling, address: int, params):
    return hook_RegisterWindowMessageW.__wrapped__(ql, address, params)

# UINT RegisterWindowMessageW(
#   LPCWSTR lpString
# );
@winsdkapi(cc=STDCALL, params={
    'lpString' : LPCWSTR
})
def hook_RegisterWindowMessageW(ql: Qiling, address: int, params):
    # maybe some samples really use this and we need to have a real implementation
    return 0xD10C

# HWND GetActiveWindow();
@winsdkapi(cc=STDCALL, params={})
def hook_GetActiveWindow(ql: Qiling, address: int, params):
    # maybe some samples really use this and we need to have a real implementation
    return 0xD10C

# HWND GetLastActivePopup(
#   HWND hWnd
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd' : HWND
})
def hook_GetLastActivePopup(ql: Qiling, address: int, params):
    return params["hWnd"]

# BOOL GetPhysicalCursorPos(
#   LPPOINT lpPoint
# );
@winsdkapi(cc=STDCALL, params={
    'lpPoint' : LPPOINT
})
def hook_GetPhysicalCursorPos(ql: Qiling, address: int, params):
    # TODO: bug? return value doesn't look like a valid pointer
    return 1

# int GetSystemMetrics(
#   int nIndex
# );
@winsdkapi(cc=STDCALL, params={
    'nIndex' : INT
})
def hook_GetSystemMetrics(ql: Qiling, address: int, params):
    info = params["nIndex"]

    size = {
        SM_CXICON : 32,
        SM_CYICON : 32,
        SM_CXVSCROLL : 4,
        SM_CYHSCROLL : 300
    }.get(info)

    if size is None:
        ql.log.debug(f'Info value {info}')
        raise QlErrorNotImplemented("API not implemented")

    return size

# HDC GetDC(
#   HWND hWnd
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd' : HWND
})
def hook_GetDC(ql: Qiling, address: int, params):
    # Maybe we should really emulate the handling of screens and windows. Is going to be a pain
    return 0xD10C

# int GetDeviceCaps(
#    hdc,
#   int index
# );
@winsdkapi(cc=STDCALL, params={
    'hdc'   : HDC,
    'index' : INT
})
def hook_GetDeviceCaps(ql: Qiling, address: int, params):
    # Maybe we should really emulate the handling of screens and windows. Is going to be a pain
    return 1

# int ReleaseDC(
#   HWND hWnd,
#   HDC  hDC
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd' : HWND,
    'hDC'  : HDC
})
def hook_ReleaseDC(ql: Qiling, address: int, params):
    return 1

# DWORD GetSysColor(
#   int nIndex
# );
@winsdkapi(cc=STDCALL, params={
    'nIndex' : INT
})
def hook_GetSysColor(ql: Qiling, address: int, params):
    return 0

# HBRUSH GetSysColorBrush(
#   int nIndex
# );
@winsdkapi(cc=STDCALL, params={
    'nIndex' : INT
})
def hook_GetSysColorBrush(ql: Qiling, address: int, params):
    return 0xD10C

# HCURSOR LoadCursorA(
#   HINSTANCE hInstance,
#   LPCSTR    lpCursorName
# );
@winsdkapi(cc=STDCALL, params={
    'hInstance'    : HINSTANCE,
    'lpCursorName' : LPCSTR
})
def hook_LoadCursorA(ql: Qiling, address: int, params):
    return 0xD10C

# HCURSOR LoadCursorFromFileA(
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName' : LPCSTR
})
def hook_LoadCursorFromFileA(ql: Qiling, address: int, params):
    return hook_LoadCursorFromFileW.__wrapped__(ql, address, params)

# HCURSOR LoadCursorFromFileW(
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName' : LPCWSTR
})
def hook_LoadCursorFromFileW(ql: Qiling, address: int, params):
    handle = Handle()
    ql.os.handle_manager.append(handle)

    return handle.id

# UINT GetOEMCP();
@winsdkapi(cc=STDCALL, params={})
def hook_GetOEMCP(ql: Qiling, address: int, params):
    return OEM_US

# int LoadStringW(
#   HINSTANCE hInstance,
#   UINT      uID,
#   LPSTR     lpBuffer,
#   int       cchBufferMax
# );
@winsdkapi(cc=STDCALL, params={
    'hInstance'    : HINSTANCE,
    'uID'          : UINT,
    'lpBuffer'     : LPWSTR,
    'cchBufferMax' : INT
})
def hook_LoadStringW(ql: Qiling, address: int, params):
    dst = params["lpBuffer"]
    max_len = params["cchBufferMax"]

    # FIXME: should not be hardcoded
    string = "AAAABBBBCCCCDDDD" + "\x00"

    if max_len:
        if len(string) >= max_len:
            string = string[:max_len] + "\x00"

        ql.mem.write(dst, string.encode("utf-16le"))

    # should not count the \x00 byte
    return len(string) - 1

# int LoadStringA(
#   HINSTANCE hInstance,
#   UINT      uID,
#   LPSTR     lpBuffer,
#   int       cchBufferMax
# );
@winsdkapi(cc=STDCALL, params={
    'hInstance'    : HINSTANCE,
    'uID'          : UINT,
    'lpBuffer'     : LPSTR,
    'cchBufferMax' : INT
})
def hook_LoadStringA(ql: Qiling, address: int, params):
    dst = params["lpBuffer"]
    max_len = params["cchBufferMax"]

    # FIXME: should not be hardcoded
    string = "AAAABBBBCCCCDDDD" + "\x00"

    if max_len:
        if len(string) >= max_len:
            string = string[:max_len] + "\x00"

        ql.mem.write(dst, string.encode())

    # should not count the \x00 byte
    return len(string) - 1

# BOOL MessageBeep(
#   UINT uType
# );
@winsdkapi(cc=STDCALL, params={
    'uType' : UINT
})
def hook_MessageBeep(ql: Qiling, address: int, params):
    return 1

# HHOOK SetWindowsHookExA(
#   int       idHook,
#   HOOKPROC  lpfn,
#   HINSTANCE hmod,
#   DWORD     dwThreadId
# );
@winsdkapi(cc=STDCALL, params={
    'idHook'     : INT,
    'lpfn'       : HOOKPROC,
    'hmod'       : HINSTANCE,
    'dwThreadId' : DWORD
})
def hook_SetWindowsHookExA(ql: Qiling, address: int, params):
    # Should hook a procedure to a dll
    hook = params["lpfn"]
    return hook

# BOOL UnhookWindowsHookEx(
#   HHOOK hhk
# );
@winsdkapi(cc=STDCALL, params={
    'hhk' : HHOOK
})
def hook_UnhookWindowsHookEx(ql: Qiling, address: int, params):
    return 1

# BOOL ShowWindow(
#   HWND hWnd,
#   int  nCmdShow
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'     : HWND,
    'nCmdShow' : INT
})
def hook_ShowWindow(ql: Qiling, address: int, params):
    # return value depends on sample goal (evasion on just display error)
    return 1

# HICON LoadIconA(
#   HINSTANCE hInstance,
#   LPCSTR    lpIconName
# );
@winsdkapi(cc=STDCALL, params={
    'hInstance'  : HINSTANCE,
    'lpIconName' : UINT # LPCSTR
})
def hook_LoadIconA(ql: Qiling, address: int, params):
    return hook_LoadIconW.__wrapped__(ql, address, params)

# HICON LoadIconW(
#   HINSTANCE hInstance,
#   LPCWSTR    lpIconName
# );
@winsdkapi(cc=STDCALL, params={
    'hInstance'  : HINSTANCE,
    'lpIconName' : UINT # LPCWSTR
})
def hook_LoadIconW(ql: Qiling, address: int, params):
    name = params['lpIconName']

    if name in (IDI_APPLICATION, IDI_ASTERISK, IDI_ERROR, IDI_EXCLAMATION, IDI_HAND,
                        IDI_INFORMATION, IDI_QUESTION, IDI_SHIELD, IDI_WARNING, IDI_WINLOGO):
        return 1

    return 0

# BOOL IsWindow(
#   HWND hWnd
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd' : HWND
})
def hook_IsWindow(ql: Qiling, address: int, params):
    # return value depends on sample  goal (evasion on just display error)
    return 1

# LRESULT SendMessageA(
#   HWND   hWnd,
#   UINT   Msg,
#   WPARAM wParam,
#   LPARAM lParam
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'   : HWND,
    'Msg'    : UINT,
    'wParam' : WPARAM,
    'lParam' : LPARAM
})
def hook_SendMessageA(ql: Qiling, address: int, params):
    # TODO don't know how to get right return value
    return 0xD10C

# LRESULT LRESULT DefWindowProcA(
#   HWND   hWnd,
#   UINT   Msg,
#   WPARAM wParam,
#   LPARAM lParam
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'   : HWND,
    'Msg'    : UINT,
    'wParam' : WPARAM,
    'lParam' : LPARAM
})
def hook_DefWindowProcA(ql: Qiling, address: int, params):
    # TODO don't know how to get right return value
    return 0xD10C

def __CharLowerBuff(ql: Qiling, address: int, params, wstring: bool):
    lpBuffer = params["lpBuffer"]
    cchLength = params["cchLength"]

    data = ql.mem.read(lpBuffer, cchLength)

    enc = 'utf-16le' if wstring else 'utf-8'
    data = data.decode(enc)
    data = data.lower()
    data = data.encode(enc)

    ql.mem.write(lpBuffer, data)

    return len(data)

# DWORD CharLowerBuffA(
#   LPSTR lpsz,
#   DWORD cchLength
# );
@winsdkapi(cc=STDCALL, params={
    'lpsz'      : LPSTR,
    'cchLength' : DWORD
})
def hook_CharLowerBuffA(ql: Qiling, address: int, params):
    return __CharLowerBuff(ql, address, params, False)

@winsdkapi(cc=STDCALL, params={
    'lpsz'      : LPWSTR,
    'cchLength' : DWORD
})
def hook_CharLowerBuffW(ql: Qiling, address: int, params):
    return __CharLowerBuff(ql, address, params, True)

# LPSTR CharLowerA(
#   LPSTR lpsz
# );
@winsdkapi(cc=STDCALL, params={
    'lpsz' : LPSTR
})
def hook_CharLowerA(ql: Qiling, address: int, params):
    lpsz = params["lpsz"]

    if (lpsz >> 16) > 0:
        value = ql.os.utils.read_cstring(lpsz)
        value = value.lower()
        value = value.encode("utf-8")
        ql.mem.write(lpsz, value)
        return len(value)
    else:
        value = chr(lpsz & 0xffff)
        return value.lower()

# LPWSTR CharNextW(
#   LPCWSTR lpsz
# );
@winsdkapi(cc=STDCALL, params={
    'lpsz' : POINTER # LPCWSTR
})
def hook_CharNextW(ql: Qiling, address: int, params):
    addr = params["lpsz"]
    s = ql.os.utils.read_wstring(addr)

    # return a pointer to the next non-null char
    return addr if len(s) == 0 else addr + 1

# LPWSTR CharNextA(
#   LPCSTR lpsz
# );
@winsdkapi(cc=STDCALL, params={
    'lpsz' : POINTER # LPCSTR
})
def hook_CharNextA(ql: Qiling, address: int, params):
    addr = params["lpsz"]
    s = ql.os.utils.read_cstring(addr)

    # return a pointer to the next non-null char
    return addr if len(s) == 0 else addr + 1

# LPWSTR CharPrevW(
#   LPCWSTR lpszStart,
#   LPCWSTR lpszCurrent
# );
@winsdkapi(cc=STDCALL, params={
    'lpszStart'   : POINTER, # LPCWSTR
    'lpszCurrent' : POINTER  # LPCWSTR
})
def hook_CharPrevW(ql: Qiling, address: int, params):
    start = params["lpszStart"]
    current = params["lpszCurrent"]
    charlen = 2

    # cannot go back beyond start pointer
    if (current - start) < charlen:
        return start

    return current - charlen

# LPWSTR CharPrevA(
#   LPCSTR lpszStart,
#   LPCSTR lpszCurrent
# );
@winsdkapi(cc=STDCALL, params={
    'lpszStart'   : POINTER, # LPCSTR
    'lpszCurrent' : POINTER  # LPCSTR
})
def hook_CharPrevA(ql: Qiling, address: int, params):
    start = params["lpszStart"]
    current = params["lpszCurrent"]
    charlen = 1

    # cannot go back beyond start pointer
    if (current - start) < charlen:
        return start

    return current - charlen

# int WINAPIV wsprintfW(
#   LPWSTR  ,
#   LPCWSTR ,
#   ...
# );
# note that cc=CDECL
@winsdkapi(cc=CDECL, params={
    'Buffer' : POINTER,
    'Format' : LPCWSTR
})
def hook_wsprintfW(ql: Qiling, address: int, params):
    Buffer = params['Buffer']
    Format = params['Format']

    if Format == 0:
        Format = "(null)"

    nargs = Format.count("%")
    ptypes = (POINTER, POINTER) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[2:]

    count = ql.os.utils.sprintf(Buffer, Format, args, wstring=True)
    ql.os.utils.update_ellipsis(params, args)

    return count

# HWND GetForegroundWindow();
@winsdkapi(cc=STDCALL, params={})
def hook_GetForegroundWindow(ql: Qiling, address: int, params):
    return 0xF02E620D  # recognizable magic value

# BOOL MoveWindow(
#   HWND hWnd,
#   int  X,
#   int  Y,
#   int  nWidth,
#   int  nHeight,
#   BOOL bRepaint
# )
@winsdkapi(cc=STDCALL, params={
    'hWnd'     : HWND,
    'X'        : INT,
    'Y'        : INT,
    'nWidth'   : INT,
    'nHeight'  : INT,
    'bRepaint' : BOOL
})
def hook_MoveWindow(ql: Qiling, address: int, params):
    return 1

# int GetKeyboardType(
#  int nTypeFlag
# );
@winsdkapi(cc=STDCALL, params={
    'nTypeFlag' : INT
})
def hook_GetKeyboardType(ql: Qiling, address: int, params):
    """
    See https://salsa.debian.org/wine-team/wine/-/blob/master/dlls/user32/input.c
    """

    # 0: Keyboard Type, 1: Keyboard subtype, 2: num func keys
    tf = params['nTypeFlag']

    kbtypes = (7, 0, 12)

    return kbtypes[tf] if tf < len(kbtypes) else 0

# int wvsprintfA(
# LPTSTR lpOutput, 
# LPCTSTR lpFormat, 
# va_list ArgList
# );
# note that cc=CDECL
@winsdkapi(cc=CDECL, params={
    "lpOutput" : POINTER,
    "lpFormat" : POINTER,
    "ArgList"  : POINTER
})
def hook_wvsprintfA(ql: Qiling, address: int, params):
    return None

# int wsprintfA(
#    char *buffer,
#    const char *format,
# );
# note that cc=CDECL
@winsdkapi(cc=CDECL, params={
    'Buffer' : LPSTR,
    'Format' : LPCSTR
})
def hook_wsprintfA(ql: Qiling, address: int, params):
    Buffer = params['Buffer']
    Format = params['Format']

    if Format == 0:
        Format = "(null)"

    nargs = Format.count("%")
    ptypes = (POINTER, POINTER) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[2:]

    count = ql.os.utils.sprintf(Buffer, Format, args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count

# int MessageBoxW(
#   HWND    hWnd,
#   LPCWSTR lpText,
#   LPCWSTR lpCaption,
#   UINT    uType
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'      : HWND,
    'lpText'    : LPCWSTR,
    'lpCaption' : LPCWSTR,
    'uType'     : UINT
})
def hook_MessageBoxW(ql: Qiling, address: int, params):
    # We always return a positive result
    type_box = params["uType"]

    if type_box in (MB_OK, MB_OKCANCEL):
        return IDOK

    if type_box in (MB_YESNO, MB_YESNOCANCEL):
        return IDYES

    ql.log.debug(type_box)
    raise QlErrorNotImplemented("API not implemented")

# int MessageBoxA(
#   HWND    hWnd,
#   LPCWSTR lpText,
#   LPCWSTR lpCaption,
#   UINT    uType
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'      : HWND,
    'lpText'    : LPCSTR,
    'lpCaption' : LPCSTR,
    'uType'     : UINT
})
def hook_MessageBoxA(ql: Qiling, address: int, params):
    return hook_MessageBoxW.__wrapped__(ql, address, params)

# BOOL GetCursorPos(
#   LPPOINT lpPoint
# );
@winsdkapi(cc=STDCALL, params={
    'lpPoint' : LPPOINT
})
def hook_GetCursorPos(ql: Qiling, address: int, params):
    dest = params["lpPoint"]

    # TODO: maybe we can add it to the profile too
    p = Point(ql, 50, 50)
    p.write(dest)

    return 0

# HANDLE CreateActCtxW(
#   PCACTCTXW pActCtx
# );
@winsdkapi(cc=STDCALL, params={
    'pActCtx' : PCACTCTXW
})
def hook_CreateActCtxW(ql: Qiling, address: int, params):
    # TODO: maybe is necessary to really create this
    handle = Handle(name="actctx")
    ql.os.handle_manager.append(handle)

    return handle.id

# DWORD GetWindowThreadProcessId(
#   HWND    hWnd,
#   LPDWORD lpdwProcessId
# );
@winsdkapi(cc=STDCALL, params={
    'hWnd'          : HWND,
    'lpdwProcessId' : LPDWORD
})
def hook_GetWindowThreadProcessId(ql: Qiling, address: int, params):
    target = params["hWnd"]

    if target == ql.os.profile.getint("KERNEL", "pid") or target == ql.os.profile.getint("KERNEL", "shell_pid"):
        pid = ql.os.profile.getint("KERNEL", "parent_pid")
    else:
        raise QlErrorNotImplemented("API not implemented")

    dst = params["lpdwProcessId"]

    if dst != 0:
        ql.mem.write(dst, pid.to_bytes(4, "little"))

    return pid

# HWND GetShellWindow();
@winsdkapi(cc=STDCALL, params={})
def hook_GetShellWindow(ql: Qiling, address: int, params):
    return ql.os.profile.getint("KERNEL", "shell_pid")

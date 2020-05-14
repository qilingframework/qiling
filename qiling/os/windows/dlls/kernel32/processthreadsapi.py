#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
import time
from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.structs import *


# void ExitProcess(
#   UINT uExitCode
# );
@winapi(cc=STDCALL, params={
    "uExitCode": DWORD
})
def hook_ExitProcess(ql, address, params):
    ql.emu_stop()
    ql.os.PE_RUN = False


# typedef struct _STARTUPINFO {
#   DWORD  cb;
#   LPTSTR lpReserved;
#   LPTSTR lpDesktop;
#   LPTSTR lpTitle;
#   DWORD  dwX;
#   DWORD  dwY;
#   DWORD  dwXSize;
#   DWORD  dwYSize;
#   DWORD  dwXCountChars;
#   DWORD  dwYCountChars;
#   DWORD  dwFillAttribute;
#   DWORD  dwFlags;
#   WORD   wShowWindow;
#   WORD   cbReserved2;
#   LPBYTE lpReserved2;
#   HANDLE hStdInput;
#   HANDLE hStdOutput;
#   HANDLE hStdError;
# } STARTUPINFO, *LPSTARTUPINFO;
def GetStartupInfo(ql, address, params):
    startup_info = {
        "cb": (0x34 + 4*ql.pointersize).to_bytes(length=4, byteorder='little'),
        "lpReserved": 0x0.to_bytes(length=ql.pointersize, byteorder='little'),
        "lpDesktop": 0xc3c930.to_bytes(length=ql.pointersize, byteorder='little'),
        "lpTitle": 0x0.to_bytes(length=ql.pointersize, byteorder='little'),
        "dwX": 0x0.to_bytes(length=4, byteorder='little'),
        "dwY": 0x0.to_bytes(length=4, byteorder='little'),
        "dwXSize": 0x64.to_bytes(length=4, byteorder='little'),
        "dwYSize": 0x64.to_bytes(length=4, byteorder='little'),
        "dwXCountChars": 0x84.to_bytes(length=4, byteorder='little'),
        "dwYCountChars": 0x80.to_bytes(length=4, byteorder='little'),
        "dwFillAttribute": 0xff.to_bytes(length=4, byteorder='little'),
        "dwFlags": 0x40.to_bytes(length=4, byteorder='little'),
        "wShowWindow": 0x1.to_bytes(length=2, byteorder='little'),
        "cbReserved2": 0x0.to_bytes(length=2, byteorder='little'),
        "lpReserved2": 0x0.to_bytes(length=ql.pointersize, byteorder='little'),
        "hStdInput": 0xffffffff.to_bytes(length=4, byteorder='little'),
        "hStdOutput": 0xffffffff.to_bytes(length=4, byteorder='little'),
        "hStdError": 0xffffffff.to_bytes(length=4, byteorder='little')
    }
    pointer = params["lpStartupInfo"]
    values = b"".join(startup_info.values())

    # CB must be the size of the struct
    assert len(values) == startup_info["cb"][0]
    ql.mem.write(pointer, values)
    return 0


# VOID WINAPI GetStartupInfoA(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(cc=STDCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoA(ql, address, params):
    return GetStartupInfo(ql, address, params)


# VOID WINAPI GetStartupInfoW(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(cc=STDCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoW(ql, address, params):
    # The struct for the W version uses LPWSTRING, but i think is the same in this context
    return GetStartupInfo(ql, address, params)


# DWORD TlsAlloc();
@winapi(cc=STDCALL, params={})
def hook_TlsAlloc(ql, address, params):
    idx = ql.os.thread_manager.cur_thread.tls_index
    ql.os.thread_manager.cur_thread.tls_index += 1
    ql.os.thread_manager.cur_thread.tls[idx] = 0
    return idx


# DWORD TlsFree(
#  DWORD dwTlsIndex
# );
@winapi(cc=STDCALL, params={
    "dwTlsIndex": UINT
})
def hook_TlsFree(ql, address, params):
    idx = params['dwTlsIndex']
    if idx not in ql.os.thread_manager.cur_thread.tls:
        ql.os.last_error = 0x57  # (ERROR_INVALID_PARAMETER)
        return 0
    else:
        del (ql.os.thread_manager.cur_thread.tls[idx])
        return 1


# LPVOID TlsGetValue(
#  DWORD dwTlsIndex
# );
@winapi(cc=STDCALL, params={
    "dwTlsIndex": UINT})
def hook_TlsGetValue(ql, address, params):
    idx = params['dwTlsIndex']
    if idx not in ql.os.thread_manager.cur_thread.tls:
        ql.os.last_error = 0x57  # (ERROR_INVALID_PARAMETER)
        return 0
    else:
        # api explicity clears last error on success:
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue
        ql.os.last_error
        return ql.os.thread_manager.cur_thread.tls[idx]


# LPVOID TlsSetValue(
#  DWORD dwTlsIndex
# );
@winapi(cc=STDCALL, params={
    "dwTlsIndex": UINT,
    "lpTlsValue": POINTER
})
def hook_TlsSetValue(ql, address, params):
    idx = params['dwTlsIndex']
    if idx not in ql.os.thread_manager.cur_thread.tls:
        ql.os.last_error = 0x57  # (ERROR_INVALID_PARAMETER)
        return 0
    else:
        ql.os.thread_manager.cur_thread.tls[idx] = params['lpTlsValue']
        return 1


# DWORD GetCurrentThreadId(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentThreadId(ql, address, params):
    ret = ql.os.thread_manager.cur_thread.id
    return ret


# DWORD GetCurrentProcessId(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentProcessId(ql, address, params):
    # Let's return a valid value
    return 0x2005


# BOOL IsProcessorFeaturePresent(
#   DWORD ProcessorFeature
# );
@winapi(cc=STDCALL, params={
    "ProcessorFeature": DWORD
})
def hook_IsProcessorFeaturePresent(ql, address, params):
    feature = params["ProcessorFeature"]
    if feature == PF_XSAVE_ENABLED:
        # it seems like unicorn can't recognize the instruction
        return 0
    else:
        return 1


# HANDLE CreateThread(
#   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
#   SIZE_T                  dwStackSize,
#   LPTHREAD_START_ROUTINE  lpStartAddress,
#   __drv_aliasesMem LPVOID lpParameter,
#   DWORD                   dwCreationFlags,
#   LPDWORD                 lpThreadId
# );
@winapi(cc=STDCALL, params={
    "lpThreadAttributes": POINTER,
    "dwStackSize": SIZE_T,
    "lpStartAddress": POINTER,
    "lpParameter": POINTER,
    "dwCreationFlags": DWORD,
    "lpThreadId": POINTER
})
def hook_CreateThread(ql, address, params):
    CREATE_RUN = 0
    CREATE_SUSPENDED = 0x00000004

    ret = 0
    lpThreadAttributes = params["lpThreadAttributes"]
    dwStackSize = params["dwStackSize"]
    lpStartAddress = params["lpStartAddress"]
    lpParameter = params["lpParameter"]
    dwCreationFlags = params["dwCreationFlags"]
    lpThreadId = params["lpThreadId"]

    # new thread obj
    new_thread = QlWindowsThread(ql)

    if dwCreationFlags & CREATE_SUSPENDED == CREATE_SUSPENDED:
        thread_status = QlWindowsThread.READY
    else:
        thread_status = QlWindowsThread.RUNNING

    # create new thread
    thread_id = new_thread.create(
        lpStartAddress,
        lpParameter,
        thread_status
    )

    # append the new thread to ThreadManager
    ql.os.thread_manager.append(new_thread)

    # create thread handle
    new_handle = Handle(obj=new_thread)
    ql.os.handle_manager.append(new_handle)
    ret = new_handle.id

    # set lpThreadId
    if lpThreadId != 0:
        ql.mem.write(lpThreadId, ql.pack(thread_id))

    # set thread handle
    return ret


# HANDLE GetCurrentProcess(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentProcess(ql, address, params):
    ret = 0
    return ret


# BOOL TerminateProcess(
#   HANDLE hProcess,
#   UINT   uExitCode
# );
@winapi(cc=STDCALL, params={
    "hProcess": HANDLE,
    "uExitCode": UINT
})
def hook_TerminateProcess(ql, address, params):
    # Samples will try to kill other process! We don't want to always stop!
    process = params["hProcess"]
    # TODO i have no idea on how to find the old ql.pe.image_address
    if process == 0x0:  # or process == ql.os.image_address:
        ql.emu_stop()
        ql.os.PE_RUN = False
    ret = 1
    return ret


# HANDLE GetCurrentThread();
@winapi(cc=STDCALL, params={
})
def hook_GetCurrentThread(ql, address, params):
    ret = ql.os.thread_manager.cur_thread.id
    return ret


# HANDLE OpenProcess(
#   DWORD dwDesiredAccess,
#   BOOL  bInheritHandle,
#   DWORD dwProcessId
# );
@winapi(cc=STDCALL, params={
    "dwDesiredAccess": DWORD,
    "bInheritHandle": HANDLE,
    "dwProcessId": DWORD
})
def hook_OpenProcess(ql, address, params):
    proc = params["dwProcessId"]
    # If the specified process is the System Process (0x00000000),
    # the function fails and the last error code is ERROR_INVALID_PARAMETER
    if proc == 0:
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0
    return 0xD10C


# BOOL OpenProcessToken(
#   HANDLE  ProcessHandle,
#   DWORD   DesiredAccess,
#   PHANDLE TokenHandle
# );
@winapi(cc=STDCALL, params={
    "ProcessHandle": HANDLE,
    "DesiredAccess": DWORD,
    "TokenHandle": POINTER
})
def hook_OpenProcessToken(ql, address, params):
    token_pointer = params["TokenHandle"]
    token = Token(ql)
    new_handle = Handle(obj=token)
    ql.os.handle_manager.append(new_handle)
    ql.mem.write(token_pointer, ql.pack(new_handle.id))
    return 1


# BOOL GetThreadContext(
#   HANDLE    hThread,
#   LPCONTEXT lpContext
# );
@winapi(cc=STDCALL, params={
    "hThread": HANDLE,
    "lpContext": POINTER
})
def hook_GetThreadContext(ql, address, params):
    return 1

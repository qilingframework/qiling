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


def _GetStartupInfo(ql, address, params):
    startup_info = StartupInfo(ql, 0xc3c930, 0, 0, 0, 0x64, 0x64, 0x84, 0x80, 0xff, 0x40, 0x1, STD_INPUT_HANDLE,
                               STD_OUTPUT_HANDLE, STD_ERROR_HANDLE)

    pointer = params["lpStartupInfo"]
    startup_info.write(pointer)
    return 0


# VOID WINAPI GetStartupInfoA(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(cc=STDCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoA(ql, address, params):
    return _GetStartupInfo(ql, address, params)


# VOID WINAPI GetStartupInfoW(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(cc=STDCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoW(ql, address, params):
    # The struct for the W version uses LPWSTRING, but i think is the same in this context
    return _GetStartupInfo(ql, address, params)


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
        ql.os.last_error = 0
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
    return ql.os.profile.getint("KERNEL", "pid")


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
    # FIXME: Temporary fix for the crash
    if lpThreadId != 0:
        ql.mem.write(lpThreadId, ql.pack(thread_id))    

    # set thread handle
    return ret


# HANDLE GetCurrentProcess(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentProcess(ql, address, params):
    return ql.os.profile.getint("KERNEL", "pid")


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
    if process == ql.os.profile.getint("KERNEL", "pid"):  # or process == ql.os.image_address:
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
    #  If the specified process is the Idle process or one of the CSRSS processes, this function fails
    #  and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code
    #  from opening them.
    if proc == ql.profile.getint("PROCESSES", "csrss.exe"):
        ql.os.last_error = ERROR_ACCESS_DENIED
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


# BOOL OpenThreadToken(
#   HANDLE  ThreadHandle,
#   DWORD   DesiredAccess,
#   BOOL    OpenAsSelf,
#   PHANDLE TokenHandle
# );
@winapi(cc=STDCALL, params={
    "ThreadHandle": HANDLE,
    "DesiredAccess": DWORD,
    "OpenAsSelf": BOOL,
    "TokenHandle": POINTER
})
def hook_OpenThreadToken(ql, address, params):
    token_pointer = params["TokenHandle"]
    token = Token(ql)
    new_handle = Handle(obj=token)
    ql.os.handle_manager.append(new_handle)
    ql.mem.write(token_pointer, ql.pack(new_handle.id))
    return 1


# BOOL GetThreadTimes(
#   HANDLE     hThread,
#   LPFILETIME lpCreationTime,
#   LPFILETIME lpExitTime,
#   LPFILETIME lpKernelTime,
#   LPFILETIME lpUserTime
# );
@winapi(cc=STDCALL, params={
    "hThread": HANDLE,
    "lpCreationTime": POINTER,
    "lpExitTime": POINTER,
    "lpKernelTime": POINTER,
    "lpUserTime": POINTER
})
def hook_GetThreadTimes(ql, address, params):
    return 1

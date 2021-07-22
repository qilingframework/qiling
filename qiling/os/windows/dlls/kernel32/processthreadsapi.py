#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

from qiling.os.windows.thread import QlWindowsThread
from qiling.os.windows.handle import Handle
from qiling.os.windows.structs import Token, StartupInfo

# void ExitProcess(
#   UINT uExitCode
# );
@winsdkapi(cc=STDCALL, params={
    'uExitCode' : UINT
})
def hook_ExitProcess(ql: Qiling, address: int, params):
    ql.emu_stop()
    ql.os.PE_RUN = False

def _GetStartupInfo(ql: Qiling, address: int, params):
    startup_info = StartupInfo(ql, 0xc3c930, 0, 0, 0, 0x64, 0x64, 0x84, 0x80, 0xff, 0x40, 0x1, STD_INPUT_HANDLE,
                               STD_OUTPUT_HANDLE, STD_ERROR_HANDLE)

    pointer = params["lpStartupInfo"]
    startup_info.write(pointer)

    return 0

# VOID WINAPI GetStartupInfoA(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winsdkapi(cc=STDCALL, params={
    'lpStartupInfo' : LPSTARTUPINFOA
})
def hook_GetStartupInfoA(ql: Qiling, address: int, params):
    return _GetStartupInfo(ql, address, params)

# VOID WINAPI GetStartupInfoW(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winsdkapi(cc=STDCALL, params={
    'lpStartupInfo' : LPSTARTUPINFOW
})
def hook_GetStartupInfoW(ql: Qiling, address: int, params):
    return _GetStartupInfo(ql, address, params)

# DWORD TlsAlloc();
@winsdkapi(cc=STDCALL, params={})
def hook_TlsAlloc(ql: Qiling, address: int, params):
    idx = ql.os.thread_manager.cur_thread.tls_index
    ql.os.thread_manager.cur_thread.tls_index += 1
    ql.os.thread_manager.cur_thread.tls[idx] = 0

    return idx

# DWORD TlsFree(
#  DWORD dwTlsIndex
# );
@winsdkapi(cc=STDCALL, params={
    'dwTlsIndex' : DWORD
})
def hook_TlsFree(ql: Qiling, address: int, params):
    idx = params['dwTlsIndex']

    if idx not in ql.os.thread_manager.cur_thread.tls:
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0

    del (ql.os.thread_manager.cur_thread.tls[idx])
    return 1

# LPVOID TlsGetValue(
#  DWORD dwTlsIndex
# );
@winsdkapi(cc=STDCALL, params={
    'dwTlsIndex' : DWORD
})
def hook_TlsGetValue(ql: Qiling, address: int, params):
    idx = params['dwTlsIndex']

    if idx not in ql.os.thread_manager.cur_thread.tls:
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0

    # api explicity clears last error on success:
    # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue
    ql.os.last_error = 0
    return ql.os.thread_manager.cur_thread.tls[idx]

# BOOL TlsSetValue(
#   DWORD  dwTlsIndex,
#   LPVOID lpTlsValue
# );
@winsdkapi(cc=STDCALL, params={
    'dwTlsIndex' : DWORD,
    'lpTlsValue' : LPVOID
})
def hook_TlsSetValue(ql: Qiling, address: int, params):
    idx = params['dwTlsIndex']

    if idx not in ql.os.thread_manager.cur_thread.tls:
        ql.os.last_error = ERROR_INVALID_PARAMETER
        return 0

    ql.os.thread_manager.cur_thread.tls[idx] = params['lpTlsValue']
    return 1

# DWORD GetCurrentThreadId(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetCurrentThreadId(ql: Qiling, address: int, params):
    return ql.os.thread_manager.cur_thread.id

# DWORD GetCurrentProcessId(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetCurrentProcessId(ql: Qiling, address: int, params):
    # Let's return a valid value
    return ql.os.profile.getint("KERNEL", "pid")

# BOOL IsProcessorFeaturePresent(
#   DWORD ProcessorFeature
# );
@winsdkapi(cc=STDCALL, params={
    'ProcessorFeature' : DWORD
})
def hook_IsProcessorFeaturePresent(ql: Qiling, address: int, params):
    feature = params["ProcessorFeature"]

    if feature == PF_XSAVE_ENABLED:
        # it seems like unicorn can't recognize the instruction
        return 0

    return 1

# HANDLE CreateThread(
#   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
#   SIZE_T                  dwStackSize,
#   LPTHREAD_START_ROUTINE  lpStartAddress,
#   __drv_aliasesMem LPVOID lpParameter,
#   DWORD                   dwCreationFlags,
#   LPDWORD                 lpThreadId
# );
@winsdkapi(cc=STDCALL, params={
    'lpThreadAttributes' : LPSECURITY_ATTRIBUTES,
    'dwStackSize'        : SIZE_T,
    'lpStartAddress'     : LPTHREAD_START_ROUTINE,
    'lpParameter'        : LPVOID,
    'dwCreationFlags'    : DWORD,
    'lpThreadId'         : LPDWORD
})
def hook_CreateThread(ql: Qiling, address: int, params):
    CREATE_SUSPENDED = 0x00000004

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

    # set lpThreadId
    # FIXME: Temporary fix for the crash
    # if lpThreadId != 0:
    # ql.mem.write(lpThreadId, ql.pack(thread_id))

    # set thread handle
    return new_handle.id

# void ExitThread(
#   DWORD dwExitCode
# );
@winsdkapi(cc=STDCALL, params={
    'dwExitCode' : DWORD
})
def hook_ExitThread(ql: Qiling, address: int, params):
    #ql.emu_stop()
    pass

# HANDLE GetCurrentProcess(
# );
@winsdkapi(cc=STDCALL, params={})
def hook_GetCurrentProcess(ql: Qiling, address: int, params):
    # FIXME: should return handle, not pid
    return ql.os.profile.getint("KERNEL", "pid")

# BOOL TerminateProcess(
#   HANDLE hProcess,
#   UINT   uExitCode
# );
@winsdkapi(cc=STDCALL, params={
    'hProcess'  : HANDLE,
    'uExitCode' : UINT
})
def hook_TerminateProcess(ql: Qiling, address: int, params):
    # Samples will try to kill other process! We don't want to always stop!
    process = params["hProcess"]

    if process == ql.os.profile.getint("KERNEL", "pid"):  # or process == ql.os.image_address:
        ql.emu_stop()
        ql.os.PE_RUN = False

    return 1

# HANDLE GetCurrentThread();
@winsdkapi(cc=STDCALL, params={})
def hook_GetCurrentThread(ql: Qiling, address: int, params):
    return ql.os.thread_manager.cur_thread.id

# HANDLE OpenProcess(
#   DWORD dwDesiredAccess,
#   BOOL  bInheritHandle,
#   DWORD dwProcessId
# );
@winsdkapi(cc=STDCALL, params={
    'dwDesiredAccess' : DWORD,
    'bInheritHandle'  : BOOL,
    'dwProcessId'     : DWORD
})
def hook_OpenProcess(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle' : HANDLE,
    'DesiredAccess' : DWORD,
    'TokenHandle'   : PHANDLE
})
def hook_OpenProcessToken(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'hThread'   : HANDLE,
    'lpContext' : LPCONTEXT
})
def hook_GetThreadContext(ql: Qiling, address: int, params):
    return 1

# BOOL OpenThreadToken(
#   HANDLE  ThreadHandle,
#   DWORD   DesiredAccess,
#   BOOL    OpenAsSelf,
#   PHANDLE TokenHandle
# );
@winsdkapi(cc=STDCALL, params={
    'ThreadHandle'  : HANDLE,
    'DesiredAccess' : DWORD,
    'OpenAsSelf'    : BOOL,
    'TokenHandle'   : PHANDLE
})
def hook_OpenThreadToken(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'hThread'        : HANDLE,
    'lpCreationTime' : LPFILETIME,
    'lpExitTime'     : LPFILETIME,
    'lpKernelTime'   : LPFILETIME,
    'lpUserTime'     : LPFILETIME
})
def hook_GetThreadTimes(ql: Qiling, address: int, params):
    return 1

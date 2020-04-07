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
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.structs import *

# void Sleep(
#  DWORD dwMilliseconds
# );
@winapi(cc=STDCALL, params={
    "dwMilliseconds": DWORD
})
def hook_Sleep(ql, address, params):
    # time.sleep(params["dwMilliseconds"] * 10**(-3))
    pass


# void EnterCriticalSection(
#  LPCRITICAL_SECTION lpCriticalSection
# );
@winapi(cc=STDCALL, params={
    "lpCriticalSection": POINTER
})
def hook_EnterCriticalSection(ql, address, params):
    return 0


# void LeaveCriticalSection(
#  LPCRITICAL_SECTION lpCriticalSection
# );
@winapi(cc=STDCALL, params={
    "lpCriticalSection": POINTER
})
def hook_LeaveCriticalSection(ql, address, params):
    return 0


# void DeleteCriticalSection(
#   LPCRITICAL_SECTION lpCriticalSection
# );
@winapi(cc=STDCALL, params={
    "lpCriticalSection": POINTER
})
def hook_DeleteCriticalSection(ql, address, params):
    return 0


# void InitializeCriticalSection(
#   LPCRITICAL_SECTION lpCriticalSection
# );
@winapi(cc=STDCALL, params={
    "lpCriticalSection": POINTER,
})
def hook_InitializeCriticalSection(ql, address, params):
    return 1


# BOOL InitializeCriticalSectionEx(
#   LPCRITICAL_SECTION lpCriticalSection,
#   DWORD              dwSpinCount,
#   DWORD              Flags
# );
@winapi(cc=STDCALL, params={
    "lpCriticalSection": POINTER,
    "dwSpinCount": DWORD,
    "Flags": DWORD
})
def hook_InitializeCriticalSectionEx(ql, address, params):
    return 1


# BOOL InitializeCriticalSectionAndSpinCount(
#  LPCRITICAL_SECTION lpCriticalSection,
#  DWORD              dwSpinCount
# );
@winapi(cc=STDCALL, params={
    "lpCriticalSection": POINTER,
    "dwSpinCount": UINT
})
def hook_InitializeCriticalSectionAndSpinCount(ql, address, params):
    return 1


# DWORD WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD  dwMilliseconds
# );
@winapi(cc=STDCALL, params={
    "hHandle": HANDLE,
    "dwMilliseconds": DWORD
})
def hook_WaitForSingleObject(ql, address, params):
    ret = 0
    hHandle = params["hHandle"]
    dwMilliseconds = params["dwMilliseconds"]

    target_thread: Thread = ql.handle_manager.get(hHandle).thread
    if not target_thread.fake:
        ql.thread_manager.current_thread.waitfor(target_thread)

    return ret


# DWORD WaitForMultipleObjects(
#   DWORD        nCount,
#   const HANDLE *lpHandles,
#   BOOL         bWaitAll,
#   DWORD        dwMilliseconds
# );
@winapi(cc=STDCALL, params={
    "nCount": DWORD,
    "lpHandles": POINTER,
    "bWaitAll": BOOL,
    "dwMilliseconds": DWORD
})
def hook_WaitForMultipleObjects(ql, address, params):
    ret = 0
    nCount = params["nCount"]
    lpHandles = params["lpHandles"]
    bWaitAll = params["bWaitAll"]
    dwMilliseconds = params["dwMilliseconds"]

    for i in range(nCount):
        handle_value = ql.unpack(ql.mem.read(lpHandles + i * ql.pointersize, ql.pointersize))
        if handle_value != 0:
            thread = ql.handle_manager.get(handle_value).thread
            ql.thread_manager.current_thread.waitfor(thread)

    return ret


# HANDLE OpenMutexW(
#   DWORD   dwDesiredAccess,
#   BOOL    bInheritHandle,
#   LPCWSTR lpName
# );
@winapi(cc=STDCALL, params={
    "dwDesiredAccess": DWORD,
    "bInheritHandle": BOOL,
    "lpName": WSTRING
})
def hook_OpenMutexW(ql, address, params):
    type, name = params["lpName"].split("\\")
    # The name can have a "Global" or "Local" prefix to explicitly open an object in the global or session namespace.
    handle = ql.handle_manager.search(name)
    if type == "Global":
        # if is global is a Windows lock. We always return a valid handle because we have no way to emulate them
        # example sample: Gandcrab e42431d37561cc695de03b85e8e99c9e31321742
        if handle is None:
            return 0xD10C
        else:
            mutex = handle.mutex
            if mutex.isFree():
                mutex.lock()
            else:
                raise QlErrorNotImplemented("[!] API not implemented")
    else:
        if handle is None:
            # If a named mutex does not exist, the function fails and GetLastError returns ERROR_FILE_NOT_FOUND.
            ql.os.last_error  = ERROR_FILE_NOT_FOUND
            return 0
        else:
            raise QlErrorNotImplemented("[!] API not implemented")


# HANDLE CreateMutexW(
#   LPSECURITY_ATTRIBUTES lpMutexAttributes,
#   BOOL                  bInitialOwner,
#   LPCWSTR               lpName
# );
@winapi(cc=STDCALL, params={
    "lpMutexAttributes": POINTER,
    "bInitialOwner": BOOL,
    "lpName": WSTRING
})
def hook_CreateMutexW(ql, address, params):
    type, name = params["lpName"].split("\\")
    owning = params["bInitialOwner"]
    handle = ql.handle_manager.search(name)
    if handle is not None:
        ql.last_error = ERROR_ALREADY_EXISTS
        return 0
    else:
        mutex = Mutex(name, type)
        if owning:
            mutex.lock()
        handle = Handle(mutex=mutex, name=name)
        ql.handle_manager.append(handle)

    return handle.ID
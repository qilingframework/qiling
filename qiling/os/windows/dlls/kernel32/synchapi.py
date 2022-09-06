#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import Handle
from qiling.os.windows.structs import Mutex

# void Sleep(
#  DWORD dwMilliseconds
# );
@winsdkapi(cc=STDCALL, params={
    'dwMilliseconds' : DWORD
})
def hook_Sleep(ql: Qiling, address: int, params):
    # time.sleep(params["dwMilliseconds"] * 10**(-3))
    pass

# void EnterCriticalSection(
#  LPCRITICAL_SECTION lpCriticalSection
# );
@winsdkapi(cc=STDCALL, params={
    'lpCriticalSection' : LPCRITICAL_SECTION
})
def hook_EnterCriticalSection(ql: Qiling, address: int, params):
    return 0

# void LeaveCriticalSection(
#  LPCRITICAL_SECTION lpCriticalSection
# );
@winsdkapi(cc=STDCALL, params={
    'lpCriticalSection' : LPCRITICAL_SECTION
})
def hook_LeaveCriticalSection(ql: Qiling, address: int, params):
    return 0

# void DeleteCriticalSection(
#   LPCRITICAL_SECTION lpCriticalSection
# );
@winsdkapi(cc=STDCALL, params={
    'lpCriticalSection' : LPCRITICAL_SECTION
})
def hook_DeleteCriticalSection(ql: Qiling, address: int, params):
    return 0

# void InitializeCriticalSection(
#   LPCRITICAL_SECTION lpCriticalSection
# );
@winsdkapi(cc=STDCALL, params={
    'lpCriticalSection' : LPCRITICAL_SECTION
})
def hook_InitializeCriticalSection(ql: Qiling, address: int, params):
    return 1

# BOOL InitializeCriticalSectionEx(
#   LPCRITICAL_SECTION lpCriticalSection,
#   DWORD              dwSpinCount,
#   DWORD              Flags
# );
@winsdkapi(cc=STDCALL, params={
    'lpCriticalSection' : LPCRITICAL_SECTION,
    'dwSpinCount'       : DWORD,
    'Flags'             : DWORD
})
def hook_InitializeCriticalSectionEx(ql: Qiling, address: int, params):
    return 1

# BOOL InitializeCriticalSectionAndSpinCount(
#  LPCRITICAL_SECTION lpCriticalSection,
#  DWORD              dwSpinCount
# );
@winsdkapi(cc=STDCALL, params={
    'lpCriticalSection' : LPCRITICAL_SECTION,
    'dwSpinCount'       : DWORD
})
def hook_InitializeCriticalSectionAndSpinCount(ql: Qiling, address: int, params):
    return 1

# DWORD WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD  dwMilliseconds
# );
@winsdkapi(cc=STDCALL, params={
    'hHandle'        : HANDLE,
    'dwMilliseconds' : DWORD
})
def hook_WaitForSingleObject(ql: Qiling, address: int, params):
    hHandle = params["hHandle"]
    handle = ql.os.handle_manager.get(hHandle)

    if handle:
        target_thread = handle.obj
        ql.os.thread_manager.cur_thread.waitfor(target_thread)

    return 0

# DWORD WaitForSingleObjectEx(
#   HANDLE hHandle,
#   DWORD  dwMilliseconds
#   BOOL   bAlertable
# );
@winsdkapi(cc=STDCALL, params={
    'hHandle'        : HANDLE,
    'dwMilliseconds' : DWORD,
    'bAlertable'     : BOOL
})
def hook_WaitForSingleObjectEx(ql: Qiling, address: int, params):
    hHandle = params["hHandle"]
    handle = ql.os.handle_manager.get(hHandle)

    if handle:
        target_thread = handle.obj
        ql.os.thread_manager.cur_thread.waitfor(target_thread)

    return 0

# DWORD WaitForMultipleObjects(
#   DWORD        nCount,
#   const HANDLE *lpHandles,
#   BOOL         bWaitAll,
#   DWORD        dwMilliseconds
# );
@winsdkapi(cc=STDCALL, params={
    'nCount'         : DWORD,
    'lpHandles'      : HANDLE,
    'bWaitAll'       : BOOL,
    'dwMilliseconds' : DWORD
})
def hook_WaitForMultipleObjects(ql: Qiling, address: int, params):
    nCount = params["nCount"]
    lpHandles = params["lpHandles"]

    for i in range(nCount):
        handle_value = ql.unpack(ql.mem.read(lpHandles + i * ql.pointersize, ql.pointersize))

        if handle_value:
            thread = ql.os.handle_manager.get(handle_value).obj
            ql.os.thread_manager.cur_thread.waitfor(thread)

    return 0

def __OpenMutex(ql: Qiling, address: int, params):
    # The name can have a "Global" or "Local" prefix to explicitly open an object in the global or session namespace.
    # It can also have no prefix
    try:
        _type, name = params["lpName"].split("\\")
    except ValueError:
        name = params["lpName"]
        _type = ""

    handle = ql.os.handle_manager.search(name)
    if _type == "Global":
        # if is global is a Windows lock. We always return a valid handle because we have no way to emulate them
        # example sample: Gandcrab e42431d37561cc695de03b85e8e99c9e31321742
        if handle is None:
            return 0xD10C

        mutex = handle.obj

        if mutex.isFree():
            mutex.lock()
        else:
            raise QlErrorNotImplemented("API not implemented")
    else:
        if handle is None:
            # If a named mutex does not exist, the function fails and GetLastError returns ERROR_FILE_NOT_FOUND.
            ql.os.last_error = ERROR_FILE_NOT_FOUND
            return 0

        raise QlErrorNotImplemented("API not implemented")

def __CreateMutex(ql: Qiling, address: int, params):
    try:
        _type, name = params["lpName"].split("\\")
    except ValueError:
        name = params["lpName"]
        _type = ""

    handle = ql.os.handle_manager.search(name)

    if handle is not None:
        # ql.os.last_error = ERROR_ALREADY_EXISTS
        return 0

    owning = params["bInitialOwner"]
    mutex = Mutex(name, _type)

    if owning:
        mutex.lock()

    handle = Handle(obj=mutex, name=name)
    ql.os.handle_manager.append(handle)

    return handle.id

# HANDLE OpenMutexW(
#   DWORD   dwDesiredAccess,
#   BOOL    bInheritHandle,
#   LPCWSTR lpName
# );
@winsdkapi(cc=STDCALL, params={
    'dwDesiredAccess' : DWORD,
    'bInheritHandle'  : BOOL,
    'lpName'          : LPCWSTR
})
def hook_OpenMutexW(ql: Qiling, address: int, params):
    return __OpenMutex(ql, address, params)

# HANDLE OpenMutexA(
#   DWORD   dwDesiredAccess,
#   BOOL    bInheritHandle,
#   LPCSTR lpName
# );
@winsdkapi(cc=STDCALL, params={
    'dwDesiredAccess' : DWORD,
    'bInheritHandle'  : BOOL,
    'lpName'          : LPCSTR
})
def hook_OpenMutexA(ql: Qiling, address: int, params):
    return __OpenMutex(ql, address, params)

# HANDLE CreateMutexW(
#   LPSECURITY_ATTRIBUTES lpMutexAttributes,
#   BOOL                  bInitialOwner,
#   LPCWSTR               lpName
# );
@winsdkapi(cc=STDCALL, params={
    'lpMutexAttributes' : LPSECURITY_ATTRIBUTES,
    'bInitialOwner'     : BOOL,
    'lpName'            : LPCWSTR
})
def hook_CreateMutexW(ql: Qiling, address: int, params):
    return __CreateMutex(ql, address, params)

# HANDLE CreateMutexA(
#   LPSECURITY_ATTRIBUTES lpMutexAttributes,
#   BOOL                  bInitialOwner,
#   LPCSTR               lpName
# );
@winsdkapi(cc=STDCALL, params={
    'lpMutexAttributes' : LPSECURITY_ATTRIBUTES,
    'bInitialOwner'     : BOOL,
    'lpName'            : LPCSTR
})
def hook_CreateMutexA(ql: Qiling, address: int, params):
    return __CreateMutex(ql, address, params)

# BOOL ReleaseMutex(
#   HANDLE hMutex
# );
@winsdkapi(cc=STDCALL, params={
    'hMutex' : HANDLE
})
def hook_ReleaseMutex(ql: Qiling, address: int, params):
    hMutex = params["hMutex"]
    handle = ql.os.handle_manager.get(hMutex)

    if not handle:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0

    mutex = handle.obj

    if not mutex or not isinstance(mutex, Mutex):
        return 0

    if mutex.isFree():
        ql.os.last_error = ERROR_NOT_OWNER
        return 0

    # FIXME: Only the owner is allowed to do this!
    mutex.unlock()
    return 1

def __CreateEvent(ql: Qiling, address: int, params):
    # Implementation seems similar enough to Mutex to just use it

    try:
        namespace, name = params["lpName"].split("\\")
    except ValueError:
        name = params["lpName"]
        namespace = ""

    handle = ql.os.handle_manager.search(name)

    if handle is not None:
        ql.os.last_error = ERROR_ALREADY_EXISTS
        # FIXME: fail with a nullptr?
        # return 0
    else:
        mutex = Mutex(name, namespace)

        if params['bInitialState']:
            mutex.lock()

        handle = Handle(obj=mutex, name=name)
        ql.os.handle_manager.append(handle)

    # FIXME: shouldn't it be 'id' instead of 'ID'?
    return handle.ID

# HANDLE CreateEventA(
#  LPSECURITY_ATTRIBUTES lpEventAttributes,
#  BOOL                  bManualReset,
#  BOOL                  bInitialState,
#  LPCSTR                lpName
# );
@winsdkapi(cc=STDCALL, params={
    'lpEventAttributes' : LPSECURITY_ATTRIBUTES,
    'bManualReset'      : BOOL,
    'bInitialState'     : BOOL,
    'lpName'            : LPCSTR
})
def hook_CreateEventA(ql: Qiling, address: int, params):
    return __CreateEvent(ql, address, params)

# HANDLE CreateEventW(
#  LPSECURITY_ATTRIBUTES lpEventAttributes,
#  BOOL                  bManualReset,
#  BOOL                  bInitialState,
#  LPCWSTR               lpName
# );
@winsdkapi(cc=STDCALL, params={
    'lpEventAttributes' : LPSECURITY_ATTRIBUTES,
    'bManualReset'      : BOOL,
    'bInitialState'     : BOOL,
    'lpName'            : LPCWSTR
})
def hook_CreateEventW(ql: Qiling, address: int, params):
    return __CreateEvent(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_TryAcquireSRWLockExclusive(ql: Qiling, address: int, params):
    pass

@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_TryAcquireSRWLockShared(ql: Qiling, address: int, params):
    pass

# void InitializeSRWLock(
#  PSRWLOCK SRWLock
# );
@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_InitializeSRWLock(ql: Qiling, address: int, params):
    return

# void AcquireSRWLockExclusive(
#   PSRWLOCK SRWLock
# );
@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_AcquireSRWLockExclusive(ql: Qiling, address: int, params):
   return

# void AcquireSRWLockShared(
#   PSRWLOCK SRWLock
# );
@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_AcquireSRWLockShared(ql: Qiling, address: int, params):
    return

# void ReleaseSRWLockExclusive(
#   PSRWLOCK SRWLock
# );
@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_ReleaseSRWLockExclusive(ql: Qiling, address: int, params):
    return

# void ReleaseSRWLockShared(
#   PSRWLOCK SRWLock
# );
@winsdkapi(cc=STDCALL, params={
    'SRWLock' : PSRWLOCK
})
def hook_ReleaseSRWLockShared(ql: Qiling, address: int, params):
    return

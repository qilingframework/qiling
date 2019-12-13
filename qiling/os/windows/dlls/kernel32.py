#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
import time
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

#void Sleep(
#  DWORD dwMilliseconds
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "dwMilliseconds": DWORD
})
def hook_Sleep(ql, address, params):
    #time.sleep(params["dwMilliseconds"] * 10**(-3))
    pass

# LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
#   LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpTopLevelExceptionFilter": DWORD
})
def hook_SetUnhandledExceptionFilter(ql, address, params):
    ret = 0x4
    return ret


# void ExitProcess(
#   UINT uExitCode
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "uExitCode": DWORD
})
def hook_ExitProcess(ql, address, params):
    ql.uc.emu_stop()
    ql.RUN = False


# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "ExitCode": INT
})
def hook_FatalExit(ql, address, params):
    ql.uc.emu_stop()
    ql.RUN = False


# VOID WINAPI GetStartupInfo(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoA(ql, address, params):
    pass


# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpModuleName": STRING
})
def hook_GetModuleHandleA(ql, address, params):
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        if not lpModuleName.lower().endswith('.dll'):
            lpModuleName += '.dll'
        if lpModuleName.lower() in ql.PE.dlls:
            ret = ql.PE.dlls[lpModuleName.lower()]
        else:
            ret = 0
    return ret


# HMODULE GetModuleHandleW(
#   LPCWSTR lpModuleName
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpModuleName": WSTRING
})
def hook_GetModuleHandleW(ql, address, params):
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        lpModuleName = bytes(lpModuleName, "ascii").decode('utf-16le')
        if not lpModuleName.lower().endswith('.dll'):
            lpModuleName += '.dll'
        if lpModuleName.lower() in ql.PE.dlls:
            ret = ql.PE.dlls[lpModuleName.lower()]
        else:
            ret = 0
    return ret


# UINT WinExec(
#   LPCSTR lpCmdLine,
#   UINT   uCmdShow
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpCmdLine": STRING,
    "uCmdShow": UINT
})
def hook_WinExec(ql, address, params):
    return 33


# NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetVersion(ql, address, params):
    ret = 0x0004
    ret = ret << 16
    ret = ret | 0x0004
    return ret


# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "flOptions": DWORD,
    "dwInitialSize": SIZE_T,
    "dwMaximumSize": SIZE_T
})
def hook_HeapCreate(ql, address, params):
    dwInitialSize = params["dwInitialSize"]
    addr = ql.heap.mem_alloc(dwInitialSize)
    return addr


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
#   LPOSVERSIONINFOA lpVersionInformation
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpVersionInformation": POINTER
})
def hook_GetVersionExA(ql, address, params):
    ret = 1
    return ret


# DWORD GetEnvironmentVariableA(
#   LPCSTR lpName,
#   LPSTR  lpBuffer,
#   DWORD  nSize
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpName": STRING,
    "lpBuffer": POINTER,
    "nSize": DWORD
})
def hook_GetEnvironmentVariableA(ql, address, params):
    ret = 0
    return ret


# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hHeap": HANDLE,
    "dwFlags": DWORD,
    "dwBytes": SIZE_T
})
def hook_HeapAlloc(ql, address, params):
    ret = ql.heap.mem_alloc(params["dwBytes"])
    return ret


# LPVOID VirtualAlloc(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  flAllocationType,
#   DWORD  flProtect
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpAddress": POINTER,
    "dwSize": SIZE_T,
    "flAllocationType": DWORD,
    "flProtect": DWORD
})
def hook_VirtualAlloc(ql, address, params):
    dwSize = params["dwSize"]
    addr = ql.heap.mem_alloc(dwSize)
    return addr


# BOOL VirtualFree(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  dwFreeType
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpAddress": POINTER,
    "dwSize": SIZE_T,
    "dwFreeType": DWORD
})
def hook_VirtualFree(ql, address, params):
    lpAddress = params["lpAddress"]
    addr = ql.heap.mem_free(lpAddress)
    return 1


# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "nStdHandle": DWORD
})
def hook_GetStdHandle(ql, address, params):
    nStdHandle = params["nStdHandle"]
    return nStdHandle


# DWORD GetFileType(
#   HANDLE hFile
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hFile": HANDLE
})
def hook_GetFileType(ql, address, params):
    hFile = params["hFile"]
    FILE_TYPE_CHAR = 0x0002
    if hFile == STD_INPUT_HANDLE or hFile == STD_OUTPUT_HANDLE or hFile == STD_ERROR_HANDLE:
        ret = FILE_TYPE_CHAR
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return ret


# UINT SetHandleCount(
#   UINT uNumber
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "uNumber": UINT
})
def hook_SetHandleCount(ql, address, params):
    uNumber = params["uNumber"]
    return uNumber


# LPSTR GetCommandLineA(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetCommandLineA(ql, address, params):
    cmdline = ql.PE.cmdline + b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStrings(
# );s
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetEnvironmentStrings(ql, address, params):
    cmdline = b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# UINT GetACP(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetACP(ql, address, params):
    ret = 437
    return ret


# BOOL GetCPInfo(
#   UINT     CodePage,
#   LPCPINFO lpCPInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "CodePage": UINT,
    "lpCPInfo": POINTER
})
def hook_GetCPInfo(ql, address, params):
    ret = 1
    return ret


# BOOL GetStringTypeW(
#   DWORD                         dwInfoType,
#   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
#   int                           cchSrc,
#   LPWORD                        lpCharType
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "dwInfoType": DWORD,
    "lpSrcStr": POINTER,
    "cchSrc": INT,
    "lpCharType": POINTER
})
def hook_GetStringTypeW(ql, address, params):
    ret = 0
    return ret


#  BOOL GetStringTypeExA
#  (
#   LCID   locale,
#   DWORD  type,
#   LPCSTR src,
#   INT    count,
#   LPWORD chartype
#  )
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "locale": POINTER,
    "type": DWORD,
    "src": STRING,
    "count": INT,
    "chartype": POINTER
})
def hook_GetStringTypeExA(ql, address, params):
    ret = 0
    return ret


# LPWCH GetEnvironmentStringsW(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetEnvironmentStringsW(ql, address, params):
    cmdline = b"\x00\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# int WideCharToMultiByte(
#   UINT                               CodePage,
#   DWORD                              dwFlags,
#   _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
#   int                                cchWideChar,
#   LPSTR                              lpMultiByteStr,
#   int                                cbMultiByte,
#   LPCCH                              lpDefaultChar,
#   LPBOOL                             lpUsedDefaultChar
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "CodePage": UINT,
    "dwFlags": DWORD,
    "lpWideCharStr": WSTRING,
    "cchWideChar": INT,
    "lpMultiByteStr": POINTER,
    "cbMultiByte": INT,
    "lpDefaultChar": POINTER,
    "lpUsedDefaultChar": POINTER
})
def hook_WideCharToMultiByte(ql, address, params):
    ret = 0

    cbMultiByte = params["cbMultiByte"]
    s_lpWideCharStr = params["lpWideCharStr"]
    lpMultiByteStr = params["lpMultiByteStr"]

    if cbMultiByte == 0:
        ret = len(s_lpWideCharStr) + 2
        ret = align(ret // 2, 2)
    else:
        s = bytes(s_lpWideCharStr, 'ascii').decode('utf-16le') + "\x00"
        ql.uc.mem_write(lpMultiByteStr, bytes(s, 'ascii'))
        ret = len(s)

    return ret


# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "penv": POINTER
})
def hook_FreeEnvironmentStringsW(ql, address, params):
    ret = 1
    return ret


# int LCMapStringW(
#   LCID    Locale,
#   DWORD   dwMapFlags,
#   LPCWSTR lpSrcStr,
#   int     cchSrc,
#   LPWSTR  lpDestStr,
#   int     cchDest
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "Locale": POINTER,
    "dwMapFlags": DWORD,
    "lpSrcStr": WSTRING,
    "cchSrc": INT,
    "lpDestStr": POINTER,
    "cchDest": INT
})
def hook_LCMapStringW(ql, address, params):
    ret = 0
    return ret


# int LCMapStringA(
#   LCID   Locale,
#   DWORD  dwMapFlags,
#   LPCSTR lpSrcStr,
#   int    cchSrc,
#   LPSTR  lpDestStr,
#   int    cchDest
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "Locale": POINTER,
    "dwMapFlags": DWORD,
    "lpSrcStr": WSTRING,
    "cchSrc": INT,
    "lpDestStr": POINTER,
    "cchDest": INT
})
def hook_LCMapStringA(ql, address, params):
    ret = 0
    return ret


# DWORD GetModuleFileNameA(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hModule": HANDLE,
    "lpFilename": POINTER,
    "nSize": DWORD
})
def hook_GetModuleFileNameA(ql, address, params):
    ret = 0
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]
    if hModule == 0:
        filename = ql.PE.filepath
        filename_len = len(filename)
        if filename_len > nSize-1:
            filename = ql.PE.filepath[:nSize-1]
            ret = nSize
        else:
            ret = filename_len
        ql.uc.mem_write(lpFilename, filename + b"\x00")
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return ret


# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hFile": HANDLE,
    "lpBuffer": POINTER,
    "nNumberOfBytesToRead": DWORD,
    "lpNumberOfBytesRead": POINTER,
    "lpOverlapped": POINTER
})
def hook_ReadFile(ql, address, params):
    ret = 1
    hFile = params["hFile"]    
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToRead = params["nNumberOfBytesToRead"]
    lpNumberOfBytesRead = params["lpNumberOfBytesRead"]
    lpOverlapped = params["lpOverlapped"]
    if hFile == STD_INPUT_HANDLE:
        s = ql.stdin.read(nNumberOfBytesToRead)
        slen = len(s)
        read_len = slen
        if slen > nNumberOfBytesToRead:
            s = s[:nNumberOfBytesToRead]
            read_len = nNumberOfBytesToRead
        ql.uc.mem_write(lpBuffer, s)
        ql.uc.mem_write(lpNumberOfBytesRead, ql.pack(read_len))
    else:
        f = ql.handle_manager.get(hFile).file
        data = f.read(nNumberOfBytesToRead)
        ql.uc.mem_write(lpBuffer, data)
        ql.uc.mem_write(lpNumberOfBytesRead, ql.pack32(lpNumberOfBytesRead))
    return ret


# BOOL WriteFile(
#   HANDLE       hFile,
#   LPCVOID      lpBuffer,
#   DWORD        nNumberOfBytesToWrite,
#   LPDWORD      lpNumberOfBytesWritten,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hFile": HANDLE,
    "lpBuffer": POINTER,
    "nNumberOfBytesToWrite": DWORD,
    "lpNumberOfBytesWritten": POINTER,
    "lpOverlapped": POINTER
})
def hook_WriteFile(ql, address, params):
    ret = 1
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
    lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
    lpOverlapped = params["lpOverlapped"]
    if hFile == STD_OUTPUT_HANDLE:
        s = ql.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
        ql.stdout.write(s)
        ql.uc.mem_write(lpNumberOfBytesWritten, ql.pack(nNumberOfBytesToWrite))
    else:
        try:
            f = ql.handle_manager.get(hFile).file
        except KeyError as ke:
            #Invalid handle
            ql.last_error = 0x6 #ERROR_INVALID_HANDLE
            return 0
        buffer = ql.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
        f.write(bytes(buffer))
        ql.uc.mem_write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
    return ret


def _CreateFile(ql, address, params, name):
    ret = INVALID_HANDLE_VALUE

    s_lpFileName = params["lpFileName"]
    dwDesiredAccess = params["dwDesiredAccess"]
    dwShareMode = params["dwShareMode"]
    lpSecurityAttributes = params["lpSecurityAttributes"]
    dwCreationDisposition = params["dwCreationDisposition"]
    dwFlagsAndAttributes = params["dwFlagsAndAttributes"]
    hTemplateFile = params["hTemplateFile"]

    # access mask DesiredAccess
    mode = ""
    if dwDesiredAccess & GENERIC_WRITE:
        mode += "wb"
    else:
        mode += "r"

    # create thread handle
    f = open(os.path.join(ql.rootfs, s_lpFileName.replace("\\", os.sep)), mode)
    new_handle = Handle(file=f)
    ql.handle_manager.append(new_handle)
    ret = new_handle.id

    return ret


# HANDLE CreateFileA(
#   LPCSTR                lpFileName,
#   DWORD                 dwDesiredAccess,
#   DWORD                 dwShareMode,
#   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   DWORD                 dwCreationDisposition,
#   DWORD                 dwFlagsAndAttributes,
#   HANDLE                hTemplateFile
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpFileName": STRING,
    "dwDesiredAccess": DWORD,
    "dwShareMode": DWORD,
    "lpSecurityAttributes": POINTER,
    "dwCreationDisposition": DWORD,
    "dwFlagsAndAttributes": DWORD,
    "hTemplateFile": HANDLE
})
def hook_CreateFileA(ql, address, params):
    ret = _CreateFile(ql, address, params, "CreateFileA")
    return ret


@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpFileName": WSTRING,
    "dwDesiredAccess": DWORD,
    "dwShareMode": DWORD,
    "lpSecurityAttributes": POINTER,
    "dwCreationDisposition": DWORD,
    "dwFlagsAndAttributes": DWORD,
    "hTemplateFile": HANDLE
})
def hook_CreateFileW(ql, address, params):
    ret = _CreateFile(ql, address, params, "CreateFileW")
    return ret


# void GetSystemTimeAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpSystemTimeAsFileTime": POINTER
})
def hook_GetSystemTimeAsFileTime(ql, address, params):
    pass


# DWORD GetCurrentThreadId(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetCurrentThreadId(ql, address, params):
    ret = ql.thread_manager.current_thread.id
    return ret


# DWORD GetCurrentProcessId(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetCurrentProcessId(ql, address, params):
    ret = 1000
    return ret


# BOOL QueryPerformanceCounter(
#   LARGE_INTEGER *lpPerformanceCount
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpPerformanceCount": POINTER
})
def hook_QueryPerformanceCounter(ql, address, params):
    ret = 0
    return ret


# BOOL IsProcessorFeaturePresent(
#   DWORD ProcessorFeature
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "ProcessorFeature": DWORD
})
def hook_IsProcessorFeaturePresent(ql, address, params):
    ret = 0
    return ret


# HANDLE CreateThread(
#   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
#   SIZE_T                  dwStackSize,
#   LPTHREAD_START_ROUTINE  lpStartAddress,
#   __drv_aliasesMem LPVOID lpParameter,
#   DWORD                   dwCreationFlags,
#   LPDWORD                 lpThreadId
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
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
    new_thread = Thread(ql)

    if dwCreationFlags & CREATE_SUSPENDED == CREATE_SUSPENDED:
        thread_status = Thread.READY
    else:
        thread_status = Thread.RUNNING

    # create new thread
    thread_id = new_thread.create(
        lpStartAddress,
        lpParameter,
        thread_status
    )

    # append the new thread to ThreadManager
    ql.thread_manager.append(new_thread)

    # create thread handle
    new_handle = Handle(thread=new_thread)
    ql.handle_manager.append(new_handle)
    ret = new_handle.id

    # set lpThreadId
    if lpThreadId != 0:
        ql.mem_write(lpThreadId, ql.pack(thread_id))

    # set thread handle
    return ret


# DWORD WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD  dwMilliseconds
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hHandle": HANDLE,
    "dwMilliseconds": DWORD
})
def hook_WaitForSingleObject(ql, address, params):
    ret = 0
    hHandle = params["hHandle"]
    dwMilliseconds = params["dwMilliseconds"]
    target_thread = ql.handle_manager.get(hHandle).thread
    ql.thread_manager.current_thread.waitfor(target_thread)
    return ret


# DWORD WaitForMultipleObjects(
#   DWORD        nCount,
#   const HANDLE *lpHandles,
#   BOOL         bWaitAll,
#   DWORD        dwMilliseconds
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
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
        handle_value = ql.unpack(ql.mem_read(lpHandles + i * ql.pointersize, ql.pointersize))
        if handle_value != 0:
            thread = ql.handle_manager.get(handle_value).thread
            ql.thread_manager.current_thread.waitfor(thread)

    return ret


# BOOL CloseHandle(
#   HANDLE hObject
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hObject": HANDLE
})
def hook_CloseHandle(ql, address, params):
    ret = 0
    return ret


# DWORD GetTickCount(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetTickCount(ql, address, params):
    ret = 200000
    return ret


# NTSYSAPI ULONGLONG VerSetConditionMask(
#   ULONGLONG ConditionMask, => 64bit param
#   DWORD     TypeMask,
#   BYTE      Condition
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "ConditionMask": ULONGLONG,
    "TypeMask": DWORD,
    "Condition": BYTE
})
def hook_VerSetConditionMask(ql, address, params):    
    ConditionMask = params["ConditionMask"]
    TypeMask = params["TypeMask"]
    Condition = params["Condition"]
    if (TypeMask == 0):
        ret = ConditionMask
    else:
        Condition &= VER_CONDITION_MASK
        if (Condition == 0):
            ret = ConditionMask
        else:
            ullCondMask = Condition
            if (TypeMask & VER_PRODUCT_TYPE):
                ConditionMask |= ullCondMask << (7 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_SUITENAME):
                ConditionMask |= ullCondMask << (6 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_SERVICEPACKMAJOR):
                ConditionMask |= ullCondMask << (5 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_SERVICEPACKMINOR):
                ConditionMask |= ullCondMask << (4 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_PLATFORMID):
                ConditionMask |= ullCondMask << (3 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_BUILDNUMBER):
                ConditionMask |= ullCondMask << (2 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_MAJORVERSION):
                ConditionMask |= ullCondMask << (1 * VER_NUM_BITS_PER_CONDITION_MASK)
            elif (TypeMask & VER_MINORVERSION):
                ConditionMask |= ullCondMask << (0 * VER_NUM_BITS_PER_CONDITION_MASK)
            ret = ConditionMask
    return ret


# HANDLE GetProcessHeap(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetProcessHeap(ql, address, params):
    ret = ql.heap.start_address
    return ret


# LONG UnhandledExceptionFilter(
#   _EXCEPTION_POINTERS *ExceptionInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "ExceptionInfo": POINTER
})
def hook_UnhandledExceptionFilter(ql, address, params):
    ret = 1 
    return ret


# BOOL TerminateProcess(
#   HANDLE hProcess,
#   UINT   uExitCode
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hProcess": HANDLE,
    "uExitCode": UINT
})
def hook_TerminateProcess(ql, address, params):
    ret = 1 
    ql.uc.emu_stop()
    ql.RUN = False
    return ret


# HANDLE GetCurrentProcess(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetCurrentProcess(ql, address, params):
    ret = 1
    return ret


# HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpLibFileName": STRING
})
def hook_LoadLibraryA(ql, address, params):
    lpLibFileName = params["lpLibFileName"]
    dll_base = ql.PE.load_dll(lpLibFileName.encode())
    return dll_base


# HMODULE LoadLibraryExA(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpLibFileName": STRING,
    "hFile": POINTER,
    "dwFlags": DWORD
})
def hook_LoadLibraryExA(ql, address, params):
    lpLibFileName = params["lpLibFileName"]
    dll_base = ql.PE.load_dll(lpLibFileName.encode())
    return dll_base


# HMODULE LoadLibraryW(
#   LPCWSTR lpLibFileName
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpLibFileName": WSTRING
})
def hook_LoadLibraryW(ql, address, params):
    lpLibFileName = bytes(params["lpLibFileName"], 'ascii')
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base


# HMODULE LoadLibraryExW(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpLibFileName": WSTRING,
    "hFile": POINTER,
    "dwFlags": DWORD
})
def hook_LoadLibraryExW(ql, address, params):
    lpLibFileName = bytes(params["lpLibFileName"], 'ascii')
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base


# FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hModule": POINTER,
    "lpProcName": STRING
})
def hook_GetProcAddress(ql, address, params):
    lpProcName = bytes(params["lpProcName"], 'ascii')

    #Check if dll is loaded
    try:
        dll_name = [key for key, value in ql.PE.dlls.items() if value == params['hModule']][0]
    except IndexError as ie:
        ql.nprint('[!] Failed to import function "%s" with handle 0x%X' % (lpProcName, params['hModule']))
        return 0

    if lpProcName in ql.PE.import_address_table[dll_name]:
        return ql.PE.import_address_table[dll_name][lpProcName]

    return 0

#LPVOID GlobalLock(
#  HGLOBAL hMem
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hMem": POINTER
})
def hook_GlobalLock(ql, address, params):
    return params['hMem']

#LPVOID GlobalUnlock(
#  HGLOBAL hMem
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "hMem": POINTER
})
def hook_GlobalUnlock(ql, address, params):
    return 1

#DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
#  UINT   uFlags,
#  SIZE_T dwBytes
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "uFlags": UINT,
    "dwBytes": UINT
})
def hook_GlobalAlloc(ql, address, params):
    return ql.heap.mem_alloc(params['dwBytes'])

#BOOL InitializeCriticalSectionAndSpinCount(
#  LPCRITICAL_SECTION lpCriticalSection,
#  DWORD              dwSpinCount
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpCriticalSection": POINTER,
    "dwSpinCount": UINT
})
def hook_InitializeCriticalSectionAndSpinCount(ql, address, params):
    return 1

#DWORD TlsAlloc();
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_TlsAlloc(ql, address, params):
    idx = ql.thread_manager.current_thread.tls_index 
    ql.thread_manager.current_thread.tls_index += 1
    ql.thread_manager.current_thread.tls[idx] = 0
    return idx

#DWORD TlsFree(
#  DWORD dwTlsIndex
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "dwTlsIndex": UINT
})
def hook_TlsFree(ql, address, params):
    idx = params['dwTlsIndex']
    if idx not in ql.thread_manager.current_thread.tls:
        ql.last_error = 0x57 #(ERROR_INVALID_PARAMETER)
        return 0
    else:
        del(ql.thread_manager.current_thread.tls[idx])
        return 1

#LPVOID TlsGetValue(
#  DWORD dwTlsIndex
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "dwTlsIndex": UINT})
def hook_TlsGetValue(ql, address, params):
    idx = params['dwTlsIndex']
    if idx not in ql.thread_manager.current_thread.tls:
        ql.last_error = 0x57 #(ERROR_INVALID_PARAMETER)
        return 0
    else:   
        # api explicity clears last error on success:
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue
        ql.last_error = 0 
        return ql.thread_manager.current_thread.tls[idx]

#LPVOID TlsSetValue(
#  DWORD dwTlsIndex
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "dwTlsIndex": UINT,
    "lpTlsValue": POINTER
})
def hook_TlsSetValue(ql, address, params):
    idx = params['dwTlsIndex']
    if idx not in ql.thread_manager.current_thread.tls:
        ql.last_error = 0x57 #(ERROR_INVALID_PARAMETER)
        return 0
    else:   
        ql.thread_manager.current_thread.tls[idx] = params['lpTlsValue']
        return 1

#BOOL VirtualProtect(
#  LPVOID lpAddress,
#  SIZE_T dwSize,
#  DWORD  flNewProtect,
#  PDWORD lpflOldProtect
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "lpAddress": POINTER,
    "dwSize": UINT,
    "flNewProtect": UINT,
    "lpflOldProtect": POINTER
})
def hook_VirtualProtect(ql, address, params):
    return 1

#_Post_equals_last_error_ DWORD GetLastError();
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_GetLastError(ql, address, params):
    return ql.last_error

#void EnterCriticalSection(
#  LPCRITICAL_SECTION lpCriticalSection
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={})
def hook_EnterCriticalSection(ql, address, params):
    return 0

#int MultiByteToWideChar(
#  UINT                              CodePage,
#  DWORD                             dwFlags,
#  _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
#  int                               cbMultiByte,
#  LPWSTR                            lpWideCharStr,
#  int                               cchWideChar
#);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "CodePage": UINT,
    "dwFlags": UINT,
    "lpMultiByteStr": STRING,
    "cbMultiByte": INT,
    "lpWideCharStr": POINTER,
    "cchWideChar": INT
})
def hook_MultiByteToWideChar(ql, address, params):
    wide_str = params['lpMultiByteStr'].encode('utf-16le')
    if params['cchWideChar'] != 0:
        ql.uc.mem_write(params['lpWideCharStr'], wide_str) 
    return len(wide_str)

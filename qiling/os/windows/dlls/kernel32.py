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
from qiling.os.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

#void Sleep(
#  DWORD dwMilliseconds
#);
@winapi(cc=STDCALL, params={
    "dwMilliseconds": DWORD
})
def hook_Sleep(ql, address, params):
    #time.sleep(params["dwMilliseconds"] * 10**(-3))
    pass

# LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
#   LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
# );
@winapi(cc=STDCALL, params={
    "lpTopLevelExceptionFilter": DWORD
})
def hook_SetUnhandledExceptionFilter(ql, address, params):
    ret = 0x4
    return ret


# void ExitProcess(
#   UINT uExitCode
# );
@winapi(cc=STDCALL, params={
    "uExitCode": DWORD
})
def hook_ExitProcess(ql, address, params):
    ql.uc.emu_stop()
    ql.RUN = False


# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );
@winapi(cc=STDCALL, params={
    "ExitCode": INT
})
def hook_FatalExit(ql, address, params):
    ql.uc.emu_stop()
    ql.RUN = False


# VOID WINAPI GetStartupInfo(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
"""
typedef struct _STARTUPINFO {
  DWORD  cb;
  LPTSTR lpReserved;
  LPTSTR lpDesktop;
  LPTSTR lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFO, *LPSTARTUPINFO;
"""


# VOID WINAPI GetStartupInfoA(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(cc=STDCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoA(ql, address, params):
    # TODO fill in std output handles.
    # Seems to work fine without them so far though
    pointer = params["lpStartupInfo"]
    size = 52 + 4 * ql.pointersize
    dwordsize = 4
    wordsize = 2
    cb = 0x44.to_bytes(length=dwordsize, byteorder='little')
    lpReserved = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    lpDesktop = 0xc3c930.to_bytes(length=ql.pointersize, byteorder='little')
    lpTitle = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    dwX = 0x0.to_bytes(length=dwordsize, byteorder='little')
    dwY = 0x0.to_bytes(length=dwordsize, byteorder='little')
    dwXSize = 0x64.to_bytes(length=dwordsize, byteorder='little')
    dwYSize = 0x64.to_bytes(length=dwordsize, byteorder='little')
    dwXCountChars = 0x84.to_bytes(length=dwordsize, byteorder='little')
    dwYCountChars = 0x80.to_bytes(length=dwordsize, byteorder='little')
    dwFillAttribute = 0xff.to_bytes(length=dwordsize, byteorder='little')
    dwFlags = 0x40.to_bytes(length=dwordsize, byteorder='little')
    wShowWindow = 0x1.to_bytes(length=wordsize, byteorder='little')
    cbReserved2 = 0x0.to_bytes(length=wordsize, byteorder='little')
    lpReserved2 = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    hStdInput = 0xffffffff.to_bytes(length=dwordsize, byteorder='little')
    hStdOutput = 0xffffffff.to_bytes(length=dwordsize, byteorder='little')
    hStdError = 0xffffffff.to_bytes(length=dwordsize, byteorder='little')
    dummy_content = cb + lpReserved + lpDesktop + lpTitle + dwX + dwY + dwXSize + dwYSize + dwXCountChars + dwYCountChars + dwFillAttribute + dwFlags + wShowWindow + cbReserved2 + lpReserved2 + hStdInput + hStdOutput + hStdError
    # addr = ql.heap.mem_alloc(size)

    assert (len(dummy_content) == size == 0x44)
    ql.uc.mem_write(pointer, dummy_content)
    return 0


# VOID WINAPI GetStartupInfoW(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(cc=STDCALL, params={
    "lpStartupInfo": POINTER
})
def hook_GetStartupInfoW(ql, address, params):
    pointer = params["lpStartupInfo"]
    size = 52 + 4 * ql.pointersize
    dwordsize = 4
    wordsize = 2
    cb = 0x44.to_bytes(length=dwordsize, byteorder='little')
    lpReserved = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    lpDesktop = 0xc3c930.to_bytes(length=ql.pointersize, byteorder='little')
    lpTitle = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    dwX = 0x0.to_bytes(length=dwordsize, byteorder='little')
    dwY = 0x0.to_bytes(length=dwordsize, byteorder='little')
    dwXSize = 0x64.to_bytes(length=dwordsize, byteorder='little')
    dwYSize = 0x64.to_bytes(length=dwordsize, byteorder='little')
    dwXCountChars = 0x84.to_bytes(length=dwordsize, byteorder='little')
    dwYCountChars = 0x80.to_bytes(length=dwordsize, byteorder='little')
    dwFillAttribute = 0xff.to_bytes(length=dwordsize, byteorder='little')
    dwFlags = 0x40.to_bytes(length=dwordsize, byteorder='little')
    wShowWindow = 0x1.to_bytes(length=wordsize, byteorder='little')
    cbReserved2 = 0x0.to_bytes(length=wordsize, byteorder='little')
    lpReserved2 = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    hStdInput = 0xffffffff.to_bytes(length=dwordsize, byteorder='little')
    hStdOutput = 0xffffffff.to_bytes(length=dwordsize, byteorder='little')
    hStdError = 0xffffffff.to_bytes(length=dwordsize, byteorder='little')
    dummy_content = cb + lpReserved + lpDesktop + lpTitle + dwX + dwY + dwXSize + dwYSize + dwXCountChars + dwYCountChars + dwFillAttribute + dwFlags + wShowWindow + cbReserved2 + lpReserved2 + hStdInput + hStdOutput + hStdError
    # addr = ql.heap.mem_alloc(size)

    assert (len(dummy_content) == size == 0x44)
    ql.uc.mem_write(pointer, dummy_content)
    return 0


#LONG InterlockedExchange(
#  LONG volatile *Target,
#  LONG          Value
#);
@winapi(cc=STDCALL, params={
    "Target": POINTER,
    "Value": UINT
})
def hook_InterlockedExchange(ql, address, params):
    old = int.from_bytes(ql.uc.mem_read(params['Target'], ql.pointersize), byteorder='little')
    ql.uc.mem_write(params['Target'], params['Value'].to_bytes(length=ql.pointersize, byteorder='little'))
    return old

#LONG InterlockedIncrement(
#  LONG volatile *Target,
#);
@winapi(cc=STDCALL, params={
    "Target": POINTER
})
def hook_InterlockedIncrement(ql, address, params):
    val = int.from_bytes(ql.uc.mem_read(params['Target'], ql.pointersize), byteorder='little')
    val += 1 & (2**ql.pointersize*8) # increment and overflow back to 0 if applicable
    ql.uc.mem_write(params['Target'], val.to_bytes(length=ql.pointersize, byteorder='little'))
    return val

#PVOID EncodePointer(
#  _In_ PVOID Ptr
#);
@winapi(cc=STDCALL, params={
    "Ptr": POINTER
})
def hook_EncodePointer(ql, address, params):
    return params['Ptr']

#PVOID DecodePointer(
#  _In_ PVOID Ptr
#);
@winapi(cc=STDCALL, params={
    "Ptr": POINTER
})
def hook_DecodePointer(ql, address, params):
    return params['Ptr']


# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
    "lpCmdLine": STRING,
    "uCmdShow": UINT
})
def hook_WinExec(ql, address, params):
    return 33


# NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion(
# );
@winapi(cc=STDCALL, params={})
def hook_GetVersion(ql, address, params):
    ret = 0x0004
    ret = ret << 16
    ret = ret | 0x0004
    return ret


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
#   LPOSVERSIONINFOA lpVersionInformation
# );
@winapi(cc=STDCALL, params={
    "lpVersionInformation": STRING

})
def hook_GetVersionExA(ql, address, params):
    return 1


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExW(
#   LPOSVERSIONINFOW lpVersionInformation
# );
@winapi(cc=STDCALL, params={
    "lpVersionInformation": STRING

})
def hook_GetVersionExW(ql, address, params):
    return 1


# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
    "lpName": STRING,
    "lpBuffer": POINTER,
    "nSize": DWORD
})
def hook_GetEnvironmentVariableA(ql, address, params):
    ret = 0
    return ret

# BOOL SetThreadLocale(
#   LCID Locale
# );
@winapi(cc=STDCALL, params={
    "Locale": UINT
})
def hook_SetThreadLocale(ql, address, params):
    return 0xC000 #LOCALE_CUSTOM_DEFAULT

# DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
#   UINT   uFlags,
#   SIZE_T uBytes
# );
@winapi(cc=STDCALL, params={
    "uFlags": UINT,
    "uBytes": SIZE_T
})
def hook_LocalAlloc(ql, address, params):
    ret = ql.heap.mem_alloc(params["uBytes"])
    return ret

# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winapi(cc=STDCALL, params={
    "hHeap": HANDLE,
    "dwFlags": DWORD,
    "dwBytes": SIZE_T
})
def hook_HeapAlloc(ql, address, params):
    ret = ql.heap.mem_alloc(params["dwBytes"])
    return ret

#BOOL HeapFree(
#  HANDLE                 hHeap,
#  DWORD                  dwFlags,
#  _Frees_ptr_opt_ LPVOID lpMem
#);
@winapi(cc=STDCALL, params={
    "hHeap": HANDLE,
    "dwFlags": DWORD,
    "lpMem": POINTER
})
def hook_HeapFree(ql, address, params):
    return ql.heap.mem_free(params['lpMem'])


# LPVOID VirtualAlloc(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  flAllocationType,
#   DWORD  flProtect
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
    "nStdHandle": DWORD
})
def hook_GetStdHandle(ql, address, params):
    nStdHandle = params["nStdHandle"]
    return nStdHandle


# DWORD GetFileType(
#   HANDLE hFile
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
    "uNumber": UINT
})
def hook_SetHandleCount(ql, address, params):
    uNumber = params["uNumber"]
    return uNumber


# LPSTR GetCommandLineA(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCommandLineA(ql, address, params):
    cmdline = ql.PE.cmdline + b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# LPSTR GetCommandLineW(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCommandLineW(ql, address, params):
    cmdline = ql.PE.cmdline.decode('ascii').encode('utf-16le')
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# LPWCH GetEnvironmentStrings(
# );s
@winapi(cc=STDCALL, params={})
def hook_GetEnvironmentStrings(ql, address, params):
    cmdline = b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    return addr


# UINT GetACP(
# );
@winapi(cc=STDCALL, params={})
def hook_GetACP(ql, address, params):
    ret = 437
    return ret


# BOOL GetCPInfo(
#   UINT     CodePage,
#   LPCPINFO lpCPInfo
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={})
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
@winapi(cc=STDCALL, params={
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
        s = bytes(s_lpWideCharStr, 'utf-16le').decode('utf-16le') + "\x00"
        ql.uc.mem_write(lpMultiByteStr, bytes(s, 'utf-16le'))
        ret = len(s)

    return ret


# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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

# DWORD GetModuleFileNameW(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winapi(cc=STDCALL, params={
    "hModule": HANDLE,
    "lpFilename": POINTER,
    "nSize": DWORD
})
def hook_GetModuleFileNameW(ql, address, params):
    
    ret = 0
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]
    if hModule == 0:
        filename = ql.PE.filepath.decode('ascii').encode('utf-16le')
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

# HANDLE FindFirstFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winapi(cc=STDCALL, params={
    "lpFilename": POINTER,
    "lpFindFileData": POINTER
})
def hook_FindFirstFileA(ql, address, params):
    pass

# HANDLE FindNextFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winapi(cc=STDCALL, params={
    "lpFilename": POINTER,
    "lpFindFileData": POINTER
})
def hook_FindNextFileA(ql, address, params):
    pass


# BOOL FindClose(
#    HANDLE hFindFile
# );
@winapi(cc=STDCALL, params={
    "hFindFile": HANDLE,
})
def hook_FindClose(ql, address, params):
    pass

# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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


@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
    "lpSystemTimeAsFileTime": POINTER
})
def hook_GetSystemTimeAsFileTime(ql, address, params):
    pass


# DWORD GetCurrentThreadId(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentThreadId(ql, address, params):
    ret = ql.thread_manager.current_thread.id
    return ret


# DWORD GetCurrentProcessId(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentProcessId(ql, address, params):
    ret = 1000
    return ret


# BOOL QueryPerformanceCounter(
#   LARGE_INTEGER *lpPerformanceCount
# );
@winapi(cc=STDCALL, params={
    "lpPerformanceCount": POINTER
})
def hook_QueryPerformanceCounter(ql, address, params):
    ret = 0
    return ret


# BOOL IsProcessorFeaturePresent(
#   DWORD ProcessorFeature
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
        handle_value = ql.unpack(ql.mem_read(lpHandles + i * ql.pointersize, ql.pointersize))
        if handle_value != 0:
            thread = ql.handle_manager.get(handle_value).thread
            ql.thread_manager.current_thread.waitfor(thread)

    return ret


# BOOL CloseHandle(
#   HANDLE hObject
# );
@winapi(cc=STDCALL, params={
    "hObject": HANDLE
})
def hook_CloseHandle(ql, address, params):
    ret = 0
    return ret


# DWORD GetTickCount(
# );
@winapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    ret = 200000
    return ret


# NTSYSAPI ULONGLONG VerSetConditionMask(
#   ULONGLONG ConditionMask, => 64bit param
#   DWORD     TypeMask,
#   BYTE      Condition
# );
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={})
def hook_GetProcessHeap(ql, address, params):
    ret = ql.heap.start_address
    return ret


# LONG UnhandledExceptionFilter(
#   _EXCEPTION_POINTERS *ExceptionInfo
# );
@winapi(cc=STDCALL, params={
    "ExceptionInfo": POINTER
})
def hook_UnhandledExceptionFilter(ql, address, params):
    ret = 1 
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
    ret = 1 
    ql.uc.emu_stop()
    ql.RUN = False
    return ret


# HANDLE GetCurrentProcess(
# );
@winapi(cc=STDCALL, params={})
def hook_GetCurrentProcess(ql, address, params):
    ret = 1
    return ret


# HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
#);
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
    "lpLibFileName": WSTRING
})
def hook_LoadLibraryW(ql, address, params):
    lpLibFileName = bytes(bytes(params["lpLibFileName"], 'ascii').deocde('utf-16le'), 'ascii')
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base


# HMODULE LoadLibraryExW(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
#);
@winapi(cc=STDCALL, params={
    "lpLibFileName": WSTRING,
    "hFile": POINTER,
    "dwFlags": DWORD
})
def hook_LoadLibraryExW(ql, address, params):
    lpLibFileName = bytes(bytes(params["lpLibFileName"], "ascii").decode('utf-16le'), 'ascii')
    dll_base = ql.PE.load_dll(lpLibFileName)
    return dll_base


# FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
#);
@winapi(cc=STDCALL, params={
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

    return 1

#LPVOID GlobalLock(
#  HGLOBAL hMem
#);
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalLock(ql, address, params):
    return params['hMem']

#LPVOID GlobalUnlock(
#  HGLOBAL hMem
#);
@winapi(cc=STDCALL, params={
    "hMem": POINTER
})
def hook_GlobalUnlock(ql, address, params):
    return 1

#DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
#  UINT   uFlags,
#  SIZE_T dwBytes
#);
@winapi(cc=STDCALL, params={
    "uFlags": UINT,
    "dwBytes": UINT
})
def hook_GlobalAlloc(ql, address, params):
    return ql.heap.mem_alloc(params['dwBytes'])





#DWORD TlsAlloc();
@winapi(cc=STDCALL, params={})
def hook_TlsAlloc(ql, address, params):
    idx = ql.thread_manager.current_thread.tls_index 
    ql.thread_manager.current_thread.tls_index += 1
    ql.thread_manager.current_thread.tls[idx] = 0
    return idx

#DWORD TlsFree(
#  DWORD dwTlsIndex
#);
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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
@winapi(cc=STDCALL, params={
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

#DWORD FlsAlloc(
#  PFLS_CALLBACK_FUNCTION lpCallback
#);
@winapi(cc=STDCALL, params={
    "lpCallback": POINTER
})
def hook_FlsAlloc(ql, address, params):
    #global cb = params['lpCallback']
    cb = params['lpCallback']
    if cb:
        return ql.fiber_manager.alloc(cb)
    else:
        return ql.fiber_manager.alloc()

#DWORD FlsFree(
#  DWORD dwFlsIndex
#);
@winapi(cc=STDCALL, params={
    "dwFlsIndex": UINT
})
def hook_FlsFree(ql, address, params):
    return ql.fiber_manager.free(params['dwFlsIndex'])

#LPVOID FlsGetValue(
#  DWORD dwFlsIndex
#);
@winapi(cc=STDCALL, params={
    "dwFlsIndex": UINT})
def hook_FlsGetValue(ql, address, params):
    return ql.fiber_manager.get(params['dwFlsIndex'])

#LPVOID FlsSetValue(
#  DWORD dwFlsIndex
#);
@winapi(cc=STDCALL, params={
    "dwFlsIndex": UINT,
    "lpFlsValue": POINTER
})
def hook_FlsSetValue(ql, address, params):
    return ql.fiber_manager.set(params['dwFlsIndex'], params['lpFlsValue'])

#BOOL HeapSetInformation(
#  HANDLE                 HeapHandle,
#  HEAP_INFORMATION_CLASS HeapInformationClass,
#  PVOID                  HeapInformation,
#  SIZE_T                 HeapInformationLength
#);
@winapi(cc=STDCALL, params={
    "HeapHandle": HANDLE,
    "HeapInformationClass": UINT,
    "HeapInformation": POINTER,
    "HeapInformationLength": UINT
})
def hook_HeapSetInformation(ql, address, params):
    return 1

#BOOL VirtualProtect(
#  LPVOID lpAddress,
#  SIZE_T dwSize,
#  DWORD  flNewProtect,
#  PDWORD lpflOldProtect
#);
@winapi(cc=STDCALL, params={
    "lpAddress": POINTER,
    "dwSize": UINT,
    "flNewProtect": UINT,
    "lpflOldProtect": POINTER
})
def hook_VirtualProtect(ql, address, params):
    return 1

#_Post_equals_last_error_ DWORD GetLastError();
@winapi(cc=STDCALL, params={})
def hook_GetLastError(ql, address, params):
    return ql.last_error

#void SetLastError(
#  DWORD dwErrCode
#);
@winapi(cc=STDCALL, params={
    "dwErrCode": UINT
})
def hook_SetLastError(ql, address, params):
    ql.last_error = params['dwErrCode']
    return 0

#BOOL IsValidCodePage(
#  UINT CodePage
#);
@winapi(cc=STDCALL, params={
    "CodePage": UINT
})
def hook_IsValidCodePage(ql, address, params):
    return 1


# int MultiByteToWideChar(
#  UINT                              CodePage,
#  DWORD                             dwFlags,
#  _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
#  int                               cbMultiByte,
#  LPWSTR                            lpWideCharStr,
#  int                               cchWideChar
# );
@winapi(cc=STDCALL, params={
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


"""
typedef struct _SYSTEMTIME {
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;
"""
# void GetLocalTime(
#   LPSYSTEMTIME lpSystemTime
# );
@winapi(cc=STDCALL, params={
    "lpSystemTime": POINTER
})
def hook_GetLocalTime(ql, address, params):
    import datetime
    ptr = params['lpSystemTime']
    d = datetime.datetime.now()
    ql.uc.mem_write(d.year.to_bytes(length=2, byteorder='little'), ptr)
    ql.uc.mem_write(d.month.to_bytes(length=2, byteorder='little'), ptr+2)
    ql.uc.mem_write(d.isoweekday().to_bytes(length=2, byteorder='little'), ptr+4)
    ql.uc.mem_write(d.day.to_bytes(length=2, byteorder='little'), ptr+6)
    ql.uc.mem_write(d.hour.to_bytes(length=2, byteorder='little'), ptr+8)
    ql.uc.mem_write(d.minute.to_bytes(length=2, byteorder='little'), ptr+10)
    ql.uc.mem_write(d.second.to_bytes(length=2, byteorder='little'), ptr+12)
    ql.uc.mem_write((d.microsecond*1000).to_bytes(length=2, byteorder='little'), ptr+14)
    return 0



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


# int LCMapStringEx(
#   LPCWSTR          lpLocaleName,
#   DWORD            dwMapFlags,
#   LPCWSTR          lpSrcStr,
#   int              cchSrc,
#   LPWSTR           lpDestStr,
#   int              cchDest,
#   LPNLSVERSIONINFO lpVersionInformation,
#   LPVOID           lpReserved,
#   LPARAM           sortHandle
# );
@winapi(cc=STDCALL, params={
    "lpLocaleName": POINTER,
    "dwMapFlags": DWORD,
    "lpSrcStr": POINTER,
    "cchSrc": INT,
    "lpDestStr": POINTER,
    "cchDest": INT,
    "lpVersionInformation": POINTER,
    "lpReserved": UINT,
    "sortHandle": UINT

})
def hook_LCMapStringEx(ql, address, params):
    # TODO needs a better implementation
    return 1


# BOOL IsWow64Process(
#   HANDLE hProcess,
#   PBOOL  Wow64Process
# );
@winapi(cc=STDCALL, params={
    "hProcess": HANDLE,
    "Wow64Process": POINTER
})
def hook_IsWow64Process(ql, address, params):
    pointer = params["Wow64Process"]
    false = 0x0.to_bytes(length=ql.pointersize, byteorder='little')
    true = 0x1.to_bytes(length=ql.pointersize, byteorder='little')
    if ql.archbit == 32:
        ql.uc.mem_write(pointer, false)
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1


# typedef struct _SYSTEM_INFO {
#   union {
#     DWORD dwOemId;
#     struct {
#       WORD wProcessorArchitecture;
#       WORD wReserved;
#     } DUMMYSTRUCTNAME;
#   } DUMMYUNIONNAME;
#   DWORD     dwPageSize;
#   LPVOID    lpMinimumApplicationAddress;
#   LPVOID    lpMaximumApplicationAddress;
#   DWORD_PTR dwActiveProcessorMask;
#   DWORD     dwNumberOfProcessors;
#   DWORD     dwProcessorType;
#   DWORD     dwAllocationGranularity;
#   WORD      wProcessorLevel;
#   WORD      wProcessorRevision;
# } SYSTEM_INFO, *LPSYSTEM_INFO;

# void GetSystemInfo(
#   LPSYSTEM_INFO lpSystemInfo
# );
@winapi(cc=STDCALL, params={
    "lpSystemInfo": POINTER
})
def hook_GetSystemInfo(ql, address, params):
    # TODO create struct
    pointer = params["lpSystemInfo"]
    dwordsize = 4
    wordsize = 2
    dummysize = 2 * wordsize + dwordsize
    size = dummysize + dwordsize + ql.pointersize + ql.pointersize + ql.pointersize + 3 * dwordsize + 2 * wordsize
    ql.uc.mem_write(pointer, 0x41.to_bytes(length=size, byteorder='little'))
    return 0


# BOOL DuplicateHandle(
#   HANDLE   hSourceProcessHandle,
#   HANDLE   hSourceHandle,
#   HANDLE   hTargetProcessHandle,
#   LPHANDLE lpTargetHandle,
#   DWORD    dwDesiredAccess,
#   BOOL     bInheritHandle,
#   DWORD    dwOptions
# );
@winapi(cc=STDCALL, params={
    "hSourceProcessHandle": POINTER,
    "hSourceHandle": POINTER,
    "hTargetProcessHandle": POINTER,
    "lpTargetHandle": POINTER,
    "dwDesiredAccess": DWORD,
    "bInheritHandle": BOOL,
    "dwOptions": DWORD
})
def hook_DuplicateHandle(ql, address, params):
    content = params["hSourceHandle"]
    dst = params["lpTargetHandle"]
    ql.uc.mem_write(dst, content.to_bytes(length=ql.pointersize, byteorder='little'))
    return 1

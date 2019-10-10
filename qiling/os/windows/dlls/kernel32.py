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
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
import sys


@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_SetUnhandledExceptionFilter(ql, address):
    ret = 0x4
    lpTopLevelExceptionFilter = ql.get_params(1)
    ql.nprint('0x%0.2x: SetUnhandledExceptionFilter(0x%x) = 0x%x'
        % (address, lpTopLevelExceptionFilter, ret))
    return ret


@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_ExitProcess(ql, address):
    uExitcode = ql.get_params(1)
    ql.nprint('0x%0.2x: ExitProcess(0x%0.2x)' % (address, uExitcode))
    ql.uc.emu_stop()
    ql.RUN = False


# __analysis_noreturn VOID FatalExit(
#   int ExitCode
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_FatalExit(ql, address):
    ExitCode = ql.get_params(1)
    print('0x%0.2x: FatalExit(0x%0.2x)' % (address, ExitCode))
    ql.uc.emu_stop()
    ql.RUN = False


# VOID WINAPI GetStartupInfo(
#   _Out_ LPSTARTUPINFO lpStartupInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetStartupInfoA(ql, address):
    lpStartupInfo = ql.get_params(1)
    ql.nprint('0x%0.2x: GetStartupInfo(0x%0.2x)' % (address, lpStartupInfo))


# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetModuleHandleA(ql, address):
    lpModuleName = ql.get_params(1)
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        if lpModuleName.lower() in ql.PE.dlls:
            ret = ql.PE.dlls[lpModuleName.lower()]
        else:
            ret = 0
    ql.nprint('0x%0.2x: GetModuleHandleA(0x%0.2x) = 0x%x' % (address, lpModuleName, ret))
    return ret


# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetModuleHandleW(ql, address):
    lpModuleName = ql.get_params(1)
    if lpModuleName == 0:
        ret = ql.PE.PE_IMAGE_BASE
    else:
        raise QlErrorNotImplemented("not implemented")
    ql.nprint('0x%0.2x: GetModuleHandleW(0x%0.2x) = 0x%x' % (address, lpModuleName, ret))
    return ret


# WinExec(cmd, nShow)
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_WinExec(ql, address):
    pCmd, nshow = ql.get_params(2)
    cmd = read_cstring(ql, pCmd)
    ql.nprint('0x%0.2x: WinExec(\'%s\', %d)' % (address, cmd, nshow))


# GetVersion()
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetVersion(ql, address):
    ret = 0
    ql.nprint('0x%0.2x: GetVersion() = %d' % (address, ret))
    return ret


# HANDLE HeapCreate(
#   DWORD  flOptions,
#   SIZE_T dwInitialSize,
#   SIZE_T dwMaximumSize
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_HeapCreate(ql, address):
    flOptions, dwInitialSize, dwMaximumSize = ql.get_params(3)
    addr = ql.heap.mem_alloc(dwInitialSize)
    ql.nprint('0x%0.2x: HeapCreate(0x%x, 0x%x, 0x%x) = 0x%x' % (address, flOptions, dwInitialSize, dwMaximumSize, addr))
    return addr


# NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExA(
#   LPOSVERSIONINFOA lpVersionInformation
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetVersionExA(ql, address):
    ret = 1
    lpVersionInformation = ql.get_params(1)
    ql.nprint('0x%0.2x: GetVersionExA(0x%x) = 0x%x' % (address, lpVersionInformation, ret))
    return ret


# DWORD GetEnvironmentVariableA(
#   LPCSTR lpName,
#   LPSTR  lpBuffer,
#   DWORD  nSize
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_GetEnvironmentVariableA(ql, address):
    ret = 0
    lpName, lpBuffer, nSize = ql.get_params(3)
    s_lpName = read_cstring(ql, lpName)
    ql.nprint('0x%0.2x: GetEnvironmentVariableA("%s", 0x%x, 0x%x) = 0x%x' % (address, s_lpName, lpBuffer, nSize, ret))
    return ret


# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_HeapAlloc(ql, address):
    hHeap, dwFlags, dwBytes = ql.get_params(3)
    ret = ql.heap.mem_alloc(dwBytes)
    ql.nprint('0x%0.2x: HeapAlloc(0x%0x, 0x%x, 0x%x) = 0x%x' % (address, hHeap, dwFlags, dwBytes, ret))
    return ret


# LPVOID VirtualAlloc(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  flAllocationType,
#   DWORD  flProtect
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=4)
def hook_VirtualAlloc(ql, address):
    lpAddress, dwSize, flAllocationType, flProtect = ql.get_params(4)
    addr = ql.heap.mem_alloc(dwSize)
    ql.nprint('0x%0.2x: VirtualAlloc(0x%x, 0x%x, 0x%x, 0x%x) = 0x%x' %
        (address, lpAddress, dwSize, flAllocationType, flProtect, addr))
    return addr

# BOOL VirtualFree(
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  dwFreeType
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_VirtualFree(ql, address):
    lpAddress, dwSize, dwFreeType = ql.get_params(3)
    addr = ql.heap.mem_free(lpAddress)
    ql.nprint('0x%0.2x: VirtualFree(0x%x, 0x%x, 0x%x) = 0x%x' %
        (address, lpAddress, dwSize, dwFreeType, addr))
    return 1

# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetStdHandle(ql, address):
    nStdHandle = ql.get_params(1)
    ql.nprint('0x%0.2x: GetStdHandle(0x%x) = 0x%x' % (address, nStdHandle, nStdHandle))
    return nStdHandle


# DWORD GetFileType(
#   HANDLE hFile
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetFileType(ql, address):
    hFile = ql.get_params(1)
    FILE_TYPE_CHAR = 0x0002
    if hFile == STD_INPUT_HANDLE or hFile == STD_OUTPUT_HANDLE or hFile == STD_ERROR_HANDLE:
        ret = FILE_TYPE_CHAR
    else:
        raise QlErrorNotImplemented("not implemented")
    ql.nprint('0x%0.2x: GetFileType(0x%x) = 0x%x' % (address, hFile, FILE_TYPE_CHAR))
    return ret

# UINT SetHandleCount(
#   UINT uNumber
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_SetHandleCount(ql, address):
    uNumber = ql.get_params(1)
    ql.nprint('0x%0.2x: SetHandleCount(0x%x) = %d' % (address, uNumber, uNumber))
    return uNumber


# LPSTR GetCommandLineA(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetCommandLineA(ql, address):
    cmdline = ql.PE.cmdline + b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    ql.nprint('0x%0.2x: GetCommandLineA() = 0x%x' % (address, addr))
    return addr


# LPWCH GetEnvironmentStrings(
# );s
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetEnvironmentStrings(ql, address):
    cmdline = b"\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    ql.nprint('0x%0.2x: GetEnvironmentStrings() = 0x%x' % (address, addr))
    return addr


# UINT GetACP(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetACP(ql, address):
    ret = 437
    ql.nprint('0x%0.2x: GetACP() = %d' % (address, ret))
    return ret


# BOOL GetCPInfo(
#   UINT     CodePage,
#   LPCPINFO lpCPInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_GetCPInfo(ql, address):
    ret = 1
    CodePage, lpCPInfo = ql.get_params(2)
    ql.nprint('0x%0.2x: GetCPInfo(0x%x, 0x%x) = %d' % (address, CodePage, lpCPInfo, ret))
    return ret


# BOOL GetStringTypeW(
#   DWORD                         dwInfoType,
#   _In_NLS_string_(cchSrc)LPCWCH lpSrcStr,
#   int                           cchSrc,
#   LPWORD                        lpCharType
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_GetStringTypeW(ql, address):
    ret = 0
    dwInfoType, lpSrcStr, cchSrc, lpCharType = ql.get_params(4)
    ql.nprint('0x%0.2x: GetStringTypeW(0x%x, 0x%x, 0x%x, 0x%x) = %d' %
         (address, dwInfoType, lpSrcStr, cchSrc, lpCharType, ret))
    return ret


#  BOOL GetStringTypeExA
#  (
#   LCID   locale,
#   DWORD  type,
#   LPCSTR src,
#   INT    count,
#   LPWORD chartype
#  )
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_GetStringTypeExA(ql, address):
    ret = 0
    locale, _type, src, count, chartype = ql.get_params(5)
    ql.nprint('0x%0.2x: GetStringTypeExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = %d' %
         (address, locale, _type, src, count, chartype, ret))
    return ret


# LPWCH GetEnvironmentStringsW(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetEnvironmentStringsW(ql, address):
    cmdline = b"\x00\x00"
    addr = ql.heap.mem_alloc(len(cmdline))
    ql.uc.mem_write(addr, cmdline)
    ql.nprint('0x%0.2x: GetEnvironmentStringsW() = 0x%x' % (address, addr))
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
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=8)
def hook_WideCharToMultiByte(ql, address):
    ret = 0
    CodePage, dwFlags, lpWideCharStr, cchWideChar, \
        lpMultiByteStr, cbMultiByte, lpDefaultChar, \
            lpUsedDefaultChar = ql.get_params(8)

    if cbMultiByte == 0:
        ret = len(read_wstring(ql, lpWideCharStr)) + 2
        ret = align(ret // 2, 2)
    else:
        s = bytes(read_wstring(ql, lpWideCharStr), 'ascii').decode('utf-16le') + "\x00"
        ql.uc.mem_write(lpMultiByteStr, bytes(s, 'ascii'))
        ret = len(s)

    ql.nprint('0x%0.2x: WideCharToMultiByte(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = %d'
        % (address, CodePage, dwFlags, lpWideCharStr, cchWideChar,
        lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar, ret))
    return ret


# BOOL FreeEnvironmentStringsW(
#   LPWCH penv
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_FreeEnvironmentStringsW(ql, address):
    ret = 1
    penv = ql.get_params(1)
    ql.nprint('0x%0.2x: FreeEnvironmentStringsW(0x%x) = %d' % (address, penv, ret))
    return ret


# int LCMapStringW(
#   LCID    Locale,
#   DWORD   dwMapFlags,
#   LPCWSTR lpSrcStr,
#   int     cchSrc,
#   LPWSTR  lpDestStr,
#   int     cchDest
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=6)
def hook_LCMapStringW(ql, address):
    ret = 0
    Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest = ql.get_params(6)
    ql.nprint('0x%0.2x: LCMapStringW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = %d'
        % (address, Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, ret))
    return ret


# int LCMapStringA(
#   LCID   Locale,
#   DWORD  dwMapFlags,
#   LPCSTR lpSrcStr,
#   int    cchSrc,
#   LPSTR  lpDestStr,
#   int    cchDest
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=6)
def hook_LCMapStringA(ql, address):
    ret = 0
    Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest = ql.get_params(6)
    ql.nprint('0x%0.2x: LCMapStringA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = %d'
        % (address, Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, ret))
    return ret


# DWORD GetModuleFileNameA(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=3)
def hook_GetModuleFileNameA(ql, address):
    ret = 0
    hModule, lpFilename, nSize = ql.get_params(3)
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
        raise QlErrorNotImplemented("not implemented")
    ql.nprint('0x%0.2x: GetModuleFileNameA(0x%x, 0x%x, 0x%x) = %d'
        % (address, hModule, lpFilename, nSize, ret))
    return ret


# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_ReadFile(ql, address):
    ret = 1
    hFile, lpBuffer, nNumberOfBytesToRead, \
        lpNumberOfBytesRead, lpOverlapped = ql.get_params(5)
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
    ql.nprint('0x%0.2x: ReadFile(0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = %d'
        % (address, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, ret))
    return ret


# BOOL WriteFile(
#   HANDLE       hFile,
#   LPCVOID      lpBuffer,
#   DWORD        nNumberOfBytesToWrite,
#   LPDWORD      lpNumberOfBytesWritten,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=5)
def hook_WriteFile(ql, address):
    ret = 1
    hFile, lpBuffer, nNumberOfBytesToWrite, \
        lpNumberOfBytesWritten, lpOverlapped = ql.get_params(5)
    if hFile == STD_OUTPUT_HANDLE:
        s = ql.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
        ql.stdout.write(s)
        ql.uc.mem_write(lpNumberOfBytesWritten, ql.pack(nNumberOfBytesToWrite))
    else:
        f = ql.handle_manager.get(hFile).file
        buffer = ql.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
        f.write(bytes(buffer))
        ql.uc.mem_write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
    ql.nprint('0x%0.2x: WriteFile(0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x' 
        % (address, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, ret))
    return ret


def _CreateFile(ql, address, name):
    ret = INVALID_HANDLE_VALUE
    lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, \
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile = ql.get_params(7)

    if name == "CreateFileA":
        s_lpFileName = read_cstring(ql, lpFileName)
    else:
        s_lpFileName = read_wstring(ql, lpFileName)

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

    ql.nprint('0x%0.2x: %s("%s", 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x'
        % (address, name, s_lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, \
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, ret))

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
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=7)
def hook_CreateFileA(ql, address):
    ret = _CreateFile(ql, address, "CreateFileA")
    return ret


@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=7)
def hook_CreateFileW(ql, address):
    ret = _CreateFile(ql, address, "CreateFileW")
    return ret


# void GetSystemTimeAsFileTime(
#   LPFILETIME lpSystemTimeAsFileTime
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_GetSystemTimeAsFileTime(ql, address):
    lpSystemTimeAsFileTime = ql.get_params(1)
    ql.nprint('0x%0.2x: GetSystemTimeAsFileTime(0x%x)' % (address, lpSystemTimeAsFileTime))


# DWORD GetCurrentThreadId(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetCurrentThreadId(ql, address):
    ret = ql.thread_manager.current_thread.id
    ql.nprint('0x%0.2x: GetCurrentThreadId() = %d' % (address, ret))
    return ret


# DWORD GetCurrentProcessId(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetCurrentProcessId(ql, address):
    ret = 1000
    ql.nprint('0x%0.2x: GetCurrentProcessId() = %d' % (address, ret))
    return ret


# BOOL QueryPerformanceCounter(
#   LARGE_INTEGER *lpPerformanceCount
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_QueryPerformanceCounter(ql, address):
    ret = 0
    lpPerformanceCount = ql.get_params(1)
    ql.nprint('0x%0.2x: QueryPerformanceCounter(0x%x) = 0x%x' % (address, lpPerformanceCount, ret))
    return ret


# BOOL IsProcessorFeaturePresent(
#   DWORD ProcessorFeature
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_IsProcessorFeaturePresent(ql, address):
    ret = 0
    ProcessorFeature = ql.get_params(1)
    ql.nprint('0x%0.2x: IsProcessorFeaturePresent(0x%x) = 0x%x' % (address, ProcessorFeature, ret))
    return ret


# HANDLE CreateThread(
#   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
#   SIZE_T                  dwStackSize,
#   LPTHREAD_START_ROUTINE  lpStartAddress,
#   __drv_aliasesMem LPVOID lpParameter,
#   DWORD                   dwCreationFlags,
#   LPDWORD                 lpThreadId
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=6)
def hook_CreateThread(ql, address):
    CREATE_RUN = 0
    CREATE_SUSPENDED = 0x00000004

    ret = 0
    lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, \
        dwCreationFlags, lpThreadId = ql.get_params(6)

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

    ql.nprint('0x%0.2x: CreateThread(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%x' \
        % (address, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId, ret))

    # set thread handle
    return ret


# DWORD WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD  dwMilliseconds
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_WaitForSingleObject(ql, address):
    ret = 0
    hHandle, dwMilliseconds = ql.get_params(2)
    target_thread = ql.handle_manager.get(hHandle).thread
    ql.thread_manager.current_thread.waitfor(target_thread)
    ql.nprint('0x%0.2x: WaitForSingleObject(0x%x, 0x%x) = %d' % \
        (address, hHandle, dwMilliseconds, ret))
    return ret


# DWORD WaitForMultipleObjects(
#   DWORD        nCount,
#   const HANDLE *lpHandles,
#   BOOL         bWaitAll,
#   DWORD        dwMilliseconds
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=4)
def hook_WaitForMultipleObjects(ql, address):
    ret = 0
    nCount, lpHandles, bWaitAll, dwMilliseconds = ql.get_params(4)

    for i in range(nCount):
        handle_value = ql.unpack(ql.mem_read(lpHandles + i * ql.pointersize, ql.pointersize))
        if handle_value != 0:
            thread = ql.handle_manager.get(handle_value).thread
            ql.thread_manager.current_thread.waitfor(thread)

    ql.nprint('0x%0.2x: WaitForMultipleObjects(0x%x, 0x%x, 0x%x, 0x%x) = %d' % \
        (address, nCount, lpHandles, bWaitAll, dwMilliseconds, ret))
    return ret


# BOOL CloseHandle(
#   HANDLE hObject
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_CloseHandle(ql, address):
    ret = 0
    hObject = ql.get_params(1)
    ql.nprint('0x%0.2x: CloseHandle(0x%x) = %d' % \
        (address, hObject, ret))
    return ret


# DWORD GetTickCount(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetTickCount(ql, address):
    ret = 200000
    ql.nprint('0x%0.2x: GetTickCount() = %d' % (address, ret))
    return ret


# NTSYSAPI ULONGLONG VerSetConditionMask(
#   ULONGLONG ConditionMask, => 64bit param
#   DWORD     TypeMask,
#   BYTE      Condition
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=4)
def hook_VerSetConditionMask(ql, address):
    l_ConditionMask, h_ConditionMask, TypeMask, Condition = ql.get_params(4)
    tmp_ConditionMask = h_ConditionMask << 8 + l_ConditionMask
    ConditionMask = tmp_ConditionMask
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

    ql.nprint('0x%0.2x: VerSetConditionMask(0x%x,0x%x, 0x%x) = 0x%x' % 
        (address, tmp_ConditionMask, TypeMask, Condition, ret))
    return ret


# HANDLE GetProcessHeap(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetProcessHeap(ql, address):
    ret = ql.heap.start_address
    ql.nprint('0x%0.2x: GetProcessHeap() = 0x%x' % (address, ret))
    return ret


# LONG UnhandledExceptionFilter(
#   _EXCEPTION_POINTERS *ExceptionInfo
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=1)
def hook_UnhandledExceptionFilter(ql, address):
    ExceptionInfo = ql.get_params(1)
    ret = 1 
    ql.nprint('0x%0.2x: UnhandledExceptionFilter(0x%x) = 0x%x' % (address, ExceptionInfo, ret))
    return ret


# BOOL TerminateProcess(
#   HANDLE hProcess,
#   UINT   uExitCode
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=2)
def hook_TerminateProcess(ql, address):
    hProcess, uExitCode = ql.get_params(2)
    ret = 1 
    ql.nprint('0x%0.2x: TerminateProcess(0x%x, 0x%x) = 0x%x' % (address, hProcess, uExitCode, ret))
    return ret
    ql.uc.emu_stop()
    ql.RUN = False


# HANDLE GetCurrentProcess(
# );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, param_num=0)
def hook_GetCurrentProcess(ql, address):
    ret = 1
    ql.nprint('0x%0.2x: GetCurrentProcess() = 0x%x' % (address, ret))
    return ret
#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from enum import IntEnum

class QL_ENDIAN(IntEnum):
    EL = 1
    EB = 2


class QL_ARCH(IntEnum):
    X86 = 1
    X8664 = 2
    ARM = 3
    ARM_THUMB = 4
    ARM64 = 5
    MIPS = 6


class QL_OS(IntEnum):
    LINUX = 1
    FREEBSD = 2
    MACOS = 3
    WINDOWS = 4
    POSIX = 5
    UEFI = 6


class QL_OUTPUT(IntEnum):
    OFF = 1
    DEFAULT = 2
    DISASM = 3
    DEBUG = 4
    DUMP = 5


class QL_DEBUGGER(IntEnum):
    GDB = 1
    IDAPRO = 2


class QL_INTERCEPT(IntEnum):
    CALL = 1
    ENTER = 2
    EXIT = 3


D_INFO = 1 # General debug information
D_PROT = 2 # Protocol level debug, print out open file flag
D_CTNT = 3 # Print out content. File content or content of a tcp stream
D_RPRT = 4 # Reporting output, main summarizing purposes
D_DRPT = 5 # Detailed Report, with address

QL_DEBUGGER_ALL = [QL_DEBUGGER.IDAPRO, QL_DEBUGGER.GDB]
QL_ARCH_ALL = [QL_ARCH.X86, QL_ARCH.X8664, QL_ARCH.ARM, QL_ARCH.ARM64, QL_ARCH.MIPS]
QL_ENDINABLE = [QL_ARCH.MIPS, QL_ARCH.ARM]
QL_OS_ALL = [QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS, QL_OS.WINDOWS, QL_OS.POSIX, QL_OS.UEFI]
QL_POSIX = [QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS]

QL_HOOK_BLOCK = 0b1
QL_CALL_BLOCK = 0b10

debugger_map = {
        "gdb": QL_DEBUGGER.GDB,
        "ida": QL_DEBUGGER.IDAPRO,
    }

arch_map = {
        "x86": QL_ARCH.X86,
        "x8664": QL_ARCH.X8664,
        "mips": QL_ARCH.MIPS,
        "arm": QL_ARCH.ARM,
        "arm64": QL_ARCH.ARM64,
    }

os_map = {
        "linux": QL_OS.LINUX,
        "macos": QL_OS.MACOS,
        "freebsd": QL_OS.FREEBSD,
        "windows": QL_OS.WINDOWS,
        "uefi": QL_OS.UEFI,
}

reptypedict = {
            "BSTR": "POINTER",
            "DLGPROC": "POINTER",
            "DWORDLONG": "ULONGLONG",
            "DWORD_PTR": "POINTER",
            "GROUP": "INT",
            "HDC": "POINTER",
            "HEAP_INFORMATION_CLASS": "UINT",
            "HGLOBAL": "POINTER",
            "HHOOK": "POINTER",
            "HINSTANCE": "HANDLE",
            "HINTERNET": "POINTER",
            "HKEY": "HANDLE",
            "HLOCAL": "POINTER",
            "HMODULE": "HANDLE",
            "HOOKPROC": "POINTER",
            "HRSRC": "POINTER",
            "HWND": "HANDLE",
            "INSTALLSTATE": "POINTER",
            "INTERNET_PORT": "DWORD",
            "INT_PTR": "POINTER",
            "LARGE_INTEGER": "POINTER",
            "LCID": "POINTER",
            "LONG": "ULONGLONG",
            "LPARAM": "POINTER",
            "LPBOOL": "POINTER",
            "LPBYTE": "POINTER",
            "LPCCH": "POINTER",
            "LPCONTEXT": "POINTER",
            "LPCPINFO": "POINTER",
            "LPCRITICAL_SECTION": "POINTER",
            "LPCSTR": "STRING",
            "LPCVOID": "POINTER",
            "LPCWCH": "POINTER",
            "LPCWSTR": "WSTRING",
            "LPDWORD": "POINTER",
            "LPFILETIME": "POINTER",
            "LPINTERNET_BUFFERSA": "POINT",
            "LPMESSAGEFILTER": "POINTER",
            "LPMODULEINFO": "POINTER",
            "LPNLSVERSIONINFO": "POINTER",
            "LPOSVERSIONINFOA": "STRING",
            "LPOSVERSIONINFOEXW": "POINTER",
            "LPOSVERSIONINFOW": "WSTRING",
            "LPOVERLAPPED": "POINTER",
            "LPPOINT": "POINTER",
            "LPPROCESSENTRY32W": "POINTER",
            "LPSECURITY_ATTRIBUTES": "POINTER",
            "LPSTARTUPINFOA": "POINTER",
            "LPSTARTUPINFOW": "POINTER",
            "LPSTR": "POINTER",
            "LPSYSTEMTIME": "POINTER",
            "LPSYSTEM_INFO": "POINTER",
            "LPTHREAD_START_ROUTINE": "POINTER",
            "LPTOP_LEVEL_EXCEPTION_FILTER": "DWORD",
            "LPUNKNOWN": "POINTER",
            "LPVOID": "POINTER",
            "LPWCH": "POINTER",
            "LPWIN32_FIND_DATAA": "POINTER",
            "LPWORD": "POINTER",
            "LPWSADATA": "STRING",
            "LPWSAPROTOCOL_INFOA": "POINTER",
            "LPWSTR": "POINTER",
            "MSIHANDLE": "POINTER",
            "OBJECT_INFORMATION_CLASS": "INT",
            "OLECHAR": "WSTRING",
            "PBOOL": "POINTER",
            "PCACTCTXW": "POINTER",
            "PCNZCH": "STRING",
            "PDWORD": "POINTER",
            "PFLS_CALLBACK_FUNCTION": "POINTER",
            "PHKEY": "POINTER",
            "PMEMORY_BASIC_INFORMATION": "POINTER",
            "PROCESSINFOCLASS": "INT",
            "PSECURITY_DESCRIPTOR": "POINTER",
            "PSID": "HANDLE",
            "PSID_IDENTIFIER_AUTHORITY": "POINTER",
            "PSLIST_HEADER": "POINTER",
            "PSRWLOCK": "POINTER",
            "PULONG": "POINTER",
            "PVECTORED_EXCEPTION_HANDLER": "HANDLE",
            "PVOID": "POINTER",
            "REFCLSID": "POINTER",
            "REFIID": "POINTER",
            "REGSAM": "POINTER",
            "SHELLEXECUTEINFOA": "POINTER",
            "SHELLEXECUTEINFOW": "POINTER",
            "SHFILEINFOW": "POINTER",
            "SOCKET": "INT",
            "SOLE_AUTHENTICATION_SERVICE": "POINTER",
            "TOKEN_INFORMATION_CLASS": "DWORD",
            "UINT_PTR": "POINTER",
            "ULONG": "UINT",
            "ULONG_PTR": "POINTER",
            "WORD": "DWORD",
            "WPARAM": "UINT",
            "_EXCEPTION_POINTERS": "POINTER",
            "int": "INT",
            "size_t": "UINT",
            "sockaddr": "POINTER",
            "unsigned int": "UINT",
            "void": "POINTER"
}
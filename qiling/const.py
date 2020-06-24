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

reptypedict = {'HKEY': 'HANDLE', 'LPCSTR': 'STRING', 'REGSAM': 'POINTER', 'PHKEY': 'POINTER', 'LPCWSTR': 'WSTRING',
               'LPFILETIME': 'POINTER', 'LPDWORD': 'POINTER', 'LPBYTE': 'POINTER', 'LPSECURITY_ATTRIBUTES': 'POINTER',
               'TOKEN_INFORMATION_CLASS': 'DWORD', 'LPVOID': 'POINTER', 'PDWORD': 'POINTER',
               'PSID': 'HANDLE', 'PSID_IDENTIFIER_AUTHORITY': 'POINTER', 'int': 'INT',
               'MSIHANDLE': 'POINTER', 'INSTALLSTATE': 'POINTER', 'size_t': 'UINT', 'PROCESSINFOCLASS': 'INT',
               'PVOID': 'POINTER', 'ULONG': 'UINT', 'PULONG': 'POINTER', 'OBJECT_INFORMATION_CLASS': 'INT',
               'LPMESSAGEFILTER': 'POINTER', 'PSECURITY_DESCRIPTOR': 'POINTER', 'LONG': 'ULONGLONG',
               'SOLE_AUTHENTICATION_SERVICE': 'POINTER', 'void': 'POINTER', 'REFCLSID': 'POINTER',
               'LPUNKNOWN': 'POINTER', 'REFIID': 'POINTER', 'OLECHAR': 'WSTRING', 'BSTR': 'POINTER',
               'unsigned int': 'UINT', 'SHFILEINFOW': 'POINTER', 'SHELLEXECUTEINFOA': 'POINTER',
               'SHELLEXECUTEINFOW': 'POINTER', 'HWND': 'HANDLE', 'LPWSTR': 'POINTER', 'DLGPROC': 'POINTER',
               'LPARAM': 'POINTER', 'HINSTANCE': 'HANDLE', 'INT_PTR': 'POINTER',
               'LPPOINT': 'POINTER', 'HDC': 'POINTER', 'LPSTR': 'POINTER', 'HOOKPROC': 'POINTER', 'HHOOK': 'POINTER',
               'WPARAM': 'UINT', 'PCACTCTXW': 'POINTER', 'HINTERNET': 'POINTER', 'DWORD_PTR': 'POINTER',
               'INTERNET_PORT': 'DWORD', 'LPINTERNET_BUFFERSA': 'POINT', 'WORD': 'DWORD', 'LPWSADATA': 'STRING',
               'LPWSAPROTOCOL_INFOA': 'POINTER', 'GROUP': 'INT', 'SOCKET': 'INT', 'sockaddr': 'POINTER',
               'PBOOL': 'POINTER', 'LPTOP_LEVEL_EXCEPTION_FILTER': 'DWORD', '_EXCEPTION_POINTERS': 'POINTER',
               'ULONG_PTR': 'POINTER', 'PVECTORED_EXCEPTION_HANDLER': 'HANDLE', 'PFLS_CALLBACK_FUNCTION': 'POINTER',
               'LPWIN32_FIND_DATAA': 'POINTER', 'LPOVERLAPPED': 'POINTER', 'LPCVOID': 'POINTER',
               'HEAP_INFORMATION_CLASS': 'UINT', 'PSLIST_HEADER': 'POINTER', 'HMODULE': 'HANDLE', 'HRSRC': 'POINTER',
               'HGLOBAL': 'POINTER', 'PMEMORY_BASIC_INFORMATION': 'POINTER', 'LPWCH': 'POINTER',
               'LPSTARTUPINFOA': 'POINTER', 'LPSTARTUPINFOW': 'POINTER', 'LPTHREAD_START_ROUTINE': 'POINTER',
               'LPCONTEXT': 'POINTER', 'LARGE_INTEGER': 'POINTER', 'LPMODULEINFO': 'POINTER', 'LPCWCH': 'POINTER',
               'LPWORD': 'POINTER', 'LCID': 'POINTER', 'LPCCH': 'POINTER', 'LPBOOL': 'POINTER',
               'LPCRITICAL_SECTION': 'POINTER', 'PSRWLOCK': 'POINTER', 'LPOSVERSIONINFOA': 'STRING',
               'LPOSVERSIONINFOW': 'WSTRING', 'LPSYSTEM_INFO': 'POINTER', 'LPSYSTEMTIME': 'POINTER',
               'LPPROCESSENTRY32W': 'POINTER', 'HLOCAL': 'POINTER', 'UINT_PTR': 'POINTER',
               'LPOSVERSIONINFOEXW': 'POINTER', 'DWORDLONG': 'ULONGLONG', 'LPCPINFO': 'POINTER',
               'LPNLSVERSIONINFO': 'POINTER', 'PCNZCH': 'STRING'}
#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

STDCALL = 1
CDECL = 2

DWORD = 1
UINT = 1
INT = 1
BOOL = 1
SIZE_T = 1
BYTE = 1
ULONGLONG = 2
HANDLE = 3
POINTER = 3
STRING = 4
WSTRING = 5
GUID = 6

# OS Threading Constants
THREAD_EVENT_INIT_VAL = 0
THREAD_EVENT_EXIT_EVENT = 1
THREAD_EVENT_UNEXECPT_EVENT = 2
THREAD_EVENT_EXECVE_EVENT = 3
THREAD_EVENT_CREATE_THREAD = 4
THREAD_EVENT_BLOCKING_EVENT = 5
THREAD_EVENT_EXIT_GROUP_EVENT = 6

THREAD_STATUS_RUNNING = 0
THREAD_STATUS_BLOCKING = 1
THREAD_STATUS_TERMINATED = 2
THREAD_STATUS_TIMEOUT = 3

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
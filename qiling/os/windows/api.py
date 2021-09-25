#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *

# See: https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types

LONG   = PARAM_INTN
ULONG  = PARAM_INTN
CHAR   = PARAM_INT8
UCHAR  = PARAM_INT16
SHORT  = PARAM_INT16
USHORT = PARAM_INT16

CCHAR                       = BYTE
WCHAR                       = SHORT

ACCESS_MASK                 = INT
BOOLEAN                     = INT
GROUP                       = INT
HFILE                       = INT
OBJECT_INFORMATION_CLASS    = INT
PROCESSINFOCLASS            = INT
SOCKET                      = INT

EX_POOL_PRIORITY            = UINT
HEAP_INFORMATION_CLASS      = UINT
KPRIORITY                   = UINT
LOCALE_T                    = UINT
LPARAM                      = UINT
SYSTEM_INFORMATION_CLASS    = UINT
WPARAM                      = UINT

EVENT_TYPE                  = DWORD
INTERNET_PORT               = DWORD
KPROCESSOR_MODE             = DWORD
KWAIT_REASON                = DWORD
LCTYPE                      = DWORD
MEMORY_CACHING_TYPE         = DWORD
NTSTATUS                    = DWORD
POOL_TYPE                   = DWORD
THREADINFOCLASS             = DWORD
TOKEN_INFORMATION_CLASS     = DWORD
WORD                        = DWORD

DWORDLONG                   = ULONGLONG

HINSTANCE                   = HANDLE
HKEY                        = HANDLE
HMODULE                     = HANDLE
HWND                        = HANDLE
PSID                        = HANDLE
SC_HANDLE                   = HANDLE

LPCSTR                      = STRING
LPOSVERSIONINFOA            = STRING
PANSI_STRING                = STRING
PCANSI_STRING               = STRING
PCNZCH                      = STRING
PCSTR                       = STRING
PCSZ                        = STRING

BSTR                        = WSTRING
LPCTSTR                     = WSTRING
LPCWSTR                     = WSTRING
LPOSVERSIONINFOW            = WSTRING
OLECHAR                     = WSTRING
PCNZWCH                     = WSTRING
PCUNICODE_STRING            = WSTRING
PCWSTR                      = WSTRING
PUNICODE_STRING             = WSTRING

DLGPROC                     = POINTER
DWORD_PTR                   = POINTER
HDC                         = POINTER
HGLOBAL                     = POINTER
HHOOK                       = POINTER
HINTERNET                   = POINTER
HLOCAL                      = POINTER
HOOKPROC                    = POINTER
HRSRC                       = POINTER
INSTALLSTATE                = POINTER
INT_PTR                     = POINTER
LCID                        = POINTER
LPBOOL                      = POINTER
LPBYTE                      = POINTER
LPCCH                       = POINTER
LPCGUID                     = POINTER
LPCONTEXT                   = POINTER
LPCPINFO                    = POINTER
LPCRITICAL_SECTION          = POINTER
LPCVOID                     = POINTER
LPCWCH                      = POINTER
LPDWORD                     = POINTER
LPFILETIME                  = POINTER
LPHANDLE                    = POINTER
LPINTERNET_BUFFERSA         = POINTER
LPMESSAGEFILTER             = POINTER
LPMODULEINFO                = POINTER
LPNLSVERSIONINFO            = POINTER
LPOSVERSIONINFOEXW          = POINTER
LPOVERLAPPED                = POINTER
LPPOINT                     = POINTER
LPPROCESSENTRY32W           = POINTER
LPSECURITY_ATTRIBUTES       = POINTER
LPSTARTUPINFOA              = POINTER
LPSTARTUPINFOW              = POINTER
LPSTR                       = POINTER
LPSYSTEMTIME                = POINTER
LPSYSTEM_INFO               = POINTER
LPTHREAD_START_ROUTINE      = POINTER
LPTOP_LEVEL_EXCEPTION_FILTER= POINTER
LPUNKNOWN                   = POINTER
LPVOID                      = POINTER
LPWCH                       = POINTER
LPWIN32_FIND_DATAA          = POINTER
LPWORD                      = POINTER
LPWSADATA                   = POINTER
LPWSAPROTOCOL_INFOA         = POINTER
LPWSTR                      = POINTER
MSIHANDLE                   = POINTER
PACCESS_STATE               = POINTER
PBOOL                       = POINTER
PBYTE                       = POINTER
PCACTCTXW                   = POINTER
PCLIENT_ID                  = POINTER
PCONSOLE_SCREEN_BUFFER_INFO = POINTER
PDEVICE_OBJECT              = POINTER
PDRIVER_CANCEL              = POINTER
PDRIVER_INITIALIZE          = POINTER
PDRIVER_OBJECT              = POINTER
PDWORD                      = POINTER
PFLS_CALLBACK_FUNCTION      = POINTER
PHANDLE                     = POINTER
PHKEY                       = POINTER
PIRP                        = POINTER
PKSTART_ROUTINE             = POINTER
PLARGE_INTEGER              = POINTER
PMDL                        = POINTER
PMEMORY_BASIC_INFORMATION   = POINTER
POBJECT_ATTRIBUTES          = POINTER
POBJECT_HANDLE_INFORMATION  = POINTER
POBJECT_TYPE                = POINTER
PRKEVENT                    = POINTER
PRTL_OSVERSIONINFOW         = POINTER
PSECURITY_DESCRIPTOR        = POINTER
PSID_IDENTIFIER_AUTHORITY   = POINTER
PSLIST_HEADER               = POINTER
PSRWLOCK                    = POINTER
PTIME_FIELDS                = POINTER
PULONG                      = POINTER
PVECTORED_EXCEPTION_HANDLER = POINTER
PVOID                       = POINTER
PWCH                        = POINTER
REFCLSID                    = POINTER
REFIID                      = POINTER
REGSAM                      = POINTER
UINT_PTR                    = POINTER
ULONG_PTR                   = POINTER

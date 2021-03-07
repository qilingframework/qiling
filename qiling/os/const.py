#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

# calling conventions
STDCALL = 1
CDECL   = 2
MS64    = 3

PARAM_INT8  = 1
PARAM_INT16 = 2
PARAM_INT32 = 3
PARAM_INT64 = 4
PARAM_INTN  = 5
PARAM_PTRX  = 128

BYTE      = PARAM_INT8
DWORD     = PARAM_INT32
INT       = PARAM_INT32
UINT      = PARAM_INT32
BOOL      = PARAM_INT32
LONGLONG  = PARAM_INT64
ULONGLONG = PARAM_INT64
SIZE_T    = PARAM_INTN
POINTER   = PARAM_INTN
HANDLE    = PARAM_INTN
STRING    = PARAM_PTRX + 1
WSTRING   = PARAM_PTRX + 2
GUID      = PARAM_PTRX + 3

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
THREAD_STATUS_STOPPED = 4
THREAD_STATUS_TIMEOUT = 3
THREAD_STATUS_SUSPEND = 5

reptypedict = {
    "BSTR"                          : POINTER,
    "DLGPROC"                       : POINTER,
    "DWORDLONG"                     : ULONGLONG,
    "DWORD_PTR"                     : POINTER,
    "GROUP"                         : INT,
    "HBITMAP"                       : HANDLE,
    "HDC"                           : POINTER,
    "HEAP_INFORMATION_CLASS"        : UINT,
    "HGLOBAL"                       : POINTER,
    "HIMAGELIST"                    : HANDLE,
    "HHOOK"                         : POINTER,
    "HINSTANCE"                     : HANDLE,
    "HINTERNET"                     : POINTER,
    "HKEY"                          : HANDLE,
    "HLOCAL"                        : POINTER,
    "HMODULE"                       : HANDLE,
    "HOOKPROC"                      : POINTER,
    "HRSRC"                         : POINTER,
    "HWND"                          : HANDLE,
    "INSTALLSTATE"                  : POINTER,
    "INTERNET_PORT"                 : DWORD,
    "INT_PTR"                       : POINTER,
    "LARGE_INTEGER"                 : POINTER,
    "LCID"                          : POINTER,
    "LONG"                          : ULONGLONG,
    "LPARAM"                        : POINTER,
    "LPBOOL"                        : POINTER,
    "LPBYTE"                        : POINTER,
    "LPCCH"                         : POINTER,
    "LPCONTEXT"                     : POINTER,
    "LPCPINFO"                      : POINTER,
    "LPCRITICAL_SECTION"            : POINTER,
    "LPCSTR"                        : STRING,
    "LPCVOID"                       : POINTER,
    "LPCWCH"                        : POINTER,
    "LPCWSTR"                       : WSTRING,
    "LPDWORD"                       : POINTER,
    "LPFILETIME"                    : POINTER,
    "LPINTERNET_BUFFERSA"           : POINTER,
    "LPMESSAGEFILTER"               : POINTER,
    "LPMODULEINFO"                  : POINTER,
    "LPNLSVERSIONINFO"              : POINTER,
    "LPOSVERSIONINFOA"              : STRING,
    "LPOSVERSIONINFOEXW"            : POINTER,
    "LPOSVERSIONINFOW"              : WSTRING,
    "LPOVERLAPPED"                  : POINTER,
    "LPPOINT"                       : POINTER,
    "LPPROCESSENTRY32W"             : POINTER,
    "LPSECURITY_ATTRIBUTES"         : POINTER,
    "LPSTARTUPINFOA"                : POINTER,
    "LPSTARTUPINFOW"                : POINTER,
    "LPSTR"                         : POINTER,
    "LPSTREAM"                      : POINTER,
    "LPSYSTEMTIME"                  : POINTER,
    "LPSYSTEM_INFO"                 : POINTER,
    "LPTHREAD_START_ROUTINE"        : POINTER,
    "LPTOP_LEVEL_EXCEPTION_FILTER"  : DWORD,
    "LPUNKNOWN"                     : POINTER,
    "LPVOID"                        : POINTER,
    "LPWCH"                         : POINTER,
    "LPWIN32_FIND_DATAA"            : POINTER,
    "LPWORD"                        : POINTER,
    "LPWSADATA"                     : STRING,
    "LPWSAPROTOCOL_INFOA"           : POINTER,
    "LPWSTR"                        : POINTER,
    "MSIHANDLE"                     : POINTER,
    "OBJECT_INFORMATION_CLASS"      : INT,
    "OLECHAR"                       : WSTRING,
    "PANSI_STRING"                  : STRING,
    "PBOOL"                         : POINTER,
    "PCACTCTXW"                     : POINTER,
    "PCANSI_STRING"                 : STRING,
    "PCNZCH"                        : STRING,
    "PCSZ"                          : STRING,
    "PCWSTR"                        : WSTRING,
    "PDWORD"                        : POINTER,
    "PFLS_CALLBACK_FUNCTION"        : POINTER,
    "PHKEY"                         : POINTER,
    "PMEMORY_BASIC_INFORMATION"     : POINTER,
    "PROCESSINFOCLASS"              : INT,
    "PSECURITY_DESCRIPTOR"          : POINTER,
    "PSID"                          : HANDLE,
    "PSID_IDENTIFIER_AUTHORITY"     : POINTER,
    "PSLIST_HEADER"                 : POINTER,
    "PSRWLOCK"                      : POINTER,
    "PTP_POOL"                      : POINTER,
    "PULONG"                        : POINTER,
    "PVECTORED_EXCEPTION_HANDLER"   : HANDLE,
    "PVOID"                         : POINTER,
    "PWSTR"                         : WSTRING,
    "REFCLSID"                      : POINTER,
    "REFIID"                        : POINTER,
    "REGSAM"                        : POINTER,
    "SC_HANDLE"                     : HANDLE,
    "SHELLEXECUTEINFOA"             : POINTER,
    "SHELLEXECUTEINFOW"             : POINTER,
    "SHFILEINFOW"                   : POINTER,
    "SOCKET"                        : INT,
    "SOLE_AUTHENTICATION_SERVICE"   : POINTER,
    "TOKEN_INFORMATION_CLASS"       : DWORD,
    "UINT_PTR"                      : POINTER,
    "ULONG"                         : UINT,
    "ULONG_PTR"                     : POINTER,
    "WER_REGISTER_FILE_TYPE"        : INT,
    "WORD"                          : DWORD,
    "WPARAM"                        : UINT,
    "_EXCEPTION_POINTERS"           : POINTER,
    "int"                           : INT,
    "size_t"                        : SIZE_T,
    "sockaddr"                      : POINTER,
    "unsigned int"                  : UINT,
    "void"                          : POINTER,

    # work around the need of "eval"
    "POINTER"   : POINTER,
    "BYTE"      : BYTE,
    "DWORD"     : DWORD,
    "HANDLE"    : HANDLE,
    "SIZE_T"    : SIZE_T,
    "UINT"      : UINT,
    "WSTRING"   : WSTRING
}

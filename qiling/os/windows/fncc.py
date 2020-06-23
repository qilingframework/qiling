#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from functools import wraps

from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.const import *
from qiling.exception import *


def replacetype(type, specialtype=None):
    if specialtype is None:
        specialtype = {}
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

    if type in reptypedict.keys():
        if type not in specialtype.keys():
            return reptypedict[type]
        else:
            return specialtype[type]
    else:
        return type

# x86/x8664 PE should share Windows APIs
def winsdkapi(cc, param_num=None, dllname=None, specialtype=None, specialtypeEx=None, defparams=None):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @param_num: the number of function params, used by variadic functions, e.g printf
    @dllname: the name of function
    @funcname: function's name
    @specialtype: customize replace type, e.g specialtype={'int':'UINT'} means repalce 'int' to 'UINT'
    @specialtypeEx: customize replace param_name's type, e.g specialtypeEx={'time':'int'} means
                replace the original type of time to int
    @defparams: customize all params and their type
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            funcname = func.__name__[5:]
            params = {}
            paramlist = None
            ql = args[0]
            if defparams is not None:
                params = defparams
            else:
                if dllname is not None:
                    root_path = os.path.abspath(os.path.join(os.getcwd(), "../.."))
                    with open(root_path+'/qiling/extensions/windows_sdk/'+dllname+'.json', 'r') as f:
                        funclist = json.load(f)
                        f.close()
                    paramlist = funclist[funcname]
                if funcname is not None:
                    for para in paramlist:
                        name = list(para.values())[0]
                        if name == 'VOID':
                            params = {}
                            break
                        elif specialtypeEx is not None and name in specialtypeEx.keys():
                            type = specialtypeEx[name]
                        else:
                            type = list(para.values())[1]
                            if isinstance(type, dict):
                                type = replacetype(type['name'], specialtype)
                            else:
                                type = replacetype(list(para.values())[1], specialtype)
                        params[name] = eval(type)
                    print(params)

            if ql.archtype == QL_ARCH.X86:
                if cc == STDCALL:
                    return ql.os.x86_stdcall(param_num, params, func, args, kwargs)
                elif cc == CDECL:
                    return ql.os.x86_cdecl(param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.X8664:
                return ql.os.x8664_fastcall(param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown self.ql.arch")
        return wrapper

    return decorator
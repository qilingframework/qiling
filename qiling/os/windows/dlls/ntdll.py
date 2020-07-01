#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
import qiling.os.windows.structs

dllname = 'ntdll_dll'

# void *memcpy(
#    void *dest,
#    const void *src,
#    size_t count
# );
@winsdkapi(cc=CDECL, dllname=dllname, replace_params={"dest": POINTER, "src": POINTER, "count": UINT})
def hook_memcpy(ql, address, params):
    try:
        data = bytes(ql.mem.read(params['src'], params['count']))
        ql.mem.write(params['dest'], data)
    except Exception as e:
        import traceback
        ql.print(traceback.format_exc())
        ql.print(e)
    return params['dest']


def _QueryInformationProcess(ql, address, params):
    flag = params["ProcessInformationClass"]
    dst = params["ProcessInformation"]
    pt_res = params["ReturnLength"]
    if flag == ProcessDebugFlags:
        value = b"\x01" * 0x4
    elif flag == ProcessDebugPort:
        value = b"\x00" * 0x4
    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET
    elif flag == ProcessBasicInformation:
        pbi = qiling.os.windows.structs.ProcessBasicInformation(ql, exitStatus=0,
                                                                pebBaseAddress=ql.os.heap_base_address, affinityMask=0,
                                                                basePriority=0,
                                                                uniqueId=ql.os.profile.getint("KERNEL", "pid"),
                                                                parentPid=ql.os.profile.getint("KERNEL", "parent_pid"))
        addr = ql.os.heap.alloc(pbi.size)
        pbi.write(addr)
        value = addr.to_bytes(ql.pointersize, "little")
    else:
        ql.dprint(D_INFO, str(flag))
        raise QlErrorNotImplemented("[!] API not implemented")
    ql.dprint(D_RPRT, "[=] The target is checking the debugger via QueryInformationProcess ")
    ql.mem.write(dst, value)
    if pt_res != 0:
        ql.mem.write(pt_res, 0x8.to_bytes(1, byteorder="little"))

    return STATUS_SUCCESS


# NTSTATUS WINAPI ZwQueryInformationProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _Out_     PVOID            ProcessInformation,
#   _In_      ULONG            ProcessInformationLength,
#   _Out_opt_ PULONG           ReturnLength
# );
@winsdkapi(cc=CDECL, dllname=dllname,
           replace_params={"ProcessHandle": HANDLE, "ProcessInformationClass": INT, "ProcessInformation": POINTER,
                      "ProcessInformationLength": UINT, "ReturnLength": POINTER})
def hook_ZwQueryInformationProcess(ql, address, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(ql, address, params)


# __kernel_entry NTSTATUS NtQueryInformationProcess(
#   IN HANDLE           ProcessHandle,
#   IN PROCESSINFOCLASS ProcessInformationClass,
#   OUT PVOID           ProcessInformation,
#   IN ULONG            ProcessInformationLength,
#   OUT PULONG          ReturnLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_NtQueryInformationProcess(ql, address, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(ql, address, params)

def _QuerySystemInformation(ql, address, params):
    siClass = params["SystemInformationClass"]
    pt_res = params["ReturnLength"]
    dst = params["SystemInformation"]
    if (siClass == SystemBasicInformation):
        bufferLength = params["SystemInformationLength"]
        if (ql.archtype == QL_ARCH.X8664):
            sbi = qiling.os.windows.structs.SystemBasicInforation(ql,
                                                              Reserved=0,
                                                              TimerResolution = 156250 ,
                                                              PageSize=ql.os.heap.page_size,
                                                              NumberOfPhysicalPages = 0x003FC38A,
                                                              LowestPhysicalPageNumber=1,
                                                              HighestPhysicalPageNumber=0x0046DFFF,
                                                              AllocationGranularity=1,
                                                              MinimumUserModeAddress=0x10000,
                                                              MaximumUserModeAddress=0x7FFFFFFEFFFF,
                                                              ActiveProcessorsAffinityMask = 0x3F,
                                                              NumberOfProcessors = 0x6)
        elif ql.archtype == QL_ARCH.X86:
            sbi = qiling.os.windows.structs.SystemBasicInforation(ql,
                                                                  Reserved=0,
                                                                  TimerResolution=156250,
                                                                  PageSize=ql.os.heap.page_size,
                                                                  NumberOfPhysicalPages=0x003FC38A,
                                                                  LowestPhysicalPageNumber=1,
                                                                  HighestPhysicalPageNumber=0x0046DFFF,
                                                                  AllocationGranularity=1,
                                                                  MinimumUserModeAddress=0x10000,
                                                                  MaximumUserModeAddress=0x7FFEFFFF,
                                                                  ActiveProcessorsAffinityMask=0x3F,
                                                                  NumberOfProcessors=0x6)
        if (bufferLength==sbi.size):
            sbi.write(dst)
            if pt_res != 0:
                ql.mem.write(pt_res, sbi.size.to_bytes(1, byteorder="little"))
        else:
            if pt_res != 0:
                ql.mem.write(pt_res, sbi.size.to_bytes(1, byteorder="little"))
            return STATUS_INFO_LENGTH_MISMATCH
    else:
        ql.dprint(D_INFO, str(siClass))
        raise QlErrorNotImplemented("[!] API not implemented")


    return STATUS_SUCCESS

# __kernel_entry NTSTATUS NtQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname,
                replace_params={"SystemInformationClass": UINT, "SystemInformation": POINTER, "SystemInformationLength": SIZE_T,
                    "ReturnLength": POINTER})
def hook_NtQuerySystemInformation(ql, address, params):
    # In minwindef.h
    # #define WINAPI      __stdcall

    _QuerySystemInformation(ql, address, params)

# pub unsafe extern "system" fn ZwQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname,
                replace_params={"SystemInformationClass": UINT, "SystemInformation": POINTER, "SystemInformationLength": SIZE_T,
                    "ReturnLength": POINTER})
def hook_ZwQuerySystemInformation(ql, address, params):
    # In minwindef.h
    # #define WINAPI      __stdcall

    return _QuerySystemInformation(ql, address, params)

# pub unsafe extern "system" fn ZwCreateDebugObject(
#     DebugObjectHandle: PHANDLE,
#     DesiredAccess: ACCESS_MASK,
#     ObjectAttributes: POBJECT_ATTRIBUTES,
#     Flags: ULONG
# ) -> NTSTATUS
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"DebugObjectHandle": HANDLE, "DesiredAccess": INT,
                                                   "ObjectAttributes": POINTER, "Flags": ULONGLONG})
def hook_ZwCreateDebugObject(ql, address, params):
    # FIXME: find documentation, almost none was found online, and create the correct object
    handle = Handle(id=params["DebugObjectHandle"])
    ql.os.handle_manager.append(handle)
    return STATUS_SUCCESS


# __kernel_entry NTSYSCALLAPI NTSTATUS NtQueryObject(
#   HANDLE                   Handle,
#   OBJECT_INFORMATION_CLASS ObjectInformationClass,
#   PVOID                    ObjectInformation,
#   ULONG                    ObjectInformationLength,
#   PULONG                   ReturnLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_ZwQueryObject(ql, address, params):
    infoClass = params["ObjectInformationClass"]
    dest = params["ObjectInformation"]
    size_dest = params["ReturnLength"]
    string = "DebugObject".encode("utf-16le")
    string_addr = ql.os.heap.alloc(len(string))
    ql.dprint(0, str(string_addr))
    ql.dprint(0, str(string))
    ql.mem.write(string_addr, string)
    us = qiling.os.windows.structs.UnicodeString(ql, length=len(string), maxLength=len(string),
                                                 buffer=string_addr)

    if infoClass == ObjectTypeInformation:
        res = qiling.os.windows.structs.ObjectTypeInformation(ql, us, 1, 1)
    elif infoClass == ObjectAllTypesInformation:
        # FIXME: there is an error in how these structs are read by al-khaser. Have no idea on where, so we are
        #  bypassing it
        # oti = qiling.os.windows.structs.ObjectTypeInformation(ql, us, 1, 1)
        # res = qiling.os.windows.structs.ObjectAllTypesInformation(ql, 2, oti)
        return 1
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    if dest != 0 and params["Handle"] != 0:
        res.write(dest)
    if size_dest != 0:
        ql.mem.write(size_dest, res.size.to_bytes(4, "little"))

    return STATUS_SUCCESS


# NTSYSAPI
# NTSTATUS
# NTAPI
# NtYieldExecution(
#  );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_ZwYieldExecution(ql, address, params):
    # FIXME: offer timeslice of this thread
    return STATUS_NO_YIELD_PERFORMED


# NTSTATUS LdrGetProcedureAddress(
#  IN HMODULE              ModuleHandle,
#  IN PANSI_STRING         FunctionName OPTIONAL,
#  IN WORD                 Oridinal OPTIONAL,
#  OUT PVOID               *FunctionAddress );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"ModuleHandle": POINTER,
    "FunctionName": STRING, "Ordinal": UINT, "FunctionAddress": POINTER})
def hook_LdrGetProcedureAddress(ql, address, params):
    if params['FunctionName']:
        identifier = bytes(params["lpProcName"], 'ascii')
    else:
        identifier = params['Ordinal']
    # Check if dll is loaded
    try:
        dll_name = [key for key, value in ql.loader.dlls.items() if value == params['ModuleHandle']][0]
    except IndexError as ie:
        ql.nprint('[!] Failed to import function "%s" with handle 0x%X' % (lpProcName, params['ModuleHandle']))
        return 0

    if identifier in ql.loader.import_address_table[dll_name]:
        addr = ql.loader.import_address_table[dll_name][identifier]
        ql.mem.write(addr.to_bytes(length=ql.pointersize, byteorder='little'), params['FunctionAddress'])
        return 0

    return 0xFFFFFFFF


# NTSYSAPI PVOID RtlAllocateHeap(
#  PVOID  HeapHandle,
#  ULONG  Flags,
#  SIZE_T Size
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"HeapHandle": POINTER,
    "Flags": UINT,"Size": SIZE_T})
def hook_RtlAllocateHeap(ql, address, params):
    ret = ql.os.heap.alloc(params["Size"])
    return ret


# wchar_t* wcsstr( const wchar_t* dest, const wchar_t* src );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"dest": POINTER, "src": WSTRING})
def hook_wcsstr(ql, address, params):
    dest = params["dest"]
    value = ql.os.read_wstring(dest)
    params["dest"] = value
    src = params["src"]
    if src in value:
        pos = value.index(src)
        return dest + post
    return 0


# HANDLE CsrGetProcessId();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CsrGetProcessId(ql, address, params):
    pid = ql.os.profile["PROCESSES"].getint("csrss.exe", fallback=12345)
    return pid
#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

from qiling.const import QL_ARCH
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.handle import *
from qiling.os.windows import structs

# void *memcpy(
#    void *dest,
#    const void *src,
#    size_t count
# );
@winsdkapi(cc=CDECL, params={
    'dest'  : POINTER,
    'src'   : POINTER,
    'count' : UINT
})
def hook_memcpy(ql: Qiling, address: int, params):
    dest = params['dest']
    src = params['src']
    count = params['count']

    data = bytes(ql.mem.read(src, count))
    ql.mem.write(dest, data)

    return dest

def _QueryInformationProcess(ql: Qiling, address: int, params):
    flag = params["ProcessInformationClass"]
    obuf_ptr = params["ProcessInformation"]
    obuf_len = params['ProcessInformationLength']
    res_size_ptr = params["ReturnLength"]

    if flag == ProcessDebugFlags:
        res_data = ql.pack32(0)     # was 0x01010101, no idea why

    elif flag == ProcessDebugPort:
        res_data = ql.pack32(0)

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBasicInformation:
        kconf = ql.os.profile['KERNEL']

        pbi = structs.make_process_basic_info(ql.arch.bits,
            ExitStatus=0,
            PebBaseAddress=ql.loader.TEB.PebAddress,
            AffinityMask=0,
            BasePriority=0,
            UniqueProcessId=kconf.getint('pid'),
            InheritedFromUniqueProcessId=kconf.getint('parent_pid')
        )

        res_data = bytes(pbi)

    else:
        # TODO: support more info class ("flag") values
        ql.log.info(f'SetInformationProcess: no implementation for info class {flag:#04x}')

        return STATUS_UNSUCCESSFUL

    res_size = len(res_data)

    if obuf_len >= res_size:
        ql.mem.write(obuf_ptr, res_data)

    if res_size_ptr:
        ql.mem.write_ptr(res_size_ptr, res_size)

    return STATUS_SUCCESS

# NTSTATUS WINAPI ZwQueryInformationProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _Out_     PVOID            ProcessInformation,
#   _In_      ULONG            ProcessInformationLength,
#   _Out_opt_ PULONG           ReturnLength
# );
@winsdkapi(cc=CDECL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG,
    'ReturnLength'             : PULONG
})
def hook_ZwQueryInformationProcess(ql: Qiling, address: int, params):
    # TODO have no idea if is cdecl or stdcall

    return _QueryInformationProcess(ql, address, params)

# __kernel_entry NTSTATUS NtQueryInformationProcess(
#   IN HANDLE           ProcessHandle,
#   IN PROCESSINFOCLASS ProcessInformationClass,
#   OUT PVOID           ProcessInformation,
#   IN ULONG            ProcessInformationLength,
#   OUT PULONG          ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG,
    'ReturnLength'             : PULONG
})
def hook_NtQueryInformationProcess(ql: Qiling, address: int, params):
    # TODO have no idea if is cdecl or stdcall

    return _QueryInformationProcess(ql, address, params)

def _QuerySystemInformation(ql: Qiling, address: int, params):
    siClass = params["SystemInformationClass"]
    pt_res = params["ReturnLength"]
    dst = params["SystemInformation"]

    if (siClass == SystemBasicInformation):
        bufferLength = params["SystemInformationLength"]

        max_uaddr = {
            QL_ARCH.X86  : 0x7FFEFFFF,
            QL_ARCH.X8664: 0x7FFFFFFEFFFF
        }[ql.arch.type]

        sbi = structs.SystemBasicInforation(
            ql,
            Reserved=0,
            TimerResolution=156250,
            PageSize=ql.mem.pagesize,
            NumberOfPhysicalPages=0x003FC38A,
            LowestPhysicalPageNumber=1,
            HighestPhysicalPageNumber=0x0046DFFF,
            AllocationGranularity=1,
            MinimumUserModeAddress=0x10000,
            MaximumUserModeAddress=max_uaddr,
            ActiveProcessorsAffinityMask=0x3F,
            NumberOfProcessors=0x6
        )

        if (bufferLength==sbi.size):
            sbi.write(dst)

            if pt_res:
                ql.mem.write_ptr(pt_res, sbi.size, 1)
        else:
            if pt_res:
                ql.mem.write_ptr(pt_res, sbi.size, 1)

            return STATUS_INFO_LENGTH_MISMATCH
    else:
        ql.log.debug(str(siClass))
        raise QlErrorNotImplemented("API not implemented")

    return STATUS_SUCCESS

# __kernel_entry NTSTATUS NtQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass'  : SYSTEM_INFORMATION_CLASS,
    'SystemInformation'       : PVOID,
    'SystemInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_NtQuerySystemInformation(ql: Qiling, address: int, params):
    # In minwindef.h
    # #define WINAPI      __stdcall

    _QuerySystemInformation(ql, address, params)

# pub unsafe extern "system" fn ZwQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass'  : SYSTEM_INFORMATION_CLASS,
    'SystemInformation'       : PVOID,
    'SystemInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_ZwQuerySystemInformation(ql: Qiling, address: int, params):
    # In minwindef.h
    # #define WINAPI      __stdcall

    return _QuerySystemInformation(ql, address, params)

# pub unsafe extern "system" fn ZwCreateDebugObject(
#     DebugObjectHandle: PHANDLE,
#     DesiredAccess: ACCESS_MASK,
#     ObjectAttributes: POBJECT_ATTRIBUTES,
#     Flags: ULONG
# ) -> NTSTATUS
@winsdkapi(cc=STDCALL, params={
    'DebugObjectHandle' : PHANDLE,
    'DesiredAccess'     : ACCESS_MASK,
    'ObjectAttributes'  : POBJECT_ATTRIBUTES,
    'Flags'             : ULONG
})
def hook_ZwCreateDebugObject(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'Handle'                  : HANDLE,
    'ObjectInformationClass'  : OBJECT_INFORMATION_CLASS,
    'ObjectInformation'       : PVOID,
    'ObjectInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_ZwQueryObject(ql: Qiling, address: int, params):
    infoClass = params["ObjectInformationClass"]
    dest = params["ObjectInformation"]
    size_dest = params["ReturnLength"]
    string = "DebugObject".encode("utf-16le")

    string_addr = ql.os.heap.alloc(len(string))
    ql.log.debug(str(string_addr))
    ql.log.debug(str(string))
    ql.mem.write(string_addr, string)
    us = structs.UnicodeString(ql, len(string), len(string), string_addr)

    if infoClass == ObjectTypeInformation:
        res = structs.ObjectTypeInformation(ql, us, 1, 1)

    elif infoClass == ObjectAllTypesInformation:
        # FIXME: there is an error in how these structs are read by al-khaser. Have no idea on where, so we are
        #  bypassing it
        # oti = structs.ObjectTypeInformation(ql, us, 1, 1)
        # res = structs.ObjectAllTypesInformation(ql, 2, oti)
        return 1

    else:
        raise QlErrorNotImplemented("API not implemented")

    if dest and params["Handle"]:
        res.write(dest)

    if size_dest:
        ql.mem.write_ptr(size_dest, res.size, 4)

    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS NTAPI NtSetInformatonProcess(
#   _In_      HANDLE           ProcessHandle,
#   _In_      PROCESSINFOCLASS ProcessInformationClass,
#   _In_      PVOID            ProcessInformation
#   _In_      ULONG            ProcessInformationLength
# );
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG
})
def hook_ZwSetInformationProcess(ql: Qiling, address: int, params):
    _SetInformationProcess(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG
})
def hook_NtSetInformationProcess(ql: Qiling, address: int, params):
    _SetInformationProcess(ql, address, params)

def _SetInformationProcess(ql: Qiling, address: int, params):
    process = params["ProcessHandle"]
    flag = params["ProcessInformationClass"]
    dst = params["ProcessInformation"]
    dst_size = params["ProcessInformationLength"]

    if flag == ProcessDebugFlags:
        value = b"\x01" * 0x4

    elif flag == ProcessDebugPort:
        value = b"\x00" * 0x4

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBreakOnTermination:
            ql.log.debug("The target may be attempting modify a the 'critical' flag of the process")  

    elif flag == ProcessExecuteFlags:
        ql.log.debug("The target may be attempting to modify DEP for the process")

        if dst:
            ql.mem.write_ptr(dst, 0, 1)

    elif flag == ProcessBasicInformation:
        kconf = ql.os.profile['KERNEL']

        pbi = structs.make_process_basic_info(ql.arch.bits,
            ExitStatus=0,
            PebBaseAddress=ql.loader.TEB.PebAddress,
            AffinityMask=0,
            BasePriority=0,
            UniqueProcessId=kconf.getint('pid'),
            InheritedFromUniqueProcessId=kconf.getint('parent_pid')
        )

        ql.log.debug("The target may be attempting to modify the PEB debug flag")
        value = bytes(pbi)

    else:
        # TODO: support more info class ("flag") values
        ql.log.info(f'SetInformationProcess: no implementation for info class {flag:#04x}')

        return STATUS_UNSUCCESSFUL

    # TODO: value is never used after assignment

    return STATUS_SUCCESS

# NTSYSAPI
# NTSTATUS
# NTAPI
# NtYieldExecution(
#  );
@winsdkapi(cc=STDCALL, params={})
def hook_ZwYieldExecution(ql: Qiling, address: int, params):
    # FIXME: offer timeslice of this thread
    return STATUS_NO_YIELD_PERFORMED

# NTSTATUS LdrGetProcedureAddress(
#  IN HMODULE              ModuleHandle,
#  IN PANSI_STRING         FunctionName OPTIONAL,
#  IN WORD                 Oridinal OPTIONAL,
#  OUT PVOID               *FunctionAddress );
@winsdkapi(cc=STDCALL, params={
    'ModuleHandle'    : HMODULE,
    'FunctionName'    : PANSI_STRING,
    'Ordinal'         : WORD,
    'FunctionAddress' : POINTER
})
def hook_LdrGetProcedureAddress(ql: Qiling, address: int, params):
    ModuleHandle = params['ModuleHandle']
    FunctionName = params['FunctionName']
    Ordinal = params['Ordinal']
    FunctionAddress = params['FunctionAddress']

    # Check if dll is loaded
    dll_name = next((os.path.basename(path).casefold() for base, _, path in ql.loader.images if base == ModuleHandle), None)

    if dll_name is None:
        ql.log.debug(f'Could not find specified handle {ModuleHandle} in loaded DLL')
        return 0

    identifier = bytes(FunctionName, 'ascii') if FunctionName else Ordinal
    iat = ql.loader.import_address_table[dll_name]

    if identifier in iat:
        ql.mem.write_ptr(FunctionAddress, iat[identifier])
        return 0

    return 0xFFFFFFFF

# NTSYSAPI PVOID RtlAllocateHeap(
#  PVOID  HeapHandle,
#  ULONG  Flags,
#  SIZE_T Size
# );
@winsdkapi(cc=STDCALL, params={
    'HeapHandle' : PVOID,
    'Flags'      : ULONG,
    'Size'       : SIZE_T
})
def hook_RtlAllocateHeap(ql: Qiling, address: int, params):
    return ql.os.heap.alloc(params["Size"])

# wchar_t* wcsstr( const wchar_t* dest, const wchar_t* src );
@winsdkapi(cc=STDCALL, params={
    'dest' : POINTER, # WSTRING
    'src'  : WSTRING
})
def hook_wcsstr(ql: Qiling, address: int, params):
    dest = params["dest"]
    src = params["src"]

    dest_str = ql.os.utils.read_wstring(dest)

    if src in dest_str:
        return dest + dest_str.index(src)

    return 0

# HANDLE CsrGetProcessId();
@winsdkapi(cc=STDCALL, params={})
def hook_CsrGetProcessId(ql: Qiling, address: int, params):
    pid = ql.os.profile["PROCESSES"].getint("csrss.exe", fallback=12345)
    return pid
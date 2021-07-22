#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

from qiling.const import QL_ARCH
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.utils import *
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

    try:
        data = bytes(ql.mem.read(src, count))
        ql.mem.write(dest, data)
    except Exception as e:
        ql.log.exception("")

    return dest

def _QueryInformationProcess(ql: Qiling, address: int, params):
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
        pbi = structs.ProcessBasicInformation(ql,
            exitStatus=0,
            pebBaseAddress=ql.os.heap_base_address, affinityMask=0,
            basePriority=0,
            uniqueId=ql.os.profile.getint("KERNEL", "pid"),
            parentPid=ql.os.profile.getint("KERNEL", "parent_pid")
        )

        addr = ql.os.heap.alloc(pbi.size)
        pbi.write(addr)
        value = addr.to_bytes(ql.pointersize, "little")
    else:
        ql.log.debug(str(flag))
        raise QlErrorNotImplemented("API not implemented")

    ql.log.debug("The target is checking the debugger via QueryInformationProcess ")
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
@winsdkapi(cc=CDECL, params={
    'ProcessHandle'            : HANDLE,
    'ProcessInformationClass'  : PROCESSINFOCLASS,
    'ProcessInformation'       : PVOID,
    'ProcessInformationLength' : ULONG,
    'ReturnLength'             : PULONG
})
def hook_ZwQueryInformationProcess(ql: Qiling, address: int, params):
    # TODO have no idea if is cdecl or stdcall

    _QueryInformationProcess(ql, address, params)

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

    _QueryInformationProcess(ql, address, params)

def _QuerySystemInformation(ql: Qiling, address: int, params):
    siClass = params["SystemInformationClass"]
    pt_res = params["ReturnLength"]
    dst = params["SystemInformation"]

    if (siClass == SystemBasicInformation):
        bufferLength = params["SystemInformationLength"]

        max_uaddr = {
            QL_ARCH.X86  : 0x7FFEFFFF,
            QL_ARCH.X8664: 0x7FFFFFFEFFFF
        }[ql.archtype]

        sbi = structs.SystemBasicInforation(
            ql,
            Reserved=0,
            TimerResolution=156250,
            PageSize=ql.os.heap.page_size,
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

            if pt_res != 0:
                ql.mem.write(pt_res, sbi.size.to_bytes(1, byteorder="little"))
        else:
            if pt_res != 0:
                ql.mem.write(pt_res, sbi.size.to_bytes(1, byteorder="little"))

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

    if dest != 0 and params["Handle"] != 0:
        res.write(dest)

    if size_dest != 0:
        ql.mem.write(size_dest, res.size.to_bytes(4, "little"))

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
    pt_res = params["ReturnLength"]

    if flag == ProcessDebugFlags:
        value = b"\x01" * 0x4

    elif flag == ProcessDebugPort:
        value = b"\x00" * 0x4

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBreakOnTermination:
            ql.log.debug("The target may be attempting modify a the 'critical' flag of the process")  

    elif flag  == ProcessExecuteFlags:
        ql.log.debug("The target may be attempting to modify DEP for the process")

        if dst != 0:
            ql.mem.write(dst, 0x0.to_bytes(1, byteorder="little"))

    elif flag == ProcessBasicInformation:
        pbi = structs.ProcessBasicInformation(
            ql,
            exitStatus=0,
            pebBaseAddress=ql.os.heap_base_address, affinityMask=0,
            basePriority=0,
            uniqueId=ql.os.profile.getint("KERNEL", "pid"),
            parentPid=ql.os.profile.geting("KERNEL", "parent_pid")
        )

        ql.log.debug("The target may be attempting to modify the PEB debug flag")
        addr = ql.os.heap.alloc(pbi.size)
        pbi.write(addr)
        value = addr.to_bytes(ql.pointersize, "little")
    else:
        ql.log.debug(str(flag))
        raise QlErrorNotImplemented("API not implemented")

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
    dll_name = next((key for key, value in ql.loader.dlls.items() if value == ModuleHandle), None)

    if dll_name is None:
        ql.log.debug(f'Could not find specified handle {ModuleHandle} in loaded DLL')
        return 0

    identifier = bytes(FunctionName, 'ascii') if FunctionName else Ordinal

    if identifier in ql.loader.import_address_table[dll_name]:
        addr = ql.loader.import_address_table[dll_name][identifier]
        ql.mem.write(addr.to_bytes(length=ql.pointersize, byteorder='little'), FunctionAddress)
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
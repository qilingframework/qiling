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
from qiling.os.windows import utils

from unicorn.x86_const import *

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
    handle = params["ProcessHandle"]
    flag = params["ProcessInformationClass"]
    obuf_ptr = params["ProcessInformation"]
    obuf_len = params['ProcessInformationLength']
    res_size_ptr = params["ReturnLength"]

    if flag == ProcessDebugFlags:
        res_data = ql.pack32(1)

    elif flag == ProcessDebugPort:
        res_data = ql.pack32(0)

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBasicInformation:
        kconf = ql.os.profile['KERNEL']
        pbi_struct = structs.make_process_basic_info(ql.arch.bits)

        pci_obj = pbi_struct(
            ExitStatus=0,
            PebBaseAddress=ql.loader.TEB.PebAddress,
            AffinityMask=0,
            BasePriority=0,
            UniqueProcessId=kconf.getint('pid'),
            InheritedFromUniqueProcessId=kconf.getint('parent_pid')
        )

        res_data = bytes(pci_obj)

    
    elif flag == ProcessCookie:
        hCurrentProcess = (1 << ql.arch.bits) - 1

        if handle != hCurrentProcess:
            # If a process attempts to query the cookie of another
            # process, then QueryInformationProcess returns an error.
            return STATUS_INVALID_PARAMETER

        # TODO: Change this to something else,
        # maybe a static randomly generated value.
        res_data = ql.pack32(0x00000001)

        if obuf_len != len(res_data):
            # If the buffer length is not ULONG size
            # then QueryInformationProcess returns an error.
            return STATUS_INFO_LENGTH_MISMATCH
    
    else:
        # TODO: support more info class ("flag") values
        ql.log.info(f'QueryInformationProcess: no implementation for info class {flag:#04x}')

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
@winsdkapi(cc=STDCALL, params={
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
    SystemInformationClass = params['SystemInformationClass']
    SystemInformation = params['SystemInformation']
    SystemInformationLength = params['SystemInformationLength']
    ReturnLength = params['ReturnLength']

    if SystemInformationClass == SystemBasicInformation:
        max_uaddr = {
            QL_ARCH.X86  : 0x7FFEFFFF,
            QL_ARCH.X8664: 0x7FFFFFFEFFFF
        }[ql.arch.type]

        sbi_struct = structs.make_system_basic_info(ql.arch.bits)

        # FIXME: retrieve the necessary info from KUSER_SHARED_DATA
        sbi_obj = sbi_struct(
            TimerResolution              = 156250,
            PageSize                     = ql.mem.pagesize,
            NumberOfPhysicalPages        = 0x003FC38A,
            LowestPhysicalPageNumber     = 1,
            HighestPhysicalPageNumber    = 0x0046DFFF,
            AllocationGranularity        = 1,
            MinimumUserModeAddress       = 0x10000,
            MaximumUserModeAddress       = max_uaddr,
            ActiveProcessorsAffinityMask = 0x3F,
            NumberOfProcessors           = 6
        )

        if ReturnLength:
            ql.mem.write_ptr(ReturnLength, sbi_struct.sizeof(), 4)

        if SystemInformationLength < sbi_struct.sizeof():
            return STATUS_INFO_LENGTH_MISMATCH

        sbi_obj.save_to(ql.mem, SystemInformation)

    else:
        raise QlErrorNotImplemented(f'not implemented for {SystemInformationClass=}')

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
    handle = params['Handle']
    ObjectInformationClass = params['ObjectInformationClass']
    ObjectInformation = params['ObjectInformation']
    ObjectInformationLength = params['ObjectInformationLength']
    ReturnLength = params['ReturnLength']

    s = 'DebugObject'.encode('utf-16le')
    addr = ql.os.heap.alloc(len(s))
    ql.mem.write(addr, s)

    unistr_struct = structs.make_unicode_string(ql.arch.bits)

    unistr_obj = unistr_struct(
        Length        = len(s),
        MaximumLength = len(s),
        Buffer        = addr
    )

    oti_struct = structs.make_object_type_info(ql.arch.bits)

    oti_obj = oti_struct(
        TypeName             = unistr_obj,
        TotalNumberOfObjects = 1,
        TotalNumberOfHandles = 1
    )

    oati_struct = structs.make_object_all_types_info(ql.arch.bits, 1)

    if ObjectInformationClass == ObjectTypeInformation:
        out = oti_obj

    elif ObjectInformationClass == ObjectAllTypesInformation:
        # FIXME: al-khaser refers the object named 'DebugObject' twice: the first time it creates a handle
        # for it (so number of handles is expected to be higher than 0) and then closes it. the next time
        # it accesses it (here), it expects the number of handles to be 0.
        #
        # ideally we would track the handles for each object, but since we do not - this is a hack to let
        # it pass.
        oti_obj.TotalNumberOfHandles = 0

        oati_obj = oati_struct(
            NumberOfObjectTypes   = 1,
            ObjectTypeInformation = (oti_obj,)
        )

        out = oati_obj

    else:
        raise QlErrorNotImplemented(f'API not implemented ({ObjectInformationClass=})')

    if ReturnLength:
        ql.mem.write_ptr(ReturnLength, out.sizeof(), 4)

    if ObjectInformationLength < out.sizeof():
        return STATUS_INFO_LENGTH_MISMATCH

    if ObjectInformation and handle:
        out.save_to(ql.mem, ObjectInformation)

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
    ibuf_ptr = params["ProcessInformation"]
    ibuf_len = params["ProcessInformationLength"]

    if flag == ProcessDebugFlags:
        flag_name = 'ProcessDebugFlags'
        comment = ''
        read_len = 4

    elif flag == ProcessDebugPort:
        flag_name = 'ProcessDebugPort'
        comment = ''
        read_len = 4

    elif flag == ProcessDebugObjectHandle:
        return STATUS_PORT_NOT_SET

    elif flag == ProcessBreakOnTermination:
        flag_name = 'ProcessBreakOnTermination'
        comment = 'the critical flag of the process'
        read_len = 1    # FIXME: is it really a single-byte data?

    elif flag == ProcessExecuteFlags:
        flag_name = 'ProcessExecuteFlags'
        comment = 'DEP for the process'
        read_len = 1

    elif flag == ProcessBasicInformation:
        flag_name = 'ProcessBasicInformation'
        comment = 'PEB debug flag for the process'

        pbi_struct = structs.make_process_basic_info(ql.arch.bits)
        read_len = pbi_struct.sizeof()

    else:
        # TODO: support more info class ("flag") values
        ql.log.info(f'SetInformationProcess: no implementation for info class {flag:#04x}')

        return STATUS_UNSUCCESSFUL

    if ibuf_len >= read_len:
        data = (ql.mem.read_ptr if read_len in (1, 2, 4, 8) else ql.mem.read)(ibuf_ptr, read_len)

        ql.log.debug(f'SetInformationProcess: {flag_name} was set to {data}')

        if comment:
            ql.log.debug(f'The target may be attempting modify {comment}')

        # NOTE: we don't actually change anything

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
        return STATUS_DLL_NOT_FOUND

    identifier = utils.read_pansi_string(ql, FunctionName) if FunctionName else Ordinal
    iat = ql.loader.import_address_table[dll_name]

    if not identifier:
        return STATUS_INVALID_PARAMETER

    if identifier not in iat:
        return STATUS_PROCEDURE_NOT_FOUND

    ql.mem.write_ptr(FunctionAddress, iat[identifier])

    return STATUS_SUCCESS


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

# NTSYSAPI PVOID RtlPcToFileHeader(
#   [in]  PVOID PcValue,
#   [out] PVOID *BaseOfImage
# );
@winsdkapi(cc=STDCALL, params={
    'PcValue'    : PVOID,
    'BaseOfImage': PVOID
})
def hook_RtlPcToFileHeader(ql: Qiling, address: int, params):
    pc = params["PcValue"]
    base_of_image_ptr = params["BaseOfImage"]

    containing_image = ql.loader.find_containing_image(pc)

    base_addr = containing_image.base if containing_image else 0

    ql.mem.write_ptr(base_of_image_ptr, base_addr)
    return base_addr

def _FindImageBaseAndFunctionTable(ql: Qiling, control_pc: int, image_base_ptr: int):
    """
    Helper function to locate a containing image for `control_pc` as well as its
    function table, while writing the image base to `image_base_ptr` (if non-zero).
    Returns:
        (base_addr, function_table_addr)
    if no image is found, otherwise
        (0, 0)
    """
    containing_image = ql.loader.find_containing_image(control_pc)

    if containing_image:
        base_addr = containing_image.base
    else:
        base_addr = 0

    # Write base address to the ImageBase pointer, if provided
    if image_base_ptr != 0:
        ql.mem.write_ptr(image_base_ptr, base_addr)

    # If we don’t have a valid base, abort now
    if base_addr == 0:
        return 0, 0

    # Look up the function-table RVA and compute the absolute address
    function_table_rva = ql.loader.function_table_lookup.get(base_addr)
    function_table_addr = base_addr + function_table_rva if function_table_rva else 0

    return base_addr, function_table_addr

# NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(
#   [in]  DWORD64               ControlPc,
#   [out] PDWORD64              ImageBase,
#   [out] PUNWIND_HISTORY_TABLE HistoryTable
# );
@winsdkapi(cc=STDCALL, params={
    'ControlPc': PVOID,
    'ImageBase': PVOID,
    'HistoryTable': PVOID
})
def hook_RtlLookupFunctionEntry(ql: Qiling, address: int, params):
    control_pc = params["ControlPc"]
    image_base_ptr = params["ImageBase"]

    # TODO: Make use of the history table to optimize this function.
    # Alternatively, we could add caching to the loader, seeing as the
    # loader is responsible for lookups in the function table.

    # For simplicity, we are going to ignore the history table.
    # history_table_ptr = params["HistoryTable"]

    # This function should not be getting called on x86.
    if ql.arch.type is QL_ARCH.X86:
        raise QlErrorNotImplemented("RtlLookupFunctionEntry is not implemented for x86")

    base_addr, function_table_addr = _FindImageBaseAndFunctionTable(ql, control_pc, image_base_ptr)

    # If no function table was found, abort.
    if function_table_addr == 0:
        return 0

    # Look up the RUNTIME_FUNCTION entry; we are interested in the index in the table
    # so that we can compute the address.
    runtime_function_idx, runtime_function = ql.loader.lookup_function_entry(base_addr, control_pc)

    # If a suitable function entry was found,
    # compute its address and return.
    if runtime_function:
        return function_table_addr + runtime_function_idx * 12    # sizeof(RUNTIME_FUNCTION)
    
    return 0

# NTSYSAPI
# PRUNTIME_FUNCTION
# RtlLookupFunctionTable (
#     IN PVOID ControlPc,
#     OUT PVOID *ImageBase,
#     OUT PULONG SizeOfTable
# );
@winsdkapi(cc=STDCALL, params={
    'ControlPc': PVOID,
    'ImageBase': PVOID,
    'SizeOfTable': PVOID
})
def hook_RtlLookupFunctionTable(ql: Qiling, address: int, params):
    control_pc = params["ControlPc"]
    image_base_ptr = params["ImageBase"]
    size_of_table_ptr = params["SizeOfTable"]

    # This function should not be getting called on x86.
    if ql.arch.type is QL_ARCH.X86:
        raise QlErrorNotImplemented("RtlLookupFunctionTable is not implemented for x86")

    base_addr, function_table_addr = _FindImageBaseAndFunctionTable(ql, control_pc, image_base_ptr)

    # If no function table was found, abort.
    if function_table_addr == 0:
        ql.mem.write_ptr(size_of_table_ptr, 0, 4)

        return 0
    
    # If a valid pointer for the size was provided,
    # we want to figure out the size of the table.
    if size_of_table_ptr != 0:
        # Look up the function table from the loader,
        # and get the number of entries.
        function_table = ql.loader.function_tables[base_addr]

        # compute the total size of the table
        size_of_table = len(function_table) * 12    # sizeof(RUNTIME_FUNCTION)

        # Write the size to memory at the provided pointer.
        ql.mem.write_ptr(size_of_table_ptr, size_of_table, 4)
    
    return function_table_addr

@winsdkapi(cc=STDCALL, params={})
def hook_LdrControlFlowGuardEnforced(ql: Qiling, address: int, params):
    # There are some checks in ntdll for whether CFG is enabled.
    # We simply bypass these checks by returning 0.
    # May not be necessary, but we do it just in case.
    return 0

# NTSYSAPI
# NTSTATUS
# ZwRaiseException (
#     IN PEXCEPTION_RECORD ExceptionRecord,
#     IN PCONTEXT ContextRecord,
#     IN BOOLEAN FirstChance
# );
@winsdkapi(cc=STDCALL, params={
    'ExceptionRecord': PVOID,
    'ContextRecord': PVOID,
    'FirstChance': BOOLEAN
}, passthru=True)
def hook_ZwRaiseException(ql: Qiling, address: int, params):
    exception_ptr = params['ExceptionRecord']
    context_ptr = params['ContextRecord']
    first_chance = params['FirstChance']

    # The native ZwRaiseException simply uses a syscall to start
    # the kernel exception dispatcher. However, Windows syscalls
    # are not really working in Qiling right now.
    # For now, we just provide a workaround for second-chance
    # exceptions to work.
    # TODO: Get some kind of solution for kernel exception
    # dispatching. This is also needed for first-chance exceptions
    # to work properly on 32-bit Windows.
    if first_chance:
        raise QlErrorNotImplemented("ZwRaiseException is not implemented for first-chance exceptions.")

    # In Windows, an unhandled exception triggers the
    # top-level unhandled exception filter, after which the process
    # is terminated and error reporting services are called.
    # Regardless of whether an unhandled exception filter is present,
    # the process terminates with the same error code that was raised.

    # Our strategy for this hook is to forward second-chance exceptions
    # to the registered unhandled exception filter, if one exists.

    if exception_ptr:
        exception_code = ql.mem.read_ptr(exception_ptr, 4) # exception code is always DWORD
        ql.log.debug(f"[ZwRaiseException] ExceptionCode: 0x{exception_code:08X}")
    else:
        ql.log.debug("[ZwRaiseException] ExceptionRecord is NULL")

    ql.log.debug(f"  ContextRecord: 0x{context_ptr:016X}")
    ql.log.debug(f"  FirstChance: {first_chance}")

    handle = ql.os.handle_manager.search("TopLevelExceptionHandler")

    if handle is None:
        ql.log.debug(f'[ZwRaiseException] No top-level exception filter was found.')
        ql.log.info(f'The process exited with code 0x{exception_code:08X}.')

        ql.os.exit_code = exception_code
        
        ql.emu_stop()
        return

    ret_addr = ql.stack_read(0)

    exception_filter = handle.obj

    # allocate some memory for the EXCEPTION_POINTERS struct
    epointers_struct = structs.make_exception_pointers(ql.arch.bits)
    exception_pointers_ptr = ql.os.heap.alloc(epointers_struct.sizeof())

    with epointers_struct.ref(ql.mem, exception_pointers_ptr) as epointers_obj:
        epointers_obj.ExceptionRecord = exception_ptr
        epointers_obj.ContextRecord = context_ptr

    exception_filter = handle.obj
    ql.log.debug(f'[ZwRaiseException] Resuming execution at the top-level exception filter at 0x{exception_filter:08X}.')

    # Hack: We are going to fake that the caller of ZwRaiseException
    # actually called the unhandled exception filter instead.

    # We will create a hook which will be triggered when the unhandled
    # exception filter returns, so that we may terminate execution.
    def __post_exception_filter(ql: Qiling):
        # Free the exception pointers struct we allocated earlier.
        # Might not be needed, since we are going to terminate the process
        # soon, but we might as well free it.
        ql.os.heap.free(exception_pointers_ptr)

        ql.log.debug(f'[ZwRaiseException] Returned from unhandled exception filter at 0x{exception_filter:08X}.')
        ql.log.info(f'The process exited with code 0x{exception_code:08X}.')

        ql.os.exit_code = exception_code

        ql.emu_stop()

    ql.hook_address(__post_exception_filter, ret_addr)

    exception_filter_args = [(POINTER, exception_pointers_ptr)]

    # Resume execution at the registered unhandled exception filter.
    # If a program is using a custom unhandled exception filter as an anti-debugging
    # trick, then the exception filter might not return.
    
    # TODO: This relies on the hook being marked 'passthru' so that Qiling
    # doesn't rewind after it returns. However, this is not entirely intended
    # behavior of passthru, so this is a bit of a hack. Maybe find some
    # way to rewrite without passthru.
    ql.os.fcall.call_native(exception_filter, exception_filter_args, ret_addr)

# NTSTATUS EtwNotificationRegister(
#   LPCGUID   ProviderGuid,
#   ULONG     Type,
#   PVOID     CallbackFunction,
#   PVOID     CallbackContext,
#   PVOID*    RegistrationHandle
# );
@winsdkapi(cc=STDCALL, params={
    'ProviderGuid': PVOID,
    'Type': DWORD,
    'CallbackFunction': PVOID,
    'CallbackContext': PVOID,
    'RegistrationHandle': PVOID
})
def hook_EtwNotificationRegister(ql: Qiling, address: int, params):
    reg_handle_ptr    = params['RegistrationHandle']

    # It is very important to have a hook for this function
    # because it is called by some Windows DLLs (sechost.dll,
    # advapi32.dll) during initialization when the global
    # CRT lock is held.
    # If a DllMain aborts here, then the global CRT lock is never
    # freed and any attempt to lock the global CRT lock *anywhere*
    # will crash us.

    # TODO: See if a more thorough implementation
    # is needed for this function.

    # For now, just create a dummy handle, and return it.
    handle = Handle()
    ql.os.handle_manager.append(handle)

    if reg_handle_ptr:
        ql.mem.write_ptr(reg_handle_ptr, handle.id)

    return STATUS_SUCCESS

# NTSYSAPI
# VOID RtlRaiseException(
#   PEXCEPTION_RECORD ExceptionRecord
# );
@winsdkapi(cc=STDCALL, params={
    'ExceptionRecord': PVOID
}, passthru=True)
def hook_RtlRaiseException(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# PRUNTIME_FUNCTION RtlVirtualUnwind(
#   DWORD  HandlerType,
#   DWORD64 ImageBase,
#   DWORD64 ControlPc,
#   PRUNTIME_FUNCTION FunctionEntry,
#   PCONTEXT ContextRecord,
#   PVOID* HandlerData,
#   PDWORD64 EstablisherFrame,
#   PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
# );
@winsdkapi(cc=STDCALL, params={
    'HandlerType': DWORD,
    'ImageBase': PVOID,
    'ControlPc': PVOID,
    'FunctionEntry': PVOID,
    'ContextRecord': PVOID,
    'HandlerData': PVOID,
    'EstablisherFrame': PVOID,
    'ContextPointers': PVOID
}, passthru=True)
def hook_RtlVirtualUnwind(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# VOID RtlUnwindEx(
#   PVOID               TargetFrame,
#   PVOID               TargetIp,
#   PEXCEPTION_RECORD   ExceptionRecord,
#   PVOID               ReturnValue,
#   PCONTEXT            OriginalContext,
#   PUNWIND_HISTORY_TABLE HistoryTable
# );
@winsdkapi(cc=STDCALL, params={
    'TargetFrame': PVOID,
    'TargetIp': PVOID,
    'ExceptionRecord': PVOID,
    'ReturnValue': PVOID,
    'OriginalContext': PVOID,
    'HistoryTable': PVOID
}, passthru=True)
def hook_RtlUnwindEx(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# BOOLEAN RtlDispatchException(
#   PEXCEPTION_RECORD ExceptionRecord,
#   PCONTEXT ContextRecord
# );
@winsdkapi(cc=STDCALL, params={
    'ExceptionRecord': PVOID,
    'ContextRecord': PVOID
}, passthru=True)
def hook_RtlDispatchException(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# VOID RtlRestoreContext(
#   PCONTEXT ContextRecord,
#   PEXCEPTION_RECORD ExceptionRecord
# );
@winsdkapi(cc=CDECL, params={
    'ContextRecord': PVOID,
    'ExceptionRecord': PVOID
}, passthru=True)
def hook_RtlRestoreContext(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# VOID RtlCaptureContext(
#   PCONTEXT ContextRecord
# );
@winsdkapi(cc=STDCALL, params={
    'ContextRecord': PVOID
}, passthru=True)
def hook_RtlCaptureContext(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# VOID RtlCaptureContext2(
#   PCONTEXT ContextRecord,
#   ULONG Flags
# );
@winsdkapi(cc=STDCALL, params={
    'ContextRecord': PVOID,
    'Flags': DWORD
}, passthru=True)
def hook_RtlCaptureContext2(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# NTSTATUS RtlInitializeExtendedContext2(
#   USHORT Version,
#   USHORT ContextFlags,
#   ULONG ExtensionCount,
#   ULONG *ExtensionSizes,
#   ULONG BufferSize,
#   PVOID Buffer,
#   PCONTEXT Context,
#   ULONG *LengthReturned
# );
@winsdkapi(cc=STDCALL, params={
    'Version': WORD,
    'ContextFlags': WORD,
    'ExtensionCount': DWORD,
    'ExtensionSizes': PVOID,
    'BufferSize': DWORD,
    'Buffer': PVOID,
    'Context': PVOID,
    'LengthReturned': PVOID
}, passthru=True)
def hook_RtlInitializeExtendedContext2(ql: Qiling, address: int, params):
    return

# NTSYSAPI
# NTSTATUS RtlGetExtendedContextLength2(
#   USHORT Version,
#   USHORT ContextFlags,
#   ULONG ExtensionCount,
#   ULONG *ExtensionSizes,
#   PULONG Length
# );
@winsdkapi(cc=STDCALL, params={
    'Version': WORD,
    'ContextFlags': WORD,
    'ExtensionCount': DWORD,
    'ExtensionSizes': PVOID,
    'Length': PVOID
}, passthru=True)
def hook_RtlGetExtendedContextLength2(ql: Qiling, address: int, params):
    return

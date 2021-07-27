#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.structs import *
from qiling.utils import verify_ret

# typedef struct _OSVERSIONINFOW {
#   ULONG dwOSVersionInfoSize;
#   ULONG dwMajorVersion;
#   ULONG dwMinorVersion;
#   ULONG dwBuildNumber;
#   ULONG dwPlatformId;
#   WCHAR szCSDVersion[128];
# }

# NTSYSAPI NTSTATUS RtlGetVersion(
#   PRTL_OSVERSIONINFOW lpVersionInformation
# );
@winsdkapi(cc=CDECL, params={
    'lpVersionInformation' : PRTL_OSVERSIONINFOW
})
def hook_RtlGetVersion(ql: Qiling, address: int, params):
    pointer = params["lpVersionInformation"]

    os = OsVersionInfoW(ql)
    os.read(pointer)
    os.major[0] = ql.os.profile.getint("SYSTEM", "majorVersion")
    os.minor[0] = ql.os.profile.getint("SYSTEM", "minorVersion")
    os.write(pointer)

    ql.log.debug("The target is checking the windows Version!")

    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS ZwSetInformationThread(
#   HANDLE          ThreadHandle,
#   THREADINFOCLASS ThreadInformationClass,
#   PVOID           ThreadInformation,
#   ULONG           ThreadInformationLength
# );
@winsdkapi(cc=STDCALL, params={
    'ThreadHandle'            : HANDLE,
    'ThreadInformationClass'  : THREADINFOCLASS,
    'ThreadInformation'       : PVOID,
    'ThreadInformationLength' : ULONG
})
def hook_ZwSetInformationThread(ql: Qiling, address: int, params):
    thread = params["ThreadHandle"]
    information = params["ThreadInformationClass"]
    dst = params["ThreadInformation"]
    size = params["ThreadInformationLength"]

    if thread == ql.os.thread_manager.cur_thread.id:
        if size >= 100:
            return STATUS_INFO_LENGTH_MISMATCH

        if information == ThreadHideFromDebugger:
            ql.log.debug("The target is checking debugger via SetInformationThread")

            if dst != 0:
                ql.mem.write(dst, ql.pack8(0))
        else:
            raise QlErrorNotImplemented(f'API not implemented {information}')

    else:
        return STATUS_INVALID_HANDLE

    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS ZwClose(
#   HANDLE Handle
# );
@winsdkapi(cc=STDCALL, params={
    'Handle' : HANDLE
})
def hook_ZwClose(ql: Qiling, address: int, params):
    value = params["Handle"]

    handle = ql.os.handle_manager.get(value)

    if handle is None:
        return STATUS_INVALID_HANDLE

    return STATUS_SUCCESS

@winsdkapi(cc=STDCALL, params={
    'Handle' : HANDLE
})
def hook_NtClose(ql: Qiling, address: int, params):
    value = params["Handle"]

    handle = ql.os.handle_manager.get(value)

    if handle is None:
        return STATUS_INVALID_HANDLE

    return STATUS_SUCCESS

# NTSYSAPI ULONG DbgPrintEx(
#   ULONG ComponentId,
#   ULONG Level,
#   PCSTR Format,
#   ...
# );
@winsdkapi(cc=CDECL, params={
    'ComponentId' : ULONG,
    'Level'       : ULONG,
    'Format'      : PCSTR
    # ...
})
def hook_DbgPrintEx(ql: Qiling, address: int, params):
    Format = params['Format']

    if Format == 0:
        Format = "(null)"

    nargs = Format.count("%")
    ptypes = (ULONG, ULONG, POINTER) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[3:]

    count = ql.os.utils.printf(Format, args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count

# ULONG DbgPrint(
#   PCSTR Format,
#   ...
# );
@winsdkapi(cc=CDECL, params={
    'Format': PCSTR
    # ...
})
def hook_DbgPrint(ql: Qiling, address: int, params):
    Format = params['Format']

    if Format == 0:
        Format = "(null)"

    nargs = Format.count("%")
    ptypes = (POINTER, ) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[1:]

    count = ql.os.utils.printf(Format, args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count

def __IoCreateDevice(ql: Qiling, address: int, params):
    DriverObject = params['DriverObject']
    DeviceExtensionSize = params['DeviceExtensionSize']
    DeviceCharacteristics = params['DeviceCharacteristics']
    DeviceObject = params['DeviceObject']

    objcls = {
        QL_ARCH.X86   : DEVICE_OBJECT32,
        QL_ARCH.X8664 : DEVICE_OBJECT64
    }[ql.archtype]

    addr = ql.os.heap.alloc(ctypes.sizeof(objcls))

    device_object = objcls()
    device_object.Type = 3 # FILE_DEVICE_CD_ROM_FILE_SYSTEM ?
    device_object.DeviceExtension = ql.os.heap.alloc(DeviceExtensionSize)
    device_object.Size = ctypes.sizeof(device_object) + DeviceExtensionSize
    device_object.ReferenceCount = 1
    device_object.DriverObject.value = DriverObject
    device_object.NextDevice.value = 0
    device_object.AttachedDevice.value = 0
    device_object.CurrentIrp.value = 0
    device_object.Timer.value = 0
    device_object.Flags = DO_DEVICE_INITIALIZING

    if params.get('Exclusive'):
        device_object.Flags |= DO_EXCLUSIVE

    device_object.Characteristics = DeviceCharacteristics

    ql.mem.write(addr, bytes(device_object)[:])
    ql.mem.write(DeviceObject, ql.pack(addr))

    # update DriverObject.DeviceObject
    ql.loader.driver_object.DeviceObject = addr

    return STATUS_SUCCESS

# NTSTATUS IoCreateDevice(
#   PDRIVER_OBJECT  DriverObject,
#   ULONG           DeviceExtensionSize,
#   PUNICODE_STRING DeviceName,
#   DEVICE_TYPE     DeviceType,
#   ULONG           DeviceCharacteristics,
#   BOOLEAN         Exclusive,
#   PDEVICE_OBJECT  *DeviceObject
# );
@winsdkapi(cc=STDCALL, params={
    'DriverObject'          : PDRIVER_OBJECT,
    'DeviceExtensionSize'   : ULONG,
    'DeviceName'            : PUNICODE_STRING,
    'DeviceType'            : DWORD, # DEVICE_TYPE
    'DeviceCharacteristics' : ULONG,
    'Exclusive'             : BOOLEAN,
    'DeviceObject'          : POINTER
})
def hook_IoCreateDevice(ql: Qiling, address: int, params):
    return __IoCreateDevice(ql, address, params)

# NTSTATUS WdmlibIoCreateDeviceSecure(
#   PDRIVER_OBJECT   DriverObject,
#   ULONG            DeviceExtensionSize,
#   PUNICODE_STRING  DeviceName,
#   DEVICE_TYPE      DeviceType,
#   ULONG            DeviceCharacteristics,
#   BOOLEAN          Exclusive,
#   PCUNICODE_STRING DefaultSDDLString,
#   LPCGUID          DeviceClassGuid,
#   PDEVICE_OBJECT   *DeviceObject
# );
@winsdkapi(cc=STDCALL, params={
    'DriverObject'          : PDRIVER_OBJECT,
    'DeviceExtensionSize'   : ULONG,
    'DeviceName'            : PUNICODE_STRING,
    'DeviceType'            : DWORD,    # DEVICE_TYPE
    'DeviceCharacteristics' : ULONG,
    'Exclusive'             : BOOLEAN,
    'DefaultSDDLString'     : PCUNICODE_STRING,
    'DeviceClassGuid'       : LPCGUID,
    'DeviceObject'          : POINTER
})
def hook_IoCreateDeviceSecure(ql: Qiling, address: int, params):
    return __IoCreateDevice(ql, address, params)

# NTSYSAPI NTSTATUS RtlCreateSecurityDescriptor(
#   PSECURITY_DESCRIPTOR SecurityDescriptor,
#   ULONG                Revision
# );
@winsdkapi(cc=STDCALL, params={
    'SecurityDescriptor' : PSECURITY_DESCRIPTOR,
    'Revision'           : ULONG
})
def hook_RtlCreateSecurityDescriptor(ql: Qiling, address: int, params):
    # TODO
    return STATUS_SUCCESS

# void IoDeleteDevice(
#   PDEVICE_OBJECT DeviceObject
# );
@winsdkapi(cc=STDCALL, params={
    'DeviceObject' : PDEVICE_OBJECT
})
def hook_IoDeleteDevice(ql: Qiling, address: int, params):
    addr = params['DeviceObject']

    ql.os.heap.free(addr)

# NTSTATUS IoCreateSymbolicLink(
#   PUNICODE_STRING SymbolicLinkName,
#   PUNICODE_STRING DeviceName
# );
@winsdkapi(cc=STDCALL, params={
    'SymbolicLinkName' : PUNICODE_STRING,
    'DeviceName'       : PUNICODE_STRING
})
def hook_IoCreateSymbolicLink(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# NTSTATUS IoDeleteSymbolicLink(
#   PUNICODE_STRING SymbolicLinkName
# );
@winsdkapi(cc=STDCALL, params={
    'SymbolicLinkName' : PUNICODE_STRING
})
def hook_IoDeleteSymbolicLink(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# void IofCompleteRequest(
#   PIRP  Irp,
#   CCHAR PriorityBoost
# );
@winsdkapi(cc=STDCALL, params={
    'Irp'           : PIRP,
    'PriorityBoost' : CCHAR
})
def hook_IofCompleteRequest(ql: Qiling, address: int, params):
    pass

# void IoCompleteRequest(
#   PIRP  Irp,
#   CCHAR PriorityBoost
# );
@winsdkapi(cc=STDCALL, params={
    'Irp'           : PIRP,
    'PriorityBoost' : CCHAR
})
def hook_IoCompleteRequest(ql: Qiling, address: int, params):
    pass

### Below APIs are passthru to native implementation, so Qiling core can log API arguments
### These APIs return None regardless, because we do not really implement anything

# NTSYSAPI VOID RtlInitUnicodeString(
#   PUNICODE_STRING         DestinationString,
#   __drv_aliasesMem PCWSTR SourceString
# );
@winsdkapi(cc=STDCALL, params={
    'DestinationString' : PUNICODE_STRING,
    'SourceString'      : PCWSTR
}, passthru=True)
def hook_RtlInitUnicodeString(ql: Qiling, address: int, params):
    return None

# NTSYSAPI VOID RtlCopyUnicodeString(
#  PUNICODE_STRING  DestinationString,
#  PCUNICODE_STRING SourceString
# );
@winsdkapi(cc=STDCALL, params={
    'DestinationString' : PUNICODE_STRING,
    'SourceString'      : PCUNICODE_STRING
}, passthru=True)
def hook_RtlCopyUnicodeString(ql: Qiling, address: int, params):
    return None

# NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(
#   PUNICODE_STRING DestinationString,
#   PCANSI_STRING   SourceString,
#   BOOLEAN         AllocateDestinationString
# );
@winsdkapi(cc=STDCALL, params={
    'DestinationString'         : PUNICODE_STRING,
    'SourceString'              : PCANSI_STRING,
    'AllocateDestinationString' : BOOLEAN
}, passthru=True)
def hook_RtlAnsiStringToUnicodeString(ql: Qiling, address: int, params):
    return None

# NTSYSAPI VOID RtlInitAnsiString(
#   PANSI_STRING          DestinationString,
#   __drv_aliasesMem PCSZ SourceString
# );
@winsdkapi(cc=STDCALL, params={
    'DestinationString' : PANSI_STRING,
    'SourceString'      : PCSZ
}, passthru=True)
def hook_RtlInitAnsiString(ql: Qiling, address: int, params):
    return None

# NTSTATUS RtlUnicodeStringToAnsiString(
#   PANSI_STRING     DestinationString,
#   PCUNICODE_STRING SourceString,
#   BOOLEAN          AllocateDestinationString
# );
@winsdkapi(cc=STDCALL, params={
    'DestinationString'         : PANSI_STRING,
    'SourceString'              : PCUNICODE_STRING,
    'AllocateDestinationString' : BOOLEAN
}, passthru=True)
def hook_RtlUnicodeStringToAnsiString(ql: Qiling, address: int, params):
    return None

# PVOID ExAllocatePool(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes
# );
@winsdkapi(cc=STDCALL, params={
    'PoolType'      : POOL_TYPE,
    'NumberOfBytes' : SIZE_T
})
def hook_ExAllocatePool(ql: Qiling, address: int, params):
    size = params['NumberOfBytes']

    return ql.os.heap.alloc(size)

# PVOID ExAllocatePoolWithTag(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes,
#  ULONG                                          Tag
# );
@winsdkapi(cc=STDCALL, params={
    'PoolType'      : POOL_TYPE,
    'NumberOfBytes' : SIZE_T,
    'Tag'           : ULONG
})
def hook_ExAllocatePoolWithTag(ql: Qiling, address: int, params):
    size = params['NumberOfBytes']

    return ql.os.heap.alloc(size)

# PVOID ExAllocatePoolWithQuotaTag(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes,
#  ULONG                                          Tag
# );
@winsdkapi(cc=STDCALL, params={
    'PoolType'      : POOL_TYPE,
    'NumberOfBytes' : SIZE_T,
    'Tag'           : ULONG
})
def hook_ExAllocatePoolWithQuotaTag(ql: Qiling, address: int, params):
    size = params['NumberOfBytes']

    return ql.os.heap.alloc(size)

# PVOID ExAllocatePoolWithQuota(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes
# );
@winsdkapi(cc=STDCALL, params={
    'PoolType'      : POOL_TYPE,
    'NumberOfBytes' : SIZE_T
})
def hook_ExAllocatePoolWithQuota(ql: Qiling, address: int, params):
    size = params['NumberOfBytes']

    return ql.os.heap.alloc(size)

# PVOID ExAllocatePoolWithTagPriority(
#  __drv_strictTypeMatch(__drv_typeCond)POOL_TYPE        PoolType,
#  SIZE_T                                                NumberOfBytes,
#  ULONG                                                 Tag,
#  __drv_strictTypeMatch(__drv_typeExpr)EX_POOL_PRIORITY Priority
# );
@winsdkapi(cc=STDCALL, params={
    'PoolType'      : POOL_TYPE,
    'NumberOfBytes' : SIZE_T,
    'Tag'           : ULONG,
    'Priority'      : EX_POOL_PRIORITY
})
def hook_ExAllocatePoolWithTagPriority(ql: Qiling, address: int, params):
    size = params['NumberOfBytes']

    return ql.os.heap.alloc(size)

# void ExFreePoolWithTag(
#  PVOID P,
#  ULONG Tag
# );
@winsdkapi(cc=STDCALL, params={
    'P'   : PVOID,
    'Tag' : ULONG
})
def hook_ExFreePoolWithTag(ql: Qiling, address: int, params):
    addr = params['P']

    ql.os.heap.free(addr)

hook_only_routine_address = [b'IoCreateDeviceSecure']

# PVOID MmGetSystemRoutineAddress(
#  PUNICODE_STRING SystemRoutineName
# );
@winsdkapi(cc=STDCALL, params={
    'SystemRoutineName' : PUNICODE_STRING
})
def hook_MmGetSystemRoutineAddress(ql: Qiling, address: int, params):
    SystemRoutineName = bytes(params["SystemRoutineName"], 'ascii')

    # check function name in import table
    for dll_name in ('ntoskrnl.exe', 'ntkrnlpa.exe', 'hal.dll'):
        if dll_name in ql.loader.import_address_table:
            if SystemRoutineName in ql.loader.import_address_table[dll_name]:
                return ql.loader.import_address_table[dll_name][SystemRoutineName]

    # function not found!
    # we check function name in `hook_only_routine_address`.
    if SystemRoutineName in hook_only_routine_address:
        index = hook_only_routine_address.index(SystemRoutineName)
        # found!
        for dll_name in ('ntoskrnl.exe', 'ntkrnlpa.exe', 'hal.dll'):
            if dll_name in ql.loader.dlls:
                # create fake address
                new_function_address = ql.loader.dlls[dll_name] + index + 1
                # update import address table
                ql.loader.import_symbols[new_function_address] = {
                    'name': SystemRoutineName,
                    'ordinal': -1
                }
                return new_function_address
    return 0

# int _wcsnicmp(
#    const wchar_t *string1,
#    const wchar_t *string2,
#    size_t count
# );
@winsdkapi(cc=STDCALL, params={
    'string1' : WSTRING,
    'string2' : WSTRING,
    'count'   : SIZE_T
}, passthru=True)
def hook__wcsnicmp(ql: Qiling, address: int, params):
    return None

# int _strnicmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winsdkapi(cc=STDCALL, params={
    'string1' : WSTRING,
    'string2' : WSTRING,
    'count'   : SIZE_T
}, passthru=True)
def hook__strnicmp(ql: Qiling, address: int, params):
    return None

# int _mbsnicmp(
#    const unsigned char *string1,
#    const unsigned char *string2,
#    size_t count
# );
@winsdkapi(cc=STDCALL, params={
    'string1' : WSTRING,
    'string2' : WSTRING,
    'count'   : SIZE_T
}, passthru=True)
def hook__mbsnicmp(ql: Qiling, address: int, params):
    return None

# int _strnicmp_l(
#    const char *string1,
#    const char *string2,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, params={
    'string1' : WSTRING,
    'string2' : WSTRING,
    'count'   : SIZE_T,
    'locale'  : LOCALE_T
}, passthru=True)
def hook__strnicmp_l(ql: Qiling, address: int, params):
    return None

# int _wcsnicmp_l(
#    const wchar_t *string1,
#    const wchar_t *string2,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, params={
    'string1' : WSTRING,
    'string2' : WSTRING,
    'count'   : SIZE_T,
    'locale'  : LOCALE_T
}, passthru=True)
def hook__wcsnicmp_l(ql: Qiling, address: int, params):
    return None

# int _mbsnicmp_l(
#    const unsigned char *string1,
#    const unsigned char *string2,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, params={
    'string1' : WSTRING,
    'string2' : WSTRING,
    'count'   : SIZE_T,
    'locale'  : LOCALE_T
}, passthru=True)
def hook__mbsnicmp_l(ql: Qiling, address: int, params):
    return None

# wchar_t *wcschr(
#    wchar_t *str,
#    wchar_t c
# );  // C++ only
@winsdkapi(cc=STDCALL, params={
    'str' : WSTRING,
    'c'   : WCHAR
}, passthru=True)
def hook_wcschr(ql: Qiling, address: int, params):
    return None

# BOOLEAN PsGetVersion(
#   PULONG          MajorVersion,
#   PULONG          MinorVersion,
#   PULONG          BuildNumber,
#   PUNICODE_STRING CSDVersion
# );
@winsdkapi(cc=STDCALL, params={
    'MajorVersion' : PULONG,
    'MinorVersion' : PULONG,
    'BuildNumber'  : PULONG,
    'CSDVersion'   : PUNICODE_STRING
}, passthru=True)
def hook_PsGetVersion(ql: Qiling, address: int, params):
    return None

# NTSYSAPI SIZE_T RtlCompareMemory(
#   const VOID *Source1,
#   const VOID *Source2,
#   SIZE_T     Length
# );
@winsdkapi(cc=STDCALL, params={
    'Source1' : POINTER,
    'Source2' : POINTER,
    'Length'  : SIZE_T
}, passthru=True)
def hook_RtlCompareMemory(ql: Qiling, address: int, params):
    return None

hook_NtBuildNumber = 0xF0001DB1

# void KeEnterCriticalRegion();
@winsdkapi(cc=STDCALL, params={})
def hook_KeEnterCriticalRegion(ql: Qiling, address: int, params):
    return None

# void KeLeaveCriticalRegion();
@winsdkapi(cc=STDCALL, params={})
def hook_KeLeaveCriticalRegion(ql: Qiling, address: int, params):
    return None

#PVOID MmMapLockedPagesSpecifyCache(
#  PMDL  MemoryDescriptorList,
#   KPROCESSOR_MODE AccessMode,
#   MEMORY_CACHING_TYPE  CacheType,
#  PVOID RequestedAddress,
#  ULONG BugCheckOnFailure,
#  ULONG  Priority
#);
@winsdkapi(cc=STDCALL, params={
    'MemoryDescriptorList' : PMDL,
    'AccessMode'           : KPROCESSOR_MODE,
    'CacheType'            : MEMORY_CACHING_TYPE,
    'RequestedAddress'     : PVOID,
    'BugCheckOnFailure'    : ULONG,
    'Priority'             : ULONG
})
def hook_MmMapLockedPagesSpecifyCache(ql: Qiling, address: int, params):
    MemoryDescriptorList = params['MemoryDescriptorList']

    mdl_class: ctypes.Structure = {
        QL_ARCH.X8664 : MDL64,
        QL_ARCH.X86   : MDL32
    }[ql.archtype]

    mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(mdl_class))
    mdl = mdl_class.from_buffer(mdl_buffer)

    return mdl.MappedSystemVa.value

# void ProbeForRead(
# const volatile VOID *Address,
# SIZE_T              Length,
# ULONG               Alignment
# );
@winsdkapi(cc=STDCALL, params={
    'Address'   : POINTER,
    'Length'    : SIZE_T,
    'Alignment' : ULONG
})
def hook_ProbeForRead(ql: Qiling, address: int, params):
    return None

# void ProbeForWrite(
# const volatile VOID *Address,
# SIZE_T              Length,
# ULONG               Alignment
# );
@winsdkapi(cc=STDCALL, params={
    'Address'   : POINTER,
    'Length'    : SIZE_T,
    'Alignment' : ULONG
})
def hook_ProbeForWrite(ql: Qiling, address: int, params):
    return None

# int _vsnwprintf(
#    wchar_t *buffer,
#    size_t count,
#    const wchar_t *format,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, params={
    'buffer' : WSTRING,
    'count'  : SIZE_T,
    'format' : WSTRING
    # ...
}, passthru=True)
def hook__vsnwprintf(ql: Qiling, address: int, params):
    return None

# int mbtowc(
#    wchar_t *wchar,
#    const char *mbchar,
#    size_t count
# );
@winsdkapi(cc=STDCALL, params={
    'wchar'  : WSTRING,
    'mbchar' : STRING,
    'count'  : SIZE_T
}, passthru=True)
def hook_mbtowc(ql: Qiling, address: int, params):
    return None

# int _mbtowc_l(
#    wchar_t *wchar,
#    const char *mbchar,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, params={
    'wchar'  : WSTRING,
    'mbchar' : STRING,
    'count'  : SIZE_T,
    'locale' : LOCALE_T
}, passthru=True)
def hook__mbtowc_l(ql: Qiling, address: int, params):
    return None

# WCHAR RtlAnsiCharToUnicodeChar(
#   _Inout_ PUCHAR *SourceCharacter
# );
@winsdkapi(cc=STDCALL, params={
    'SourceCharacter' : STRING
}, passthru=True)
def hook_RtlAnsiCharToUnicodeChar(ql: Qiling, address: int, params):
    return None

# NTSYSAPI NTSTATUS RtlMultiByteToUnicodeN(
#   PWCH       UnicodeString,
#   ULONG      MaxBytesInUnicodeString,
#   PULONG     BytesInUnicodeString,
#   const CHAR *MultiByteString,
#   ULONG      BytesInMultiByteString
# );
@winsdkapi(cc=STDCALL, params={
    'UnicodeString'           : PWCH,
    'MaxBytesInUnicodeString' : ULONG,
    'BytesInUnicodeString'    : PULONG,
    'MultiByteString'         : POINTER,
    'BytesInMultiByteString'  : ULONG,
}, passthru=True)
def hook_RtlMultiByteToUnicodeN(ql: Qiling, address: int, params):
    return None

# __kernel_entry NTSTATUS NtQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
def _NtQuerySystemInformation(ql: Qiling, address: int, params):
    if params["SystemInformationClass"] == 0xb:  # SystemModuleInformation
        # if SystemInformationLength = 0, we return the total size in ReturnLength
        NumberOfModules = 1

        if ql.archbit == 64:
            # only 1 module for ntoskrnl.exe
            # FIXME: let users customize this?
            size = 4 + ctypes.sizeof(RTL_PROCESS_MODULE_INFORMATION64) * NumberOfModules
        else:
            size = 4 + ctypes.sizeof(RTL_PROCESS_MODULE_INFORMATION32) * NumberOfModules

        if params["ReturnLength"] != 0:
            ql.mem.write(params["ReturnLength"], ql.pack(size))

        if params["SystemInformationLength"] < size:
            return STATUS_INFO_LENGTH_MISMATCH

        else:  # return all the loaded modules
            if ql.archbit == 64:
                module = RTL_PROCESS_MODULE_INFORMATION64()
            else:
                module = RTL_PROCESS_MODULE_INFORMATION32()
 
            module.Section = 0
            module.MappedBase = 0

            if ql.loader.is_driver == True:
                module.ImageBase = ql.loader.dlls.get("ntoskrnl.exe")

            module.ImageSize = 0xab000
            module.Flags = 0x8804000
            module.LoadOrderIndex = 0  # order of this module
            module.InitOrderIndex = 0
            module.LoadCount = 1
            module.OffsetToFileName = len(b"\\SystemRoot\\system32\\")
            module.FullPathName = b"\\SystemRoot\\system32\\ntoskrnl.exe"

            process_modules = ql.pack32(NumberOfModules) + bytes(module)
            ql.mem.write(params["SystemInformation"], process_modules)

    return STATUS_SUCCESS

@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass'  : SYSTEM_INFORMATION_CLASS,
    'SystemInformation'       : PVOID,
    'SystemInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_NtQuerySystemInformation(ql: Qiling, address: int, params):
    return _NtQuerySystemInformation(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass'  : SYSTEM_INFORMATION_CLASS,
    'SystemInformation'       : PVOID,
    'SystemInformationLength' : ULONG,
    'ReturnLength'            : PULONG
})
def hook_ZwQuerySystemInformation(ql: Qiling, address: int, params):
    return _NtQuerySystemInformation(ql, address, params)

# void KeInitializeEvent(
#   PRKEVENT   Event,
#   EVENT_TYPE Type,
#   BOOLEAN    State
# );
@winsdkapi(cc=STDCALL, params={
    'Event' : PRKEVENT,
    'Type'  : EVENT_TYPE,
    'State' : BOOLEAN
})
def hook_KeInitializeEvent(ql: Qiling, address: int, params):
    return None

# NTSTATUS IoCsqInitialize(
#   PIO_CSQ                       Csq,
#   PIO_CSQ_INSERT_IRP            CsqInsertIrp,
#   PIO_CSQ_REMOVE_IRP            CsqRemoveIrp,
#   PIO_CSQ_PEEK_NEXT_IRP         CsqPeekNextIrp,
#   PIO_CSQ_ACQUIRE_LOCK          CsqAcquireLock,
#   PIO_CSQ_RELEASE_LOCK          CsqReleaseLock,
#   PIO_CSQ_COMPLETE_CANCELED_IRP CsqCompleteCanceledIrp
# );
@winsdkapi(cc=STDCALL, params={
    'Csq'                    : POINTER,
    'CsqInsertIrp'           : POINTER,
    'CsqRemoveIrp'           : POINTER,
    'CsqPeekNextIrp'         : POINTER,
    'CsqAcquireLock'         : POINTER,
    'CsqReleaseLock'         : POINTER,
    'CsqCompleteCanceledIrp' : POINTER
})
def hook_IoCsqInitialize(ql: Qiling, address: int, params):
    return 0

# void IoStartPacket(
#   PDEVICE_OBJECT DeviceObject,
#   PIRP           Irp,
#   PULONG         Key,
#   PDRIVER_CANCEL CancelFunction
# );
@winsdkapi(cc=STDCALL, params={
    'DeviceObject'   : PDEVICE_OBJECT,
    'Irp'            : PIRP,
    'Key'            : PULONG,
    'CancelFunction' : PDRIVER_CANCEL
}, passthru=True)
def hook_IoStartPacket(ql: Qiling, address: int, params):
    return None

# VOID IoAcquireCancelSpinLock(
#   _Out_ PKIRQL Irql
# );
@winsdkapi(cc=STDCALL, params={
    'Irql' : POINTER
}, passthru=True)
def hook_IoAcquireCancelSpinLock(ql: Qiling, address: int, params):
    return None

# PEPROCESS PsGetCurrentProcess();
@winsdkapi(cc=STDCALL, params={})
def hook_PsGetCurrentProcess(ql: Qiling, address: int, params):
    return ql.eprocess_address

# HANDLE PsGetCurrentProcessId();
@winsdkapi(cc=STDCALL, params={})
def hook_PsGetCurrentProcessId(ql: Qiling, address: int, params):
    # current process ID is 101
    # TODO: let user customize this?
    return ql.os.pid

# NTSTATUS
# IoCreateDriver(
#   IN  PUNICODE_STRING DriverName    OPTIONAL,
#   IN  PDRIVER_INITIALIZE InitializationFunction
# );
@winsdkapi(cc=STDCALL, params={
    'DriverName'             : PUNICODE_STRING,
    'InitializationFunction' : PDRIVER_INITIALIZE
})
def hook_IoCreateDriver(ql: Qiling, address: int, params):
    init_func = params["InitializationFunction"]

    ret_addr = ql.stack_read(0)
    # print("\n\n>>> IoCreateDriver at %x, going to execute function at %x, RET = %x\n" %(address, init_func, ret_addr))

    # save SP & init_sp
    sp = ql.reg.sp
    init_sp = ql.os.init_sp

    ql.os.fcall = ql.os.fcall_select(STDCALL)
    ql.os.fcall.writeParams((
        (POINTER, ql.loader.driver_object_address),
        (POINTER, ql.loader.regitry_path_address)))

    ql.until_addr = ret_addr

    # now lest emualate InitializationFunction
    try:
        ql.run(begin=init_func)
    except UcError as err:
        verify_ret(ql, err)

    # reset SP since emulated function does not cleanup
    ql.reg.sp = sp
    ql.os.init_sp = init_sp

    # ret_addr = ql.stack_read(0)
    # print("\n\nPC = %x, ret = %x\n" %(ql.pc, ret_addr))

    return 0

# void ExSystemTimeToLocalTime(
#   PLARGE_INTEGER SystemTime,
#   PLARGE_INTEGER LocalTime
# );
@winsdkapi(cc=STDCALL,params={
    'SystemTime' : PLARGE_INTEGER,
    'LocalTime'  : PLARGE_INTEGER
}, passthru=True)
def hook_ExSystemTimeToLocalTime(ql: Qiling, address: int, params):
    # FIXME: implement this to customize user timezone?
    return None

# NTSYSAPI VOID RtlTimeToTimeFields(
#   PLARGE_INTEGER Time,
#   PTIME_FIELDS   TimeFields
# );
@winsdkapi(cc=STDCALL, params={
    'Time'       : PLARGE_INTEGER,
    'TimeFields' : PTIME_FIELDS
}, passthru=True)
def hook_RtlTimeToTimeFields(ql: Qiling, address: int, params):
    return None

# int vsprintf_s(
#    char *buffer,
#    size_t numberOfElements,
#    const char *format,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, params={
    'buffer'           : POINTER,
    'numberOfElements' : SIZE_T,
    'format'           : STRING
    # ...
}, passthru=True)
def hook_vsprintf_s(ql: Qiling, address: int, params):
    return None

# int _vsprintf_s_l(
#    char *buffer,
#    size_t numberOfElements,
#    const char *format,
#    locale_t locale,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, params={
    'buffer'           : POINTER,
    'numberOfElements' : SIZE_T,
    'format'           : STRING,
    'locale'           : LOCALE_T
    # ...
}, passthru=True)
def hook__vsprintf_s_l(ql: Qiling, address: int, params):
    return None

# int vswprintf_s(
#    wchar_t *buffer,
#    size_t numberOfElements,
#    const wchar_t *format,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, params={
    'buffer'           : POINTER,
    'numberOfElements' : SIZE_T,
    'format'           : WSTRING
    # ...
}, passthru=True)
def hook_vswprintf_s(ql: Qiling, address: int, params):
    return None

# int _vswprintf_s_l(
#    wchar_t *buffer,
#    size_t numberOfElements,
#    const wchar_t *format,
#    locale_t locale,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, params={
    'buffer'           : POINTER,
    'numberOfElements' : SIZE_T,
    'format'           : WSTRING,
    'locale'           : LOCALE_T
    # ...
}, passthru=True)
def hook__vswprintf_s_l(ql: Qiling, address: int, params):
    return None

# BOOLEAN MmIsAddressValid(
#   PVOID VirtualAddress
# );
@winsdkapi(cc=STDCALL, params={
    'VirtualAddress' : POINTER
})
def hook_MmIsAddressValid(ql: Qiling, address: int, params):
    return 1

# void KeBugCheckEx(
#   ULONG     BugCheckCode,
#   ULONG_PTR BugCheckParameter1,
#   ULONG_PTR BugCheckParameter2,
#   ULONG_PTR BugCheckParameter3,
#   ULONG_PTR BugCheckParameter4
# );
# ULONG_PTR == POINTER
@winsdkapi(cc=STDCALL, params={
    'BugCheckCode'       : ULONG,
    'BugCheckParameter1' : ULONG_PTR,
    'BugCheckParameter2' : ULONG_PTR,
    'BugCheckParameter3' : ULONG_PTR,
    'BugCheckParameter4' : ULONG_PTR
})
def hook_KeBugCheckEx(ql: Qiling, address: int, params):
    pass

# void KeBugCheck(
#   ULONG BugCheckCode
# );
@winsdkapi(cc=STDCALL, params={
    'BugCheckCode' : ULONG
})
def hook_KeBugCheck(ql: Qiling, address: int, params):
    pass

@winsdkapi(cc=STDCALL, params={})
def hook_PsProcessType(ql: Qiling, address: int, params):
    pass

@winsdkapi(cc=STDCALL, params={
    'Process' : POINTER
})
def hook_PsGetProcessImageFileName(ql: Qiling, address: int, params):
    addr = ql.os.heap.alloc(260)
    ql.mem.write(addr, b'C:\\test.exe')

    return addr

# NTSTATUS PsLookupProcessByProcessId(
#   HANDLE    ProcessId,
#   PEPROCESS *Process
# );

@winsdkapi(cc=STDCALL, params={
    "ProcessId" : HANDLE,
    "Process"   : POINTER
})
def hook_PsLookupProcessByProcessId(ql: Qiling, address: int, params):
    ProcessId = params["ProcessId"]
    Process = params["Process"]

    if ql.archbit == 64:
        obj = EPROCESS64
    else:
        obj = EPROCESS32

    addr = ql.os.heap.alloc(ctypes.sizeof(obj))
    ql.mem.write(Process, ql.pack(addr))
    ql.log.info(f'PID = {ProcessId:#x}, addrof(EPROCESS) == {addr:#x}')

    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS ZwOpenKey(
#   PHANDLE            KeyHandle,
#   ACCESS_MASK        DesiredAccess,
#   POBJECT_ATTRIBUTES ObjectAttributes
# );
@winsdkapi(cc=STDCALL, params={
    'KeyHandle'        : PHANDLE,
    'DesiredAccess'    : ACCESS_MASK,
    'ObjectAttributes' : POBJECT_ATTRIBUTES
})
def hook_ZwOpenKey(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

@winsdkapi(cc=STDCALL, params={
    'KeyHandle'        : PHANDLE,
    'DesiredAccess'    : ACCESS_MASK,
    'ObjectAttributes' : POBJECT_ATTRIBUTES
})
def hook_NtOpenKey(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# NTSTATUS
# KeWaitForSingleObject (
#     PVOID Object,
#     KWAIT_REASON WaitReason,
#     KPROCESSOR_MODE WaitMode,
#     BOOLEAN Alertable,
#     PLARGE_INTEGER Timeout
#     );
@winsdkapi(cc=STDCALL, params={
    'Object'     : PVOID,
    'WaitReason' : KWAIT_REASON,
    'WaitMode'   : KPROCESSOR_MODE,
    'Alertable'  : BOOLEAN,
    'Timeout'    : PLARGE_INTEGER
})
def hook_KeWaitForSingleObject(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# LONG_PTR ObfReferenceObject(
#   PVOID Object
# );
@winsdkapi(cc=STDCALL, params={
    'Object' : PVOID
}, passthru=True)
def hook_ObfReferenceObject(ql: Qiling, address: int, params):
    return None

# NTSTATUS PsCreateSystemThread(
#   PHANDLE            ThreadHandle,
#   ULONG              DesiredAccess,
#   POBJECT_ATTRIBUTES ObjectAttributes,
#   HANDLE             ProcessHandle,
#   PCLIENT_ID         ClientId,
#   PKSTART_ROUTINE    StartRoutine,
#   PVOID              StartContext
# );
@winsdkapi(cc=STDCALL, params={
    'ThreadHandle'     : PHANDLE,
    'DesiredAccess'    : ULONG,
    'ObjectAttributes' : POBJECT_ATTRIBUTES,
    'ProcessHandle'    : HANDLE,
    'ClientId'         : PCLIENT_ID,
    'StartRoutine'     : PKSTART_ROUTINE,
    'StartContext'     : PVOID
})
def hook_PsCreateSystemThread(ql: Qiling, address: int, params):
    ThreadHandle = params["ThreadHandle"]
    lpThreadId = params["ClientId"]

    UniqueProcess = 0x4141
    thread_id = 0x1337
    handle_value = 0x31337

    # set lpThreadId
    if lpThreadId != 0:
        ql.mem.write(lpThreadId, ql.pack(UniqueProcess))
        ql.mem.write(lpThreadId + ql.pointersize, ql.pack(thread_id))

    # set lpThreadId
    if ThreadHandle != 0:
        ql.mem.write(ThreadHandle, ql.pack(handle_value))

    # set thread handle
    return STATUS_SUCCESS

# NTSTATUS ObReferenceObjectByHandle(
#   HANDLE                     Handle,
#   ACCESS_MASK                DesiredAccess,
#   POBJECT_TYPE               ObjectType,
#   KPROCESSOR_MODE            AccessMode,
#   PVOID                      *Object,
#   POBJECT_HANDLE_INFORMATION HandleInformation
# );
@winsdkapi(cc=STDCALL, params={
    'Handle'            : HANDLE,
    'DesiredAccess'     : ACCESS_MASK,
    'ObjectType'        : POBJECT_TYPE,
    'AccessMode'        : KPROCESSOR_MODE,
    'Object'            : PVOID,
    'HandleInformation' : POBJECT_HANDLE_INFORMATION
})
def hook_ObReferenceObjectByHandle(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# LONG KeSetEvent(
#   PRKEVENT  Event,
#   KPRIORITY Increment,
#   BOOLEAN   Wait
# );
@winsdkapi(cc=STDCALL, params={
    'Event'     : PRKEVENT,
    'Increment' : KPRIORITY,
    'Wait'      : BOOLEAN
})
def hook_KeSetEvent(ql: Qiling, address: int, params):
    return 0

# LONG KeResetEvent(
#   PRKEVENT  Event,
#   KPRIORITY Increment,
#   BOOLEAN   Wait
# );
@winsdkapi(cc=STDCALL, params={
    'Event'     : PRKEVENT,
    'Increment' : KPRIORITY,
    'Wait'      : BOOLEAN
})
def hook_KeResetEvent(ql: Qiling, address: int, params):
    return 0

# void KeClearEvent(
#   PRKEVENT Event
# );
@winsdkapi(cc=STDCALL, params={
    'Event' : PRKEVENT
})
def hook_KeClearEvent(ql: Qiling, address: int, params):
    return 0

# NTSTATUS PsTerminateSystemThread(
#   NTSTATUS ExitStatus
# );
@winsdkapi(cc=STDCALL, params={
    'ExitStatus' : NTSTATUS
})
def hook_PsTerminateSystemThread(ql: Qiling, address: int, params):
    return 0

# NTSTATUS ObReferenceObjectByPointer(
#   PVOID           Object,
#   ACCESS_MASK     DesiredAccess,
#   POBJECT_TYPE    ObjectType,
#   KPROCESSOR_MODE AccessMode
# );
@winsdkapi(cc=STDCALL, params={
    'Object'        : PVOID,
    'DesiredAccess' : ACCESS_MASK,
    'ObjectType'    : POBJECT_TYPE,
    'AccessMode'    : KPROCESSOR_MODE
})
def hook_ObReferenceObjectByPointer(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# NTSTATUS ObOpenObjectByPointer(
#   PVOID           Object,
#   ULONG           HandleAttributes,
#   PACCESS_STATE   PassedAccessState,
#   ACCESS_MASK     DesiredAccess,
#   POBJECT_TYPE    ObjectType,
#   KPROCESSOR_MODE AccessMode,
#   PHANDLE         Handle
# );
@winsdkapi(cc=STDCALL, params={
    'Object'            : PVOID,
    'HandleAttributes'  : ULONG,
    'PassedAccessState' : PACCESS_STATE,
    'DesiredAccess'     : ACCESS_MASK,
    'ObjectType'        : POBJECT_TYPE,
    'AccessMode'        : KPROCESSOR_MODE,
    'Handle'            : PHANDLE
})
def hook_ObOpenObjectByPointer(ql: Qiling, address: int, params):
    Object = params["Object"]
    point_to_new_handle = params["Handle"]

    new_handle = Handle(name=f'p={Object:x}')
    ql.os.handle_manager.append(new_handle)
    ql.mem.write(point_to_new_handle, ql.pack(new_handle.id))
    ql.log.info(f'New handle of {Object:#x} is {new_handle.id:#x}')

    return STATUS_SUCCESS

@winsdkapi(cc=CDECL, params={})
def hook_ObfDereferenceObject(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
#     IN HANDLE               ProcessHandle OPTIONAL,
#     IN NTSTATUS             ExitStatus );
@winsdkapi(cc=STDCALL, params={
    'ProcessHandle' : HANDLE,
    'ExitStatus'    : NTSTATUS
})
def hook_NtTerminateProcess(ql: Qiling, address: int, params):
    return STATUS_SUCCESS

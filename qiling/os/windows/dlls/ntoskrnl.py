#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.api import *

# typedef struct _OSVERSIONINFOW {
#   ULONG dwOSVersionInfoSize;
#   ULONG dwMajorVersion;
#   ULONG dwMinorVersion;
#   ULONG dwBuildNumber;
#   ULONG dwPlatformId;
#   WCHAR szCSDVersion[128];
# }

from qiling.os.windows.structs import *

dllname = 'kernel32_dll'

# NTSYSAPI NTSTATUS RtlGetVersion(
#   PRTL_OSVERSIONINFOW lpVersionInformation
# );
@winsdkapi(cc=CDECL, dllname=dllname, replace_params={"lpVersionInformation": POINTER})
def hook_RtlGetVersion(ql, address, params):
    pointer = params["lpVersionInformation"]
    os = OsVersionInfoW(ql)
    os.read(pointer)
    os.major[0] = ql.os.profile.getint("SYSTEM", "majorVersion")
    os.minor[0] = ql.os.profile.getint("SYSTEM", "minorVersion")
    os.write(pointer)
    ql.dprint(D_RPRT, "[=] The target is checking the windows Version!")
    return STATUS_SUCCESS


# NTSYSAPI NTSTATUS ZwSetInformationThread(
#   HANDLE          ThreadHandle,
#   THREADINFOCLASS ThreadInformationClass,
#   PVOID           ThreadInformation,
#   ULONG           ThreadInformationLength
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"ThreadHandle": HANDLE,
    "ThreadInformationClass": INT, "ThreadInformation": POINTER, "ThreadInformationLength": UINT})
def hook_ZwSetInformationThread(ql, address, params):
    thread = params["ThreadHandle"]
    information = params["ThreadInformationClass"]
    dst = params["ThreadInformation"]
    size = params["ThreadInformationLength"]

    if thread == ql.os.thread_manager.cur_thread.id:
        if size >= 100:
            return STATUS_INFO_LENGTH_MISMATCH
        if information == ThreadHideFromDebugger:
            ql.dprint(D_RPRT, "[=] The target is checking debugger via SetInformationThread")
            if dst != 0:
                ql.mem.write(dst, 0x0.to_bytes(1, byteorder="little"))
        else:
            raise QlErrorNotImplemented("[!] API not implemented %d " %
                                        information)

    else:
        return STATUS_INVALID_HANDLE
    return STATUS_SUCCESS


# NTSYSAPI NTSTATUS ZwClose(
#   HANDLE Handle
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Handle": HANDLE})
def hook_ZwClose(ql, address, params):
    value = params["Handle"]
    handle = ql.os.handle_manager.get(value)
    if handle is None:
        return STATUS_INVALID_HANDLE
    return STATUS_SUCCESS

@winsdkapi(cc=STDCALL,  replace_params={"Handle": HANDLE})
def hook_NtClose(ql, address, params):
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
@winsdkapi(cc=CDECL, dllname=dllname, param_num=3)
def hook_DbgPrintEx(ql, address, _):
    ret = 0
    format_string = ql.os.get_function_param(3)

    if len(format_string) < 3:
        ql.nprint('0x%0.2x: printf(format = 0x0) = 0x%x\n' % (address, ret))
        return ret

    format_string = read_cstring(ql, format_string[2])

    if format_string.count('%') == 0:
        param_addr = ql.reg.sp + ql.pointersize * 2
    else:
        param_addr = ql.reg.sp + ql.pointersize * 3

    ret, _ = printf(ql, address, format_string, param_addr, "DbgPrintEx")

    ql.os.set_return_value(ret)

    count = format_string.count('%')
    # x8664 fastcall does not known the real number of parameters
    # so we need to manually pop the stack
    if ql.archtype == QL_ARCH.X8664:
        # if number of params > 4
        if count + 1 > 4:
            rsp = ql.uc.reg_read(UC_X86_REG_RSP)
            ql.register(UC_X86_REG_RSP, rsp + (count - 4 + 1) * 8)

    return None

# ULONG DbgPrint(
#   PCSTR Format,
#   ...   
# );
@winsdkapi(cc=CDECL, dllname=dllname, param_num=1)
def hook_DbgPrint(ql, address, _):
    ret = 0
    format_string_addr = ql.os.get_function_param(1)
    format_string = read_cstring(ql, format_string_addr)

    if format_string.count('%') == 0:
        param_addr = ql.reg.sp + ql.pointersize * 2
    else:
        param_addr = ql.reg.sp + ql.pointersize * 3

    ret, _ = printf(ql, address, format_string, param_addr, "DbgPrint")

    ql.os.set_return_value(ql)

    count = format_string.count('%')
    # x8664 fastcall does not known the real number of parameters
    # so we need to manually pop the stack
    if ql.archtype == QL_ARCH.X8664:
        # if number of params > 4
        if count + 1 > 4:
            rsp = ql.uc.reg_read(UC_X86_REG_RSP)
            ql.register(UC_X86_REG_RSP, rsp + (count - 4 + 1) * 8)

    return None


def ntoskrnl_IoCreateDevice(ql, address, params):
    if ql.archtype == QL_ARCH.X86:
        addr = ql.os.heap.alloc(ctypes.sizeof(DEVICE_OBJECT32))
        device_object = DEVICE_OBJECT32()
    elif ql.archtype == QL_ARCH.X8664:
        addr = ql.os.heap.alloc(ctypes.sizeof(DEVICE_OBJECT64))
        device_object = DEVICE_OBJECT64()

    device_object.Type = 3
    device_object.DeviceExtension = ql.os.heap.alloc(
        params['DeviceExtensionSize'])
    device_object.Size = ctypes.sizeof(
        device_object) + params['DeviceExtensionSize']
    device_object.ReferenceCount = 1
    device_object.DriverObject.value = params['DriverObject']
    device_object.NextDevice.value = 0
    device_object.AttachedDevice.value = 0
    device_object.CurrentIrp.value = 0
    device_object.Timer.value = 0
    device_object.Flags = 0x00000080  # DO_DEVICE_INITIALIZING
    if params['Exclusive']:
        device_object.Flags |= 0x00000008  # DO_EXCLUSIVE
    device_object.Characteristics = params['DeviceCharacteristics']
    ql.mem.write(addr, bytes(device_object)[:])
    ql.mem.write(params["DeviceObject"],
                 addr.to_bytes(length=ql.pointersize, byteorder='little'))

    # update DriverObject.DeviceObject
    ql.loader.driver_object.DeviceObject = addr

    return 0


# NTSTATUS IoCreateDevice(
#   PDRIVER_OBJECT  DriverObject,
#   ULONG           DeviceExtensionSize,
#   PUNICODE_STRING DeviceName,
#   DEVICE_TYPE     DeviceType,
#   ULONG           DeviceCharacteristics,
#   BOOLEAN         Exclusive,
#   PDEVICE_OBJECT  *DeviceObject
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "DriverObject": POINTER,
            "DeviceExtensionSize": ULONG,
            "DeviceName": PUNICODE_STRING,
            "DeviceType": DWORD,
            "DeviceCharacteristics": ULONG,
            "Exclusive": BOOLEAN,
            "DeviceObject": POINTER,
        })
def hook_IoCreateDevice(ql, address, params):
    return ntoskrnl_IoCreateDevice(ql, address, params)


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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "DriverObject": POINTER,
            "DeviceExtensionSize": ULONG,
            "DeviceName": PUNICODE_STRING,
            "DeviceType": DWORD,
            "DeviceCharacteristics": ULONG,
            "Exclusive": BOOLEAN,
            "DefaultSDDLString": PCUNICODE_STRING,
            "DeviceClassGuid": ULONG,
            "DeviceObject": POINTER
        })
def hook_IoCreateDeviceSecure(ql, address, params):
    return ntoskrnl_IoCreateDevice(ql, address, params)


# NTSYSAPI NTSTATUS RtlCreateSecurityDescriptor(
#   PSECURITY_DESCRIPTOR SecurityDescriptor,
#   ULONG                Revision
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"SecurityDescriptor": POINTER, "Revision": ULONG})
def hook_RtlCreateSecurityDescriptor(ql, address, params):
    # TODO
    return 0


# void IoDeleteDevice(
#   PDEVICE_OBJECT DeviceObject
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"DeviceObject": POINTER})
def hook_IoDeleteDevice(ql, address, params):
    addr = params['DeviceObject']
    ql.os.heap.free(addr)
    return None


# NTSTATUS IoDeleteSymbolicLink(
#   PUNICODE_STRING SymbolicLinkName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"SymbolicLinkName": PUNICODE_STRING})
def hook_IoDeleteSymbolicLink(ql, address, params):
    return 0


# NTSTATUS IoCreateSymbolicLink(
#   PUNICODE_STRING SymbolicLinkName,
#   PUNICODE_STRING DeviceName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "SymbolicLinkName": PUNICODE_STRING,
            "DeviceName": PUNICODE_STRING
        })
def hook_IoCreateSymbolicLink(ql, address, params):
    return 0


# NTSTATUS IoDeleteSymbolicLink(
#   PUNICODE_STRING SymbolicLinkName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"SymbolicLinkName": PUNICODE_STRING})
def hook_IoDeleteSymbolicLink(ql, address, params):
    return 0


# void IofCompleteRequest(
#   PIRP  Irp,
#   CCHAR PriorityBoost
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Irp": POINTER,
            "PriorityBoost": CCHAR
            })
def hook_IofCompleteRequest(ql, address, params):
    return None


# void IoCompleteRequest(
#   PIRP  Irp,
#   CCHAR PriorityBoost
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Irp": POINTER, "PriorityBoost": CCHAR})
def hook_IoCompleteRequest(ql, address, params):
    return None


### Below APIs are passthru to native implementation, so Qiling core can log API arguments
### These APIs return None regardless, because we do not really implement anything


# NTSYSAPI VOID RtlInitUnicodeString(
#   PUNICODE_STRING         DestinationString,
#   __drv_aliasesMem PCWSTR SourceString
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "DestinationString": POINTER,
            "SourceString": PCWSTR
        })
def hook_RtlInitUnicodeString(ql, address, params):
    return None


# NTSYSAPI VOID RtlCopyUnicodeString(
#  PUNICODE_STRING  DestinationString,
#  PCUNICODE_STRING SourceString
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "DestinationString": PUNICODE_STRING,
            "SourceString": PCUNICODE_STRING
        })
def hook_RtlCopyUnicodeString(ql, address, params):
    return None


# NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(
#   PUNICODE_STRING DestinationString,
#   PCANSI_STRING   SourceString,
#   BOOLEAN         AllocateDestinationString
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "DestinationString": PUNICODE_STRING,
            "SourceString": PCANSI_STRING,
            "AllocateDestinationString": BOOLEAN
        })
def hook_RtlAnsiStringToUnicodeString(ql, address, params):
    return None


# NTSYSAPI VOID RtlInitAnsiString(
#   PANSI_STRING          DestinationString,
#   __drv_aliasesMem PCSZ SourceString
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "DestinationString": PANSI_STRING,
            "SourceString": PCSZ
        })
def hook_RtlInitAnsiString(ql, address, params):
    return None


# NTSTATUS RtlUnicodeStringToAnsiString(
#   PANSI_STRING     DestinationString,
#   PCUNICODE_STRING SourceString,
#   BOOLEAN          AllocateDestinationString
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "DestinationString": POINTER,
            "SourceString": PCUNICODE_STRING,
            "AllocateDestinationString": BOOLEAN
        })
def hook_RtlUnicodeStringToAnsiString(ql, address, params):
    return None


# PVOID ExAllocatePool(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"PoolType": DWORD, "NumberOfBytes": DWORD})
def hook_ExAllocatePool(ql, address, params):
    size = params['NumberOfBytes']
    addr = ql.os.heap.alloc(size)
    return addr


# PVOID ExAllocatePoolWithTag(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes,
#  ULONG                                          Tag
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "PoolType": DWORD,
            "NumberOfBytes": SIZE_T,
            "Tag": DWORD,
        })
def hook_ExAllocatePoolWithTag(ql, address, params):
    size = params['NumberOfBytes']
    addr = ql.os.heap.alloc(size)
    return addr


# PVOID ExAllocatePoolWithQuotaTag(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes,
#  ULONG                                          Tag
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "PoolType": DWORD,
            "NumberOfBytes": SIZE_T,
            "Tag": DWORD,
        })
def hook_ExAllocatePoolWithQuotaTag(ql, address, params):
    size = params['NumberOfBytes']
    addr = ql.os.heap.alloc(size)
    return addr


# PVOID ExAllocatePoolWithQuota(
#  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
#  SIZE_T                                         NumberOfBytes
# );


@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"PoolType": DWORD, "NumberOfBytes": SIZE_T})
def hook_ExAllocatePoolWithQuota(ql, address, params):
    size = params['NumberOfBytes']
    addr = ql.os.heap.alloc(size)
    return addr


# PVOID ExAllocatePoolWithTagPriority(
#  __drv_strictTypeMatch(__drv_typeCond)POOL_TYPE        PoolType,
#  SIZE_T                                                NumberOfBytes,
#  ULONG                                                 Tag,
#  __drv_strictTypeMatch(__drv_typeExpr)EX_POOL_PRIORITY Priority
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "PoolType": DWORD,
            "NumberOfBytes": SIZE_T,
            "Tag": ULONG,
            "Priority": ULONG
        })
def hook_ExAllocatePoolWithTagPriority(ql, address, params):
    size = params['NumberOfBytes']
    addr = ql.os.heap.alloc(size)
    return addr


# void ExFreePoolWithTag(
#  PVOID P,
#  ULONG Tag
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"P": POINTER, "Tag": ULONG})
def hook_ExFreePoolWithTag(ql, address, params):
    addr = params['P']
    ql.os.heap.free(addr)
    return None


hook_only_routine_address = [b'IoCreateDeviceSecure']


# PVOID MmGetSystemRoutineAddress(
#  PUNICODE_STRING SystemRoutineName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "SystemRoutineName": PUNICODE_STRING,
})
def hook_MmGetSystemRoutineAddress(ql, address, params):
    SystemRoutineName = bytes(params["SystemRoutineName"], 'ascii')

    # check function name in import table
    for dll_name in ['ntoskrnl.exe', 'ntkrnlpa.exe', 'hal.dll']:
        if dll_name in ql.loader.import_address_table and SystemRoutineName in ql.loader.import_address_table[
                dll_name]:
            return ql.loader.import_address_table[dll_name][SystemRoutineName]

    # function not found!
    # we check function name in `hook_only_routine_address`.
    if SystemRoutineName in hook_only_routine_address:
        index = hook_only_routine_address.index(SystemRoutineName)
        # found!
        for dll_name in ['ntoskrnl.exe', 'ntkrnlpa.exe', 'hal.dll']:
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
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "string1": WSTRING,
            "string2": WSTRING,
            "count": SIZE_T
        })
def hook__wcsnicmp(ql, address, params):
    return None


# int _strnicmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "string1": STRING,
            "string2": STRING,
            "count": SIZE_T
        })
def hook__strnicmp(ql, address, params):
    return None


# int _mbsnicmp(
#    const unsigned char *string1,
#    const unsigned char *string2,
#    size_t count
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "string1": STRING,
            "string2": STRING,
            "count": SIZE_T
        })
def hook__mbsnicmp(ql, address, params):
    return None


# int _strnicmp_l(
#    const char *string1,
#    const char *string2,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "string1": STRING,
            "string2": STRING,
            "count": SIZE_T,
            "locale": LOCALE_T
        })
def hook__strnicmp_l(ql, address, params):
    return None


# int _wcsnicmp_l(
#    const wchar_t *string1,
#    const wchar_t *string2,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "string1": WSTRING,
            "string2": WSTRING,
            "count": SIZE_T,
            "locale": LOCALE_T
        })
def hook__wcsnicmp_l(ql, address, params):
    return None


# int _mbsnicmp_l(
#    const unsigned char *string1,
#    const unsigned char *string2,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "string1": WSTRING,
            "string2": WSTRING,
            "count": SIZE_T,
            "locale": LOCALE_T
        })
def hook__mbsnicmp_l(ql, address, params):
    return None


# wchar_t *wcschr(
#    wchar_t *str,
#    wchar_t c
# );  // C++ only
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={"str": WSTRING, "c": WCHAR})
def hook_wcschr(ql, address, params):
    return None


# BOOLEAN PsGetVersion(
#   PULONG          MajorVersion,
#   PULONG          MinorVersion,
#   PULONG          BuildNumber,
#   PUNICODE_STRING CSDVersion
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "MajorVersion": POINTER,
            "MinorVersion": POINTER,
            "BuildNumber": POINTER,
            "CSDVersion": PUNICODE_STRING
        })
def hook_PsGetVersion(ql, address, params):
    return None


# NTSYSAPI SIZE_T RtlCompareMemory(
#   const VOID *Source1,
#   const VOID *Source2,
#   SIZE_T     Length
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "Source1": POINTER,
            "Source2": POINTER,
            "Length": SIZE_T
        })
def hook_RtlCompareMemory(ql, address, params):
    return None

hook_NtBuildNumber = 0xF0001DB1

# void KeEnterCriticalRegion();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_KeEnterCriticalRegion(ql, address, params):
    return None


# void KeLeaveCriticalRegion();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_KeLeaveCriticalRegion(ql, address, params):
    return None


#PVOID MmMapLockedPagesSpecifyCache(
#  PMDL  MemoryDescriptorList,
#   KPROCESSOR_MODE AccessMode,
#   MEMORY_CACHING_TYPE  CacheType,
#  PVOID RequestedAddress,
#  ULONG BugCheckOnFailure,
#  ULONG  Priority
#);
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "MemoryDescriptorList": POINTER,
            "AccessMode": ULONG,
            "CacheType": ULONG,
            "RequestedAddress": POINTER,
            "BugCheckOnFailure": ULONG,
            "Priority": ULONG
        })
def hook_MmMapLockedPagesSpecifyCache(ql, address, params):
    MemoryDescriptorList = params['MemoryDescriptorList']
    if ql.archtype == QL_ARCH.X8664:
        mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(MDL64))
        mdl = MDL64.from_buffer(mdl_buffer)
        return mdl.MappedSystemVa.value
    else:
        mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(MDL32))
        mdl = MDL32.from_buffer(mdl_buffer)
        return mdl.MappedSystemVa.value


# void ProbeForRead(
# const volatile VOID *Address,
# SIZE_T              Length,
# ULONG               Alignment
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Address": POINTER,
            "Length": SIZE_T,
            "Alignment": ULONG,
        })
def hook_ProbeForRead(ql, address, params):
    return None


# void ProbeForWrite(
# const volatile VOID *Address,
# SIZE_T              Length,
# ULONG               Alignment
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Address": POINTER,
            "Length": SIZE_T,
            "Alignment": ULONG,
        })
def hook_ProbeForWrite(ql, address, params):
    return None


# int _vsnwprintf(
#    wchar_t *buffer,
#    size_t count,
#    const wchar_t *format,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "buffer": WSTRING,
            "count": SIZE_T,
            "format": WSTRING,
        })
def hook__vsnwprintf(ql, address, params):
    return None


# int mbtowc(
#    wchar_t *wchar,
#    const char *mbchar,
#    size_t count
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "wchar": WSTRING,
            "mbchar": STRING,
            "count": SIZE_T,
        })
def hook_mbtowc(ql, address, params):
    return None


# int _mbtowc_l(
#    wchar_t *wchar,
#    const char *mbchar,
#    size_t count,
#    _locale_t locale
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "wchar": WSTRING,
            "mbchar": STRING,
            "count": SIZE_T,
            "locale": LOCALE_T
        })
def hook__mbtowc_l(ql, address, params):
    return None


# WCHAR RtlAnsiCharToUnicodeChar(
#   _Inout_ PUCHAR *SourceCharacter
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
    "SourceCharacter": STRING,
})
def hook_RtlAnsiCharToUnicodeChar(ql, address, params):
    return None


# NTSYSAPI NTSTATUS RtlMultiByteToUnicodeN(
#   PWCH       UnicodeString,
#   ULONG      MaxBytesInUnicodeString,
#   PULONG     BytesInUnicodeString,
#   const CHAR *MultiByteString,
#   ULONG      BytesInMultiByteString
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "UnicodeString": POINTER,
            "MaxBytesInUnicodeString": ULONG,
            "BytesInUnicodeString": POINTER,
            "MultiByteString": STRING,
            "BytesInMultiByteString": ULONG,
        })
def hook_RtlMultiByteToUnicodeN(ql, address, params):
    return None


# __kernel_entry NTSTATUS NtQuerySystemInformation(
#   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#   OUT PVOID                   SystemInformation,
#   IN ULONG                    SystemInformationLength,
#   OUT PULONG                  ReturnLength
# );
def _NtQuerySystemInformation(ql, address, params):
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
            ql.mem.write( params["ReturnLength"], 
            size.to_bytes(length=ql.pointersize, byteorder='little'))
        if params["SystemInformationLength"] < size:
            return 0xC0000004
        else:  # return all the loaded modules
            if ql.archbit == 64:
                module = RTL_PROCESS_MODULE_INFORMATION64()
            else:
                module = RTL_PROCESS_MODULE_INFORMATION32()

            module.Section = 0
            module.MappedBase = 0
            module.ImageBase = ql.loader.dlls["ntoskrnl.exe"]
            module.ImageSize = 0xab000
            module.Flags = 0x8804000
            module.LoadOrderIndex = 0  # order of this module
            module.InitOrderIndex = 0
            module.LoadCount = 1
            module.OffsetToFileName = len(b"\\SystemRoot\\system32\\")
            module.FullPathName = b"\\SystemRoot\\system32\\ntoskrnl.exe"

            process_modules = NumberOfModules.to_bytes(4, byteorder="little")
            process_modules += bytes(module)
            ql.mem.write(params["SystemInformation"], process_modules)
    return 0

@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "SystemInformationClass": UINT,
            "SystemInformation": POINTER,
            "SystemInformationLength": ULONG,
            "ReturnLength": POINTER,
        })
def hook_NtQuerySystemInformation(ql, address, params):
    return _NtQuerySystemInformation(ql, address, params)

@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "SystemInformationClass": UINT,
            "SystemInformation": POINTER,
            "SystemInformationLength": ULONG,
            "ReturnLength": POINTER,
        })
def hook_ZwQuerySystemInformation(ql, address, params):
    return _NtQuerySystemInformation(ql, address, params)

# void KeInitializeEvent(
#   PRKEVENT   Event,
#   EVENT_TYPE Type,
#   BOOLEAN    State
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Event": POINTER,
            "Type": UINT,
            "State": BOOLEAN,
        })
def hook_KeInitializeEvent(ql, address, params):
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Csq": POINTER,
            "CsqInsertIrp": POINTER,
            "CsqRemoveIrp": POINTER,
            "CsqPeekNextIrp": POINTER,
            "CsqAcquireLock": POINTER,
            "CsqReleaseLock": POINTER,
            "CsqCompleteCanceledIrp": POINTER,
        })
def hook_IoCsqInitialize(ql, address, params):
    return 0


# void IoStartPacket(
#   PDEVICE_OBJECT DeviceObject,
#   PIRP           Irp,
#   PULONG         Key,
#   PDRIVER_CANCEL CancelFunction
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "DeviceObject": POINTER,
            "Irp": POINTER,
            "Key": POINTER,
            "CancelFunction": POINTER,
        })
def hook_IoStartPacket(ql, address, params):
    return None


# VOID IoAcquireCancelSpinLock(
#   _Out_ PKIRQL Irql
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
    "Irql": POINTER,
})
def hook_IoAcquireCancelSpinLock(ql, address, params):
    return None


# PEPROCESS PsGetCurrentProcess();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_PsGetCurrentProcess(ql, address, params):
    return ql.eprocess_address


# HANDLE PsGetCurrentProcessId();
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_PsGetCurrentProcessId(ql, address, params):
    # current process ID is 101
    # TODO: let user customize this?
    return ql.os.pid


# NTSTATUS
# IoCreateDriver(
#   IN  PUNICODE_STRING DriverName    OPTIONAL,
#   IN  PDRIVER_INITIALIZE InitializationFunction
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "DriverName": PUNICODE_STRING,
            "InitializationFunction": POINTER,
        })
def hook_IoCreateDriver(ql, address, params):
    init_func = params["InitializationFunction"]

    ret_addr = ql.stack_read(0)
    # print("\n\n>>> IoCreateDriver at %x, going to execute function at %x, RET = %x\n" %(address, init_func, ret_addr))

    # save SP & init_sp
    sp = ql.reg.sp
    init_sp = ql.os.init_sp

    ql.os.set_function_args((ql.driver_object_address, ql.regitry_path_address))
    ql.until_addr = ret_addr

    # now lest emualate InitializationFunction
    try:
        ql.run(begin=init_func)
    except UcError as err:
        verify_ret(self.ql, err)

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
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "SystemTime": POINTER,
            "LocalTime": POINTER,
        })
def hook_ExSystemTimeToLocalTime(ql, address, params):
    # FIXME: implement this to customize user timezone?
    return None


# NTSYSAPI VOID RtlTimeToTimeFields(
#   PLARGE_INTEGER Time,
#   PTIME_FIELDS   TimeFields
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "Time": POINTER,
            "TimeFields": POINTER,
        })
def hook_RtlTimeToTimeFields(ql, address, params):
    return None


# int vsprintf_s(
#    char *buffer,
#    size_t numberOfElements,
#    const char *format,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "buffer": POINTER,
            "numberOfElements": SIZE_T,
            "format": STRING,
        })
def hook_vsprintf_s(ql, address, params):
    return None


# int _vsprintf_s_l(
#    char *buffer,
#    size_t numberOfElements,
#    const char *format,
#    locale_t locale,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "buffer": POINTER,
            "numberOfElements": SIZE_T,
            "format": STRING,
            "locale": LOCALE_T,
        })
def hook__vsprintf_s_l(ql, address, params):
    return None


# int vswprintf_s(
#    wchar_t *buffer,
#    size_t numberOfElements,
#    const wchar_t *format,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "buffer": POINTER,
            "numberOfElements": SIZE_T,
            "format": WSTRING,
        })
def hook_vswprintf_s(ql, address, params):
    return None


# int _vswprintf_s_l(
#    wchar_t *buffer,
#    size_t numberOfElements,
#    const wchar_t *format,
#    locale_t locale,
#    va_list argptr
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
            "buffer": POINTER,
            "numberOfElements": SIZE_T,
            "format": WSTRING,
            "locale": LOCALE_T,
        })
def hook__vswprintf_s_l(ql, address, params):
    return None


# BOOLEAN MmIsAddressValid(
#   PVOID VirtualAddress
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "VirtualAddress": POINTER,
})
def hook_MmIsAddressValid(ql, address, params):
    return 1


# void KeBugCheckEx(
#   ULONG     BugCheckCode,
#   ULONG_PTR BugCheckParameter1,
#   ULONG_PTR BugCheckParameter2,
#   ULONG_PTR BugCheckParameter3,
#   ULONG_PTR BugCheckParameter4
# );
# ULONG_PTR == POINTER
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "BugCheckCode": ULONG,
    "BugCheckParameter1": POINTER,
    "BugCheckParameter2": POINTER,
    "BugCheckParameter3": POINTER,
    "BugCheckParameter4": POINTER,
})
def hook_KeBugCheckEx(ql, address, params):
    pass

# void KeBugCheck(
#   ULONG BugCheckCode
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "BugCheckCode": ULONG
})
def hook_KeBugCheck(ql, address, params):
    pass

@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_PsProcessType(ql, address, params):
    pass

@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "Process": POINTER
})
def hook_PsGetProcessImageFileName(ql, address, params):
    addr = ql.os.heap.alloc(260)
    ql.mem.write(addr, b'C:\\test.exe')
    return addr

# NTSTATUS PsLookupProcessByProcessId(
#   HANDLE    ProcessId,
#   PEPROCESS *Process
# );

@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "ProcessId": HANDLE,
    "Process": POINTER
})
def hook_PsLookupProcessByProcessId(ql, address, params):
    ProcessId = params["ProcessId"]
    Process = params["Process"]
    if ql.archbit == 64:
        addr = ql.os.heap.alloc(ctypes.sizeof(EPROCESS64))
    else:
        addr = ql.os.heap.alloc(ctypes.sizeof(EPROCESS32))
    ql.mem.write(Process, ql.pack(addr))
    ql.nprint("PID = 0x%x, addrof(EPROCESS) == 0x%x" % (ProcessId, addr))
    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS ZwOpenKey(
#   PHANDLE            KeyHandle,
#   ACCESS_MASK        DesiredAccess,
#   POBJECT_ATTRIBUTES ObjectAttributes
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "KeyHandle": POINTER,
    "DesiredAccess": DWORD,
    "ObjectAttributes": POINTER
})
def hook_ZwOpenKey(ql, address, params):
    return STATUS_SUCCESS

@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "KeyHandle": POINTER,
    "DesiredAccess": DWORD,
    "ObjectAttributes": POINTER
})
def hook_NtOpenKey(ql, address, params):
    return STATUS_SUCCESS

# NTSTATUS
# KeWaitForSingleObject (
#     PVOID Object,
#     KWAIT_REASON WaitReason,
#     KPROCESSOR_MODE WaitMode,
#     BOOLEAN Alertable,
#     PLARGE_INTEGER Timeout
#     );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "Object": POINTER,
    "WaitReason": DWORD,
    "WaitMode": DWORD,
    "Alertable": DWORD,
    "Timeout": POINTER,
})
def hook_KeWaitForSingleObject(ql, address, params):
    return STATUS_SUCCESS

# LONG_PTR ObfReferenceObject(
#   PVOID Object
# );
@winsdkapi(cc=STDCALL, dllname=dllname, passthru=True, replace_params={
    "Object": POINTER
    })
def hook_ObfReferenceObject(ql, address, params):
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "ThreadHandle": POINTER,
            "DesiredAccess": ULONG,
            "ObjectAttributes": POINTER,
            "ProcessHandle": HANDLE,
            "ClientId": POINTER,
            "StartRoutine": POINTER,
            "StartContext": POINTER
    })
def hook_PsCreateSystemThread(ql, address, params):
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Handle": HANDLE,
            "DesiredAccess": ULONG,
            "ObjectType": POINTER,
            "AccessMode": ULONG,
            "Object": POINTER,
            "HandleInformation": POINTER
    })
def hook_ObReferenceObjectByHandle(ql, address, params):
    return STATUS_SUCCESS

# LONG KeSetEvent(
#   PRKEVENT  Event,
#   KPRIORITY Increment,
#   BOOLEAN   Wait
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Event": POINTER,
            "Increment": ULONG,
            "Wait": ULONG
    })
def hook_KeSetEvent(ql, address, params):
    return 0

# void KeClearEvent(
#   PRKEVENT Event
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Event": POINTER
    })
def hook_KeClearEvent(ql, address, params):
    return 0

# NTSTATUS PsTerminateSystemThread(
#   NTSTATUS ExitStatus
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "ExitStatus": DWORD
    })
def hook_PsTerminateSystemThread(ql, address, params):
    return 0

# NTSTATUS ObReferenceObjectByPointer(
#   PVOID           Object,
#   ACCESS_MASK     DesiredAccess,
#   POBJECT_TYPE    ObjectType,
#   KPROCESSOR_MODE AccessMode
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Object": POINTER,
            "DesiredAccess": DWORD,
            "ObjectType": POINTER,
            "AccessMode": DWORD
    })
def hook_ObReferenceObjectByPointer(ql, address, params):
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "Object": POINTER,
            "HandleAttributes": ULONG,
            "PassedAccessState": POINTER,
            "DesiredAccess": DWORD,
            "ObjectType": POINTER,
            "AccessMode": ULONG,
            "Handle": POINTER,
    })
def hook_ObOpenObjectByPointer(ql, address, params):
    Object = params["Object"]
    point_to_new_handle = params["Handle"]
    new_handle = Handle(name="p=%x" % Object)
    ql.os.handle_manager.append(new_handle)
    ql.mem.write(point_to_new_handle, ql.pack(new_handle.id))
    ql.nprint("New handle of 0x%x is 0x%x" % (Object, new_handle.id))
    return STATUS_SUCCESS

@winsdkapi(cc=CDECL, dllname=dllname)
def hook_ObfDereferenceObject(ql, address, params):
    return STATUS_SUCCESS

# NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
#     IN HANDLE               ProcessHandle OPTIONAL,
#     IN NTSTATUS             ExitStatus );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
            "ProcessHandle": HANDLE,
            "ExitStatus": DWORD
    })
def hook_NtTerminateProcess(ql, address, params):
    return STATUS_SUCCESS
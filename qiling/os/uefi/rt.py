#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import TYPE_CHECKING

import time

from qiling.os.const import *
from .const import *
from .utils import init_struct
from .fncc import dxeapi
from .ProcessorBind import *
from .PiMultiPhase import EFI_VARIABLE
from .UefiBaseType import EFI_TIME
from .UefiSpec import EFI_UNSPECIFIED_TIMEZONE, EFI_RUNTIME_SERVICES


if TYPE_CHECKING:
    from qiling import Qiling


@dxeapi(params={
    "Time":         POINTER,    # OUT PTR(EFI_TIME)
    "Capabilities": POINTER     # OUT PTR(EFI_TIME_CAPABILITIES)
})
def hook_GetTime(ql: Qiling, address: int, params):
    Time = params['Time']

    if not Time:
        return EFI_INVALID_PARAMETER

    localtime = time.localtime()

    EFI_TIME(
        Year = localtime.tm_year,
        Month = localtime.tm_mon,
        Day = localtime.tm_mday,
        Hour = localtime.tm_hour,
        Minute = localtime.tm_min,
        Second = localtime.tm_sec,
        Nanosecond = 0,

        # tz and dst settings are stored in the "RtcTimeSettings" nvram variable.
        # we just use the default settings instead
        TimeZone = EFI_UNSPECIFIED_TIMEZONE,
        Daylight = 0
    ).save_to(ql.mem, Time)

    return EFI_SUCCESS

@dxeapi(params={
    "Time": POINTER     # IN PTR(EFI_TIME)
})
def hook_SetTime(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "Enabled": POINTER,     # OUT PTR(BOOLEAN)
    "Pending": POINTER,     # OUT PTR(BOOLEAN)
    "Time":    POINTER      # OUT PTR(EFI_TIME)
})
def hook_GetWakeupTime(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "Enable": BOOL,     # BOOLEAN
    "Time":   POINTER   # PTR(EFI_TIME)
})
def hook_SetWakeupTime(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "MemoryMapSize":     UINT,      # UINTN
    "DescriptorSize":    UINT,      # UINTN
    "DescriptorVersion": UINT,      # UINT32
    "VirtualMap":        POINTER    # PTR(EFI_MEMORY_DESCRIPTOR)
})
def hook_SetVirtualAddressMap(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "DebugDisposition": UINT,       # UINTN
    "Address":          POINTER     # OUT PTR(PTR(VOID))
})
def hook_ConvertPointer(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "VariableName": WSTRING,    # PTR(CHAR16)
    "VendorGuid":   GUID,       # PTR(EFI_GUID)
    "Attributes":   POINTER,    # OUT PTR(UINT32)
    "DataSize":     POINTER,    # IN OUT PTR(UINTN)
    "Data":         POINTER     # OUT PTR(VOID)
})
def hook_GetVariable(ql: Qiling, address: int, params):
    var_name = params["VariableName"]
    vendor_guid = params["VendorGuid"]
    attr_ptr = params["Attributes"]
    data_size_ptr = params["DataSize"]
    data_ptr = params["Data"]

    if (not var_name) or (not vendor_guid) or (not data_size_ptr):
        return EFI_INVALID_PARAMETER

    if var_name not in ql.env:
        return EFI_NOT_FOUND

    var_data = ql.env[var_name]
    data_size = len(var_data)
    buff_size = ql.mem.read_ptr(data_size_ptr)

    if attr_ptr:
        # FIXME: until we manage variables with their attributes, provide a default set
        attributes = (
            EFI_VARIABLE.NON_VOLATILE |
            EFI_VARIABLE.BOOTSERVICE_ACCESS |
            EFI_VARIABLE.RUNTIME_ACCESS
        )

        ql.mem.write_ptr(attr_ptr, attributes, 4)

    ql.mem.write_ptr(data_size_ptr, data_size)

    if buff_size < data_size:
        return EFI_BUFFER_TOO_SMALL

    if data_ptr:
        ql.mem.write(data_ptr, var_data)

    return EFI_SUCCESS


@dxeapi(params={
    "VariableNameSize": POINTER,    # IN OUT PTR(UINTN)
    "VariableName":     POINTER,    # IN OUT PTR(CHAR16)
    "VendorGuid":       GUID        # IN OUT PTR(EFI_GUID)
})
def hook_GetNextVariableName(ql: Qiling, address: int, params):
    var_name_size = params["VariableNameSize"]
    var_name = params["VariableName"]
    vendor_guid = params["VendorGuid"]

    if (not var_name_size) or (not var_name) or (not vendor_guid):
        return EFI_INVALID_PARAMETER

    name_size = ql.mem.read_ptr(var_name_size)
    last_name = ql.os.utils.read_wstring(var_name, name_size)

    nvvars = ql.env['Names'] # This is a list of variable names in correct order.

    if last_name not in nvvars:
        return EFI_NOT_FOUND

    idx = nvvars.index(last_name)

    # make sure it is not the last one (i.e. we have a next one to pull)
    if idx == len(nvvars) - 1:
        return EFI_NOT_FOUND

    # get next var name, and add null terminator
    new_name = nvvars[idx + 1] + '\x00'

    # turn it into a wide string
    new_name = ''.join(f'{c}\x00' for c in new_name)

    if len(new_name) > name_size:
        ql.mem.write_ptr(var_name_size, len(new_name))
        return EFI_BUFFER_TOO_SMALL

    ql.mem.write(var_name, new_name.encode('ascii'))

    return EFI_SUCCESS

@dxeapi(params={
    "VariableName": WSTRING,    # PTR(CHAR16)
    "VendorGuid":   GUID,       # PTR(EFI_GUID)
    "Attributes":   UINT,       # UINT32
    "DataSize":     UINT,       # UINTN
    "Data":         POINTER     # PTR(VOID)
})
def hook_SetVariable(ql: Qiling, address: int, params):
    var_name = params["VariableName"]
    vendor_guid = params["VendorGuid"]
    attributes = params["Attributes"]
    data_size = params["DataSize"]
    data_ptr = params["Data"]

    if not var_name:
        return EFI_INVALID_PARAMETER

    # deprecated
    if attributes & EFI_VARIABLE.AUTHENTICATED_WRITE_ACCESS:
        return EFI_UNSUPPORTED

    append = attributes & EFI_VARIABLE.APPEND_WRITE
    auth = attributes & (
        EFI_VARIABLE.TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
        EFI_VARIABLE.ENHANCED_AUTHENTICATED_ACCESS
    )

    # TODO: manage variables with namespaces (guids)
    # TODO: manage variables according to their access attributes

    # when data size is set to zero and this is not auth or append access, delete the var
    if data_size == 0 and not (auth or append):
        if var_name not in ql.env:
            return EFI_NOT_FOUND

        del ql.env[var_name]

    data = bytes(ql.mem.read(data_ptr, data_size))

    if append:
        if var_name not in ql.env:
            return EFI_NOT_FOUND

        data = ql.env[var_name] + data

    ql.env[var_name] = data

    return EFI_SUCCESS

@dxeapi(params={
    "HighCount": POINTER    # OUT PTR(UINT32)
})
def hook_GetNextHighMonotonicCount(ql: Qiling, address: int, params):
    ql.os.monotonic_count += 0x0000000100000000
    hmc = ql.os.monotonic_count
    hmc = (hmc >> 32) & 0xffffffff

    ql.mem.write_ptr(params["HighCount"], hmc, 4)

    return EFI_SUCCESS

@dxeapi(params={
    "ResetType":   INT,     # EFI_RESET_TYPE
    "ResetStatus": INT,     # EFI_STATUS
    "DataSize":    UINT,    # UINTN
    "ResetData":   POINTER  # PTR(VOID)
})
def hook_ResetSystem(ql: Qiling, address: int, params):
    ql.emu_stop()

    return EFI_SUCCESS

@dxeapi(params={
    "CapsuleHeaderArray": POINTER,      # PTR(PTR(EFI_CAPSULE_HEADER))
    "CapsuleCount":       UINT,         # UINTN
    "ScatterGatherList":  ULONGLONG     # EFI_PHYSICAL_ADDRESS
})
def hook_UpdateCapsule(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "CapsuleHeaderArray": POINTER,  # PTR(PTR(EFI_CAPSULE_HEADER))
    "CapsuleCount":       UINT,     # UINTN
    "MaximumCapsuleSize": POINTER,  # OUT PTR(UINT64)
    "ResetType":          POINTER   # OUT PTR(EFI_RESET_TYPE)
})
def hook_QueryCapsuleCapabilities(ql: Qiling, address: int, params):
    return EFI_SUCCESS

@dxeapi(params={
    "Attributes":                   UINT,       # UINT32
    "MaximumVariableStorageSize":   POINTER,    # OUT PTR(UINT64)
    "RemainingVariableStorageSize": POINTER,    # OUT PTR(UINT64)
    "MaximumVariableSize":          POINTER     # OUT PTR(UINT64)
})
def hook_QueryVariableInfo(ql: Qiling, address: int, params):
    return EFI_SUCCESS

def initialize(ql: Qiling, gRT: int):
    descriptor = {
        'struct' : EFI_RUNTIME_SERVICES,
        'fields' : (
            ('Hdr',                       None),
            ('GetTime',                   hook_GetTime),
            ('SetTime',                   hook_SetTime),
            ('GetWakeupTime',             hook_GetWakeupTime),
            ('SetWakeupTime',             hook_SetWakeupTime),
            ('SetVirtualAddressMap',      hook_SetVirtualAddressMap),
            ('ConvertPointer',            hook_ConvertPointer),
            ('GetVariable',               hook_GetVariable),
            ('GetNextVariableName',       hook_GetNextVariableName),
            ('SetVariable',               hook_SetVariable),
            ('GetNextHighMonotonicCount', hook_GetNextHighMonotonicCount),
            ('ResetSystem',               hook_ResetSystem),
            ('UpdateCapsule',             hook_UpdateCapsule),
            ('QueryCapsuleCapabilities',  hook_QueryCapsuleCapabilities),
            ('QueryVariableInfo',         hook_QueryVariableInfo)
        )
    }

    instance = init_struct(ql, gRT, descriptor)
    instance.save_to(ql.mem, gRT)

__all__ = [
    'initialize'
]

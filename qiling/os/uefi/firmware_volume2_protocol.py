from qiling.os.uefi.fncc import *
from qiling.os.uefi.utils import *
from qiling.os.uefi.type64 import *
from qiling.os.const import *

import uefi_firmware
from uefi_firmware.utils import sguid

g_volumes = {}

#
# Utility functions for handling firmware images
#

def get_flash_region(rom_file, region_name):
    data = open(rom_file, "rb").read()
    parser = uefi_firmware.AutoParser(data)
    firmware = parser.parse()
    for region in firmware.regions:
        if region.name == region_name:
            return region

def get_firmware_volume(bios_region, volume_guid):
    for volume in bios_region.objects:
        if sguid(volume.fvname) == volume_guid:
            return volume

def get_file_from_volume(volume, file_guid):
    for fs in volume.firmware_filesystems:
        for file in fs.files:
            if file.guid_label == file_guid:
                return file

def get_section(file, section_type, section_instance):
    instance = -1
    for section in file.sections:
        if section.type == section_type:
            instance += 1
            if instance == section_instance:
                return section

#
# The full details regarding the EFI_FIRMWARE_VOLUME2_PROTOCOL can be found in volume 3, page 86 of the
# Platform Initialization specification: https://uefi.org/sites/default/files/resources/PI_Spec_1_6.pdf
#

@dxeapi(params={
    "This": POINTER,
    "FvAttributes": POINTER})
def hook_GetVolumeAttributes(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "FvAttributes": POINTER})
def hook_SetVolumeAttributes(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "NameGuid": GUID,
    "Buffer": POINTER,
    "BufferSize": POINTER,
    "FoundType": POINTER,
    "FileAttributes": POINTER,
    "AuthenticationStatus": POINTER})
def hook_ReadFile(ql, address, params):

    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "NameGuid": POINTER,
    "SectionType": BYTE,
    "SectionInstance": UINT,
    "Buffer": POINTER,
    "BufferSize": POINTER,
    "AuthenticationStatus": POINTER})
def hook_ReadSection(ql, address, params):
    name_guid = sguid(ql.mem.read(params["NameGuid"], 16))
    # BYTE params are actually passed as DWORDs in Qiling
    section_type = params["SectionType"] & 0xFF

    volume = g_volumes[params["This"]]
    file = get_file_from_volume(volume, name_guid)
    if file is None:
        return EFI_NOT_FOUND

    section = get_section(file, section_type, params["SectionInstance"])
    if section is None:
        return EFI_NOT_FOUND

    buff = read_int64(ql, params["Buffer"])
    if buff == 0:
        sec_mem = ql.loader.heap.alloc(len(section.data))
        ql.mem.write(sec_mem, section.data)
        write_int64(ql, params["Buffer"], sec_mem)
        write_int64(ql, params["BufferSize"], len(section.data))
        return EFI_SUCCESS
    else:
        # Buffer is caller-allocated, not implemented yet
        return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "NumberOfFiles": UINT,
    "WritePolicy": UINT,
    "FileData": POINTER})
def hook_WriteFile(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "Key": POINTER,
    "FileType": POINTER,
    "NameGuid": GUID,
    "Attributes": POINTER,
    "Size": POINTER})
def hook_GetNextFile(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "InformationType": POINTER,
    "BufferSize": POINTER,
    "Buffer": POINTER})
def hook_GetInfo(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER,
    "InformationType": POINTER,
    "BufferSize": UINT,
    "Buffer": POINTER})
def hook_SetInfo(ql, address, params):
    return EFI_UNSUPPORTED

def install_FIRMWARE_VOLUME2_PROTOCOL(ql, start_ptr, rom_file, volume_guid):
    global g_volumes

    bios_region = get_flash_region(rom_file, "bios")
    volume = get_firmware_volume(bios_region, volume_guid)
    g_volumes[start_ptr] = volume

    efi_firmware_volume2_protocol = EFI_FIRMWARE_VOLUME2_PROTOCOL()
    ptr = start_ptr + ctypes.sizeof(EFI_FIRMWARE_VOLUME2_PROTOCOL)
    pointer_size = 8

    # GetVolumeAttributes
    efi_firmware_volume2_protocol.GetVolumeAttributes = ptr
    ql.hook_address(hook_GetVolumeAttributes, ptr)
    ptr += pointer_size
    # SetVolumeAttributes
    efi_firmware_volume2_protocol.SetVolumeAttributes = ptr
    ql.hook_address(hook_SetVolumeAttributes, ptr)
    ptr += pointer_size
    # ReadFile
    efi_firmware_volume2_protocol.ReadFile = ptr
    ql.hook_address(hook_ReadFile, ptr)
    ptr += pointer_size
    # ReadSection
    efi_firmware_volume2_protocol.ReadSection = ptr
    ql.hook_address(hook_ReadSection, ptr)
    ptr += pointer_size
    # WriteFile
    efi_firmware_volume2_protocol.WriteFile = ptr
    ql.hook_address(hook_WriteFile, ptr)
    ptr += pointer_size
    # GetNextFile
    efi_firmware_volume2_protocol.GetNextFile = ptr
    ql.hook_address(hook_GetNextFile, ptr)
    ptr += pointer_size
    # KeySize
    efi_firmware_volume2_protocol.KeySize = 0
    ptr += ctypes.sizeof(ctypes.c_uint32)
    # ParentHandle
    efi_firmware_volume2_protocol.ParentHandle = 0
    ptr += ctypes.sizeof(efi_firmware_volume2_protocol.ParentHandle)
    # GetInfo
    efi_firmware_volume2_protocol.GetInfo = ptr
    ql.hook_address(hook_GetInfo, ptr)
    ptr += pointer_size
    # SetInfo
    efi_firmware_volume2_protocol.SetInfo = ptr
    ql.hook_address(hook_SetInfo, ptr)
    ptr += pointer_size

    return (ptr, efi_firmware_volume2_protocol)
#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .ProcessorBind import UINT32, UINT64, STRUCT, ENUM


# @see: MdePkg\Include\Uefi\UefiMultiPhase.h
class EFI_TABLE_HEADER(STRUCT):
    _fields_ = [
        ('Signature',  UINT64),
        ('Revision',   UINT32),
        ('HeaderSize', UINT32),
        ('CRC32',      UINT32),
        ('Reserved',   UINT32)
    ]


class EFI_RESET_TYPE(ENUM):
    _members_ = [
        'EfiResetCold',
        'EfiResetWarm'
        'EfiResetShutdown',
        'EfiResetPlatformSpecific',
    ]


class EFI_MEMORY_TYPE(ENUM):
    _members_ = [
        'EfiReservedMemoryType',
        'EfiLoaderCode',
        'EfiLoaderData',
        'EfiBootServicesCode',
        'EfiBootServicesData',
        'EfiRuntimeServicesCode',
        'EfiRuntimeServicesData',
        'EfiConventionalMemory',
        'EfiUnusableMemory',
        'EfiACPIReclaimMemory',
        'EfiACPIMemoryNVS',
        'EfiMemoryMappedIO',
        'EfiMemoryMappedIOPortSpace',
        'EfiPalCode',
        'EfiPersistentMemory',
        'EfiMaxMemoryType'
    ]


__all__ = [
    'EFI_TABLE_HEADER',
    'EFI_RESET_TYPE',
    'EFI_MEMORY_TYPE'
]

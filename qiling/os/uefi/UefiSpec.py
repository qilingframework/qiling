
#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# @see: MdePkg\Include\Uefi\UefiSpec.h

from .ProcessorBind import *
from .UefiBaseType import *
from .UefiMultiPhase import *

# definitions for EFI_TIME.Daylight
EFI_TIME_ADJUST_DAYLIGHT = (1 << 1)
EFI_TIME_IN_DAYLIGHT     = (1 << 2)

# definition for EFI_TIME.TimeZone
EFI_UNSPECIFIED_TIMEZONE = 0x07ff

class EFI_ALLOCATE_TYPE(ENUM):
    _members_ = [
        'AllocateAnyPages',
        'AllocateMaxAddress',
        'AllocateAddress',
        'MaxAllocateType'
    ]

class EFI_TIMER_DELAY(ENUM):
    _members_ = [
        'TimerCancel',
        'TimerPeriodic',
        'TimerRelative'
    ]

class EFI_INTERFACE_TYPE(ENUM):
    _members_ = [
        'EFI_NATIVE_INTERFACE'
    ]

class EFI_LOCATE_SEARCH_TYPE(ENUM):
    _members_ = [
        'AllHandles',
        'ByRegisterNotify',
        'ByProtocol'
]

class EFI_TIME_CAPABILITIES(STRUCT):
    _pack_ = 8

    _fields_ = [
        ('Resolution', UINT32),
        ('Accuracy',   UINT32),
        ('SetsToZero', BOOLEAN),
    ]

class EFI_MEMORY_DESCRIPTOR(STRUCT):
    _pack_ = 8

    _fields_ = [
        ('Type',          UINT32),
        ('PhysicalStart', EFI_PHYSICAL_ADDRESS),
        ('VirtualStart',  EFI_VIRTUAL_ADDRESS),
        ('NumberOfPages', UINT64),
        ('Attribute',     UINT64)
    ]

class EFI_CAPSULE_HEADER(STRUCT):
    _fields_ = [
        ('CapsuleGuid',      EFI_GUID),
        ('HeaderSize',       UINT32),
        ('Flags',            UINT32),
        ('CapsuleImageSize', UINT32)
    ]

EFI_GET_TIME                   = FUNCPTR(EFI_STATUS, PTR(EFI_TIME), PTR(EFI_TIME_CAPABILITIES))
EFI_SET_TIME                   = FUNCPTR(EFI_STATUS, PTR(EFI_TIME))
EFI_GET_WAKEUP_TIME            = FUNCPTR(EFI_STATUS, PTR(BOOLEAN), PTR(BOOLEAN), PTR(EFI_TIME))
EFI_SET_WAKEUP_TIME            = FUNCPTR(EFI_STATUS, BOOLEAN, PTR(EFI_TIME))
EFI_SET_VIRTUAL_ADDRESS_MAP    = FUNCPTR(EFI_STATUS, UINTN, UINTN, UINT32, PTR(EFI_MEMORY_DESCRIPTOR))
EFI_CONVERT_POINTER            = FUNCPTR(EFI_STATUS, UINTN, PTR(PTR(VOID)))
EFI_GET_VARIABLE               = FUNCPTR(EFI_STATUS, PTR(CHAR16), PTR(EFI_GUID), PTR(UINT32), PTR(UINTN), PTR(VOID))
EFI_GET_NEXT_VARIABLE_NAME     = FUNCPTR(EFI_STATUS, PTR(UINTN), PTR(CHAR16), PTR(EFI_GUID))
EFI_SET_VARIABLE               = FUNCPTR(EFI_STATUS, PTR(CHAR16), PTR(EFI_GUID), UINT32, UINTN, PTR(VOID))
EFI_GET_NEXT_HIGH_MONO_COUNT   = FUNCPTR(EFI_STATUS, PTR(UINT32))
EFI_RESET_SYSTEM               = FUNCPTR(VOID, EFI_RESET_TYPE, EFI_STATUS, UINTN, PTR(VOID))
EFI_UPDATE_CAPSULE             = FUNCPTR(EFI_STATUS, PTR(PTR(EFI_CAPSULE_HEADER)), UINTN, EFI_PHYSICAL_ADDRESS)
EFI_QUERY_CAPSULE_CAPABILITIES = FUNCPTR(EFI_STATUS, PTR(PTR(EFI_CAPSULE_HEADER)), UINTN, PTR(UINT64), PTR(EFI_RESET_TYPE))
EFI_QUERY_VARIABLE_INFO        = FUNCPTR(EFI_STATUS, UINT32, PTR(UINT64), PTR(UINT64), PTR(UINT64))

class EFI_RUNTIME_SERVICES(STRUCT):
    _fields_ = [
        ('Hdr',                       EFI_TABLE_HEADER),
        ('GetTime',                   EFI_GET_TIME),
        ('SetTime',                   EFI_SET_TIME),
        ('GetWakeupTime',             EFI_GET_WAKEUP_TIME),
        ('SetWakeupTime',             EFI_SET_WAKEUP_TIME),
        ('SetVirtualAddressMap',      EFI_SET_VIRTUAL_ADDRESS_MAP),
        ('ConvertPointer',            EFI_CONVERT_POINTER),
        ('GetVariable',               EFI_GET_VARIABLE),
        ('GetNextVariableName',       EFI_GET_NEXT_VARIABLE_NAME),
        ('SetVariable',               EFI_SET_VARIABLE),
        ('GetNextHighMonotonicCount', EFI_GET_NEXT_HIGH_MONO_COUNT),
        ('ResetSystem',               EFI_RESET_SYSTEM),
        ('UpdateCapsule',             EFI_UPDATE_CAPSULE),
        ('QueryCapsuleCapabilities',  EFI_QUERY_CAPSULE_CAPABILITIES),
        ('QueryVariableInfo',         EFI_QUERY_VARIABLE_INFO)
    ]

EFI_EVENT_NOTIFY = FUNCPTR(VOID, EFI_EVENT, PTR(VOID))

# this one belongs to another header, actually
class EFI_DEVICE_PATH_PROTOCOL(STRUCT):
    _fields_ = [
        ('Type',    UINT8),
        ('SubType', UINT8),
        ('Length',  UINT8 * 2)
    ]

class EFI_OPEN_PROTOCOL_INFORMATION_ENTRY(STRUCT):
    _fields_ = [
        ('AgentHandle',      EFI_HANDLE),
        ('ControllerHandle', EFI_HANDLE),
        ('Attributes',       UINT32),
        ('OpenCount',        UINT32)
    ]

EFI_RAISE_TPL                    = FUNCPTR(EFI_TPL, EFI_TPL)
EFI_RESTORE_TPL                  = FUNCPTR(VOID, EFI_TPL)
EFI_ALLOCATE_PAGES               = FUNCPTR(EFI_STATUS, EFI_ALLOCATE_TYPE, EFI_MEMORY_TYPE, UINTN, PTR(EFI_PHYSICAL_ADDRESS))
EFI_FREE_PAGES                   = FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINTN)
EFI_GET_MEMORY_MAP               = FUNCPTR(EFI_STATUS, PTR(UINTN), PTR(EFI_MEMORY_DESCRIPTOR), PTR(UINTN), PTR(UINTN), PTR(UINT32))
EFI_ALLOCATE_POOL                = FUNCPTR(EFI_STATUS, EFI_MEMORY_TYPE, UINTN, PTR(PTR(VOID)))
EFI_FREE_POOL                    = FUNCPTR(EFI_STATUS, PTR(VOID))
EFI_CREATE_EVENT                 = FUNCPTR(EFI_STATUS, UINT32, EFI_TPL, EFI_EVENT_NOTIFY, PTR(VOID), PTR(EFI_EVENT))
EFI_SET_TIMER                    = FUNCPTR(EFI_STATUS, EFI_EVENT, EFI_TIMER_DELAY, UINT64)
EFI_WAIT_FOR_EVENT               = FUNCPTR(EFI_STATUS, UINTN, PTR(EFI_EVENT), PTR(UINTN))
EFI_SIGNAL_EVENT                 = FUNCPTR(EFI_STATUS, EFI_EVENT)
EFI_CLOSE_EVENT                  = FUNCPTR(EFI_STATUS, EFI_EVENT)
EFI_CHECK_EVENT                  = FUNCPTR(EFI_STATUS, EFI_EVENT)
EFI_INSTALL_PROTOCOL_INTERFACE   = FUNCPTR(EFI_STATUS, PTR(EFI_HANDLE), PTR(EFI_GUID), EFI_INTERFACE_TYPE, PTR(VOID))
EFI_REINSTALL_PROTOCOL_INTERFACE = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID), PTR(VOID), PTR(VOID))
EFI_UNINSTALL_PROTOCOL_INTERFACE = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID), PTR(VOID))
EFI_HANDLE_PROTOCOL              = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID), PTR(PTR(VOID)))
EFI_REGISTER_PROTOCOL_NOTIFY     = FUNCPTR(EFI_STATUS, PTR(EFI_GUID), EFI_EVENT, PTR(PTR(VOID)))
EFI_LOCATE_HANDLE                = FUNCPTR(EFI_STATUS, EFI_LOCATE_SEARCH_TYPE, PTR(EFI_GUID), PTR(VOID), PTR(UINTN), PTR(EFI_HANDLE))
EFI_LOCATE_DEVICE_PATH           = FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(PTR(EFI_DEVICE_PATH_PROTOCOL)), PTR(EFI_HANDLE))
EFI_INSTALL_CONFIGURATION_TABLE  = FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(VOID))
EFI_IMAGE_LOAD                   = FUNCPTR(EFI_STATUS, BOOLEAN, EFI_HANDLE, PTR(EFI_DEVICE_PATH_PROTOCOL), PTR(VOID) , UINTN, PTR(EFI_HANDLE))
EFI_IMAGE_START                  = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(UINTN), PTR(PTR(CHAR16)))
EFI_EXIT                         = FUNCPTR(EFI_STATUS, EFI_HANDLE, EFI_STATUS, UINTN, PTR(CHAR16))
EFI_IMAGE_UNLOAD                 = FUNCPTR(EFI_STATUS, EFI_HANDLE)
EFI_EXIT_BOOT_SERVICES           = FUNCPTR(EFI_STATUS, EFI_HANDLE, UINTN)
EFI_GET_NEXT_MONOTONIC_COUNT     = FUNCPTR(EFI_STATUS, PTR(UINT64))
EFI_STALL                        = FUNCPTR(EFI_STATUS, UINTN)
EFI_SET_WATCHDOG_TIMER           = FUNCPTR(EFI_STATUS, UINTN, UINT64, UINTN, PTR(CHAR16))
EFI_CONNECT_CONTROLLER           = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_HANDLE), PTR(EFI_DEVICE_PATH_PROTOCOL), BOOLEAN)
EFI_DISCONNECT_CONTROLLER        = FUNCPTR(EFI_STATUS, EFI_HANDLE, EFI_HANDLE, EFI_HANDLE)
EFI_OPEN_PROTOCOL                = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID), PTR(PTR(VOID)), EFI_HANDLE, EFI_HANDLE, UINT32)
EFI_CLOSE_PROTOCOL               = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID), EFI_HANDLE, EFI_HANDLE)
EFI_OPEN_PROTOCOL_INFORMATION    = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID), PTR(PTR(EFI_OPEN_PROTOCOL_INFORMATION_ENTRY)), PTR(UINTN))
EFI_PROTOCOLS_PER_HANDLE         = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(PTR(PTR(EFI_GUID))), PTR(UINTN))
EFI_LOCATE_HANDLE_BUFFER         = FUNCPTR(EFI_STATUS, EFI_LOCATE_SEARCH_TYPE, PTR(EFI_GUID), PTR(VOID), PTR(UINTN), PTR(PTR(EFI_HANDLE)))
EFI_LOCATE_PROTOCOL              = FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(VOID), PTR(PTR(VOID)))
EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES   = FUNCPTR(EFI_STATUS, PTR(EFI_HANDLE))  # ...
EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES = FUNCPTR(EFI_STATUS, EFI_HANDLE)  # ...
EFI_CALCULATE_CRC32              = FUNCPTR(EFI_STATUS, PTR(VOID), UINTN, PTR(UINT32))
EFI_COPY_MEM                     = FUNCPTR(VOID, PTR(VOID), PTR(VOID), UINTN)
EFI_SET_MEM                      = FUNCPTR(VOID, PTR(VOID), UINTN, UINT8)
EFI_CREATE_EVENT_EX              = FUNCPTR(EFI_STATUS, UINT32, EFI_TPL, EFI_EVENT_NOTIFY, PTR(VOID), PTR(EFI_GUID), PTR(EFI_EVENT))

class EFI_BOOT_SERVICES(STRUCT):
    _fields_ = [
        ('Hdr',                        EFI_TABLE_HEADER),
        ('RaiseTPL',                   EFI_RAISE_TPL),
        ('RestoreTPL',                 EFI_RESTORE_TPL),
        ('AllocatePages',              EFI_ALLOCATE_PAGES),
        ('FreePages',                  EFI_FREE_PAGES),
        ('GetMemoryMap',               EFI_GET_MEMORY_MAP),
        ('AllocatePool',               EFI_ALLOCATE_POOL),
        ('FreePool',                   EFI_FREE_POOL),
        ('CreateEvent',                EFI_CREATE_EVENT),
        ('SetTimer',                   EFI_SET_TIMER),
        ('WaitForEvent',               EFI_WAIT_FOR_EVENT),
        ('SignalEvent',                EFI_SIGNAL_EVENT),
        ('CloseEvent',                 EFI_CLOSE_EVENT),
        ('CheckEvent',                 EFI_CHECK_EVENT),
        ('InstallProtocolInterface',   EFI_INSTALL_PROTOCOL_INTERFACE),
        ('ReinstallProtocolInterface', EFI_REINSTALL_PROTOCOL_INTERFACE),
        ('UninstallProtocolInterface', EFI_UNINSTALL_PROTOCOL_INTERFACE),
        ('HandleProtocol',             EFI_HANDLE_PROTOCOL),
        ('Reserved',                   PTR(VOID)),
        ('RegisterProtocolNotify',     EFI_REGISTER_PROTOCOL_NOTIFY),
        ('LocateHandle',               EFI_LOCATE_HANDLE),
        ('LocateDevicePath',           EFI_LOCATE_DEVICE_PATH),
        ('InstallConfigurationTable',  EFI_INSTALL_CONFIGURATION_TABLE),
        ('LoadImage',                  EFI_IMAGE_LOAD),
        ('StartImage',                 EFI_IMAGE_START),
        ('Exit',                       EFI_EXIT),
        ('UnloadImage',                EFI_IMAGE_UNLOAD),
        ('ExitBootServices',           EFI_EXIT_BOOT_SERVICES),
        ('GetNextMonotonicCount',      EFI_GET_NEXT_MONOTONIC_COUNT),
        ('Stall',                      EFI_STALL),
        ('SetWatchdogTimer',           EFI_SET_WATCHDOG_TIMER),
        ('ConnectController',          EFI_CONNECT_CONTROLLER),
        ('DisconnectController',       EFI_DISCONNECT_CONTROLLER),
        ('OpenProtocol',               EFI_OPEN_PROTOCOL),
        ('CloseProtocol',              EFI_CLOSE_PROTOCOL),
        ('OpenProtocolInformation',    EFI_OPEN_PROTOCOL_INFORMATION),
        ('ProtocolsPerHandle',         EFI_PROTOCOLS_PER_HANDLE),
        ('LocateHandleBuffer',         EFI_LOCATE_HANDLE_BUFFER),
        ('LocateProtocol',             EFI_LOCATE_PROTOCOL),
        ('InstallMultipleProtocolInterfaces',   EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES),
        ('UninstallMultipleProtocolInterfaces', EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES),
        ('CalculateCrc32',             EFI_CALCULATE_CRC32),
        ('CopyMem',                    EFI_COPY_MEM),
        ('SetMem',                     EFI_SET_MEM),
        ('CreateEventEx',              EFI_CREATE_EVENT_EX)
    ]

class EFI_CONFIGURATION_TABLE(STRUCT):
    _fields_ = [
        ('VendorGuid',    EFI_GUID),
        ('VendorTable',    PTR(VOID)),
    ]

# TODO: to be implemented
# @see: MdePkg\Include\Protocol\SimpleTextIn.h
EFI_SIMPLE_TEXT_INPUT_PROTOCOL = STRUCT

# TODO: to be implemented
# @see: MdePkg\Include\Protocol\SimpleTextOut.h
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = STRUCT

class EFI_SYSTEM_TABLE(STRUCT):
    _pack_ = 8

    _fields_ = [
        ('Hdr',                  EFI_TABLE_HEADER),
        ('FirmwareVendor',       PTR(CHAR16)),
        ('FirmwareRevision',     UINT32),
        ('ConsoleInHandle',      EFI_HANDLE),
        ('ConIn',                PTR(EFI_SIMPLE_TEXT_INPUT_PROTOCOL)),
        ('ConsoleOutHandle',     EFI_HANDLE),
        ('ConOut',               PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)),
        ('StandardErrorHandle',  EFI_HANDLE),
        ('StdErr',               PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)),
        ('RuntimeServices',      PTR(EFI_RUNTIME_SERVICES)),
        ('BootServices',         PTR(EFI_BOOT_SERVICES)),
        ('NumberOfTableEntries', UINTN),
        ('ConfigurationTable',   PTR(EFI_CONFIGURATION_TABLE))
    ]

__all__ = [
    'EFI_TIME_ADJUST_DAYLIGHT',
    'EFI_TIME_IN_DAYLIGHT',
    'EFI_UNSPECIFIED_TIMEZONE',
    'EFI_RUNTIME_SERVICES',
    'EFI_BOOT_SERVICES',
    'EFI_CONFIGURATION_TABLE',
    'EFI_SYSTEM_TABLE',
    'EFI_ALLOCATE_TYPE',
    'EFI_INTERFACE_TYPE',
    'EFI_LOCATE_SEARCH_TYPE',
    'EFI_DEVICE_PATH_PROTOCOL',
    'EFI_OPEN_PROTOCOL_INFORMATION_ENTRY',
    'EFI_IMAGE_UNLOAD'
]
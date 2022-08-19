#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from enum import IntEnum

from qiling.os import struct
from qiling.os.windows.const import MAX_PATH
from qiling.os.windows.handle import Handle
from qiling.exception import QlErrorNotImplemented
from .wdk_const import IRP_MJ_MAXIMUM_FUNCTION, PROCESSOR_FEATURE_MAX


def make_teb(archbits: int):
    """Generate a TEB structure class.
    """

    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    class TEB(Struct):
        _fields_ = (
            ('CurrentSEH',             native_type),
            ('StackBase',              native_type),
            ('StackLimit',             native_type),
            ('SubSystemTib',           native_type),
            ('FiberData',              native_type),
            ('ArbitraryDataSlot',      native_type),
            ('TebAddress',             native_type),
            ('EnvironmentPointer',     native_type),
            ('ProcessID',              native_type),
            ('ThreadID',               native_type),
            ('RpcHandle',              native_type),
            ('TlsAddress',             native_type),
            ('PebAddress',             native_type),
            ('LastError',              ctypes.c_int32),
            ('CriticalSectionsCount',  ctypes.c_int32),
            ('CsrClientThreadAddress', native_type),
            ('Win32ThreadInfo',        native_type),
            ('Win32ClientInfo',        ctypes.c_byte * 124),
            ('ReservedWow64',          native_type),
            ('CurrentLocale',          ctypes.c_int32),
            ('FpSwStatusReg',          ctypes.c_int32),
            ('ReservedOS',             ctypes.c_byte * 216)
        )

    return TEB


def make_peb(archbits: int):
    """Generate a PEB structure class.
    """

    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    # expected peb structure size
    expected_size = {
        32: 0x47c,
        64: 0x7c8
    }[archbits]

    # pad to expected size based on currently defined set of fields.
    # this is not very elegant, but ctypes.resize does not work on classes
    padding_size = expected_size - {
        32: 0x70,
        64: 0xc8
    }[archbits]

    # https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm
    class PEB(Struct):
        _fields_ = (
            ('InheritedAddressSpace',    ctypes.c_int8),
            ('ReadImageFileExecOptions', ctypes.c_int8),
            ('BeingDebugged',            ctypes.c_int8),
            ('BitField',                 ctypes.c_int8),
            ('Mutant',                   native_type),
            ('ImageBaseAddress',         native_type),
            ('LdrAddress',               native_type),
            ('ProcessParameters',        native_type),
            ('SubSystemData',            native_type),
            ('ProcessHeap',              native_type),
            ('FastPebLock',              native_type),
            ('AtlThunkSListPtr',         native_type),
            ('IFEOKey',                  native_type),
            ('CrossProcessFlags',        ctypes.c_int32),
            ('KernelCallbackTable',      native_type),
            ('SystemReserved',           ctypes.c_int32),
            ('AtlThunkSListPtr32',       ctypes.c_int32),
            ('ApiSetMap',                native_type),
            ('TlsExpansionCounter',      ctypes.c_int32),
            ('TlsBitmap',                native_type),
            ('TlsBitmapBits',            ctypes.c_int32 * 2),
            ('ReadOnlySharedMemoryBase', native_type),
            ('SharedData',               native_type),
            ('ReadOnlyStaticServerData', native_type),
            ('AnsiCodePageData',         native_type),
            ('OemCodePageData',          native_type),
            ('UnicodeCaseTableData',     native_type),
            ('NumberOfProcessors',       ctypes.c_int32),
            ('NtGlobalFlag',             ctypes.c_int32),
            ('CriticalSectionTimeout',   native_type),

            # more fields to be added here. in the meantime, pad the
            # structure to the size it is expected to be
            ('_padding', ctypes.c_char * padding_size)
        )

    # make sure mismatches in peb size are not overlooked
    assert PEB.sizeof() == expected_size

    return PEB


# https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
def make_unicode_string(archbits: int):
    """Generate a UNICODE_STRING structure class.
    """

    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    class UNICODE_STRING(Struct):
        _fields_ = (
            ('Length',        ctypes.c_uint16),
            ('MaximumLength', ctypes.c_uint16),
            ('Buffer',        native_type)
        )

    return UNICODE_STRING


# https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object
def make_driver_object(archbits: int):
    """Generate a DRIVER_OBJECT structure class.
    """

    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    ucstr_struct = make_unicode_string(archbits)

    class DRIVER_OBJECT(Struct):
        _fields_ = (
            ('Type',             ctypes.c_uint16),
            ('Size',             ctypes.c_uint16),
            ('DeviceObject',     native_type),
            ('Flags',            ctypes.c_uint32),
            ('DriverStart',      native_type),
            ('DriverSize',       ctypes.c_uint32),
            ('DriverSection',    native_type),
            ('DriverExtension',  native_type),
            ('DriverName',       ucstr_struct),
            ('HardwareDatabase', native_type),
            ('FastIoDispatch',   native_type),
            ('DriverInit',       native_type),
            ('DriverStartIo',    native_type),
            ('DriverUnload',     native_type),
            ('MajorFunction',    native_type * (IRP_MJ_MAXIMUM_FUNCTION + 1))
        )

    return DRIVER_OBJECT


class KSYSTEM_TIME(struct.BaseStruct):
    _fields_ = (
        ('LowPart',   ctypes.c_uint32),
        ('High1Time', ctypes.c_int32),
        ('High2Time', ctypes.c_int32)
    )


class _LARGE_INTEGER(struct.BaseStruct):
    _fields_ = (
        ('LowPart',  ctypes.c_uint32),
        ('HighPart', ctypes.c_int32)
    )


class LARGE_INTEGER(ctypes.Union):
    _fields_ = (
        ('u', _LARGE_INTEGER),
        ('QuadPart', ctypes.c_int64)
    )

# see:
# https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data/index.htm
# https://doxygen.reactos.org/d7/deb/xdk_2ketypes_8h_source.html#l01155

class KUSER_SHARED_DATA(struct.BaseStruct):
    _fields_ = (
        ('TickCountLowDeprecated',      ctypes.c_uint32),
        ('TickCountMultiplier',         ctypes.c_uint32),
        ('InterruptTime',               KSYSTEM_TIME),
        ('SystemTime',                  KSYSTEM_TIME),
        ('TimeZoneBias',                KSYSTEM_TIME),
        ('ImageNumberLow',              ctypes.c_uint16),
        ('ImageNumberHigh',             ctypes.c_uint16),
        ('NtSystemRoot',                ctypes.c_wchar * MAX_PATH),
        ('MaxStackTraceDepth',          ctypes.c_uint32),
        ('CryptoExponent',              ctypes.c_uint32),
        ('TimeZoneId',                  ctypes.c_uint32),
        ('LargePageMinimum',            ctypes.c_uint32),
        ('Reserved2',                   ctypes.c_uint32 * 7),
        ('NtProductType',               ctypes.c_uint32),
        ('ProductTypeIsValid',          ctypes.c_uint32),
        ('NtMajorVersion',              ctypes.c_uint32),
        ('NtMinorVersion',              ctypes.c_uint32),
        ('ProcessorFeatures',           ctypes.c_uint8 * PROCESSOR_FEATURE_MAX),
        ('Reserved1',                   ctypes.c_uint32),
        ('Reserved3',                   ctypes.c_uint32),
        ('TimeSlip',                    ctypes.c_uint32),
        ('AlternativeArchitecture',     ctypes.c_uint32),
        ('AltArchitecturePad',          ctypes.c_uint32),
        ('SystemExpirationDate',        LARGE_INTEGER),
        ('SuiteMask',                   ctypes.c_uint32),
        ('KdDebuggerEnabled',           ctypes.c_uint8),
        ('NXSupportPolicy',             ctypes.c_uint8),
        ('ActiveConsoleId',             ctypes.c_uint32),
        ('DismountCount',               ctypes.c_uint32),
        ('ComPlusPackage',              ctypes.c_uint32),
        ('LastSystemRITEventTickCount', ctypes.c_uint32),
        ('NumberOfPhysicalPages',       ctypes.c_uint32),
        ('SafeBootMode',                ctypes.c_uint8),
        ('TscQpcData',                  ctypes.c_uint8),    # also: VirtualizationFlags
        ('TscQpcFlags',                 ctypes.c_uint8),
        ('TscQpcPad',                   ctypes.c_uint8 * 3),
        ('SharedDataFlags',             ctypes.c_uint8),
        ('DataFlagsPad',                ctypes.c_uint8 * 3),
        ('TestRetInstruction',          ctypes.c_uint8),

        # pad structure to expected structure size
        ('_padding0', ctypes.c_uint8 * 0x2F8)
    )


def make_list_entry(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    class LIST_ENTRY(Struct):
        _fields_ = (
            ('Flink', native_type),
            ('Blink', native_type)
        )

    return LIST_ENTRY


def make_device_object(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)
    Union = struct.get_aligned_union(archbits)

    pointer_type = native_type
    ListEntry = make_list_entry(archbits)

    class KDEVICE_QUEUE_ENTRY(Struct):
        _fields_ = (
            ('DeviceListEntry', ListEntry),
            ('SortKey', ctypes.c_uint32),
            ('Inserted', ctypes.c_uint8)
        )

    class WAIT_ENTRY(Struct):
        _fields_ = (
            ('DmaWaitEntry', ListEntry),
            ('NumberOfChannels', ctypes.c_uint32),
            ('DmaContext', ctypes.c_uint32)
        )

    class WAIT_QUEUE_UNION(Union):
        _fields_ = (
            ("WaitQueueEntry", KDEVICE_QUEUE_ENTRY),
            ("Dma", WAIT_ENTRY)
        )

    class WAIT_CONTEXT_BLOCK(Struct):
        _fields_ = (
            ('WaitQueue', WAIT_QUEUE_UNION),
            ('DeviceRoutine', pointer_type),
            ('DeviceContext', pointer_type),
            ('NumberOfMapRegisters', ctypes.c_uint32),
            ('DeviceObject', pointer_type),
            ('CurrentIrp', pointer_type),
            ('BufferChainingDpc', pointer_type)
        )

    class KDEVICE_QUEUE(Struct):
        _fields_ = (
            ('Type', ctypes.c_int16),
            ('Size', ctypes.c_int16),
            ('DeviceListHead', ListEntry),
            ('Lock', ctypes.c_uint32),
            ('Busy', ctypes.c_uint8)
        )

    # https://github.com/ntdiff/headers/blob/master/Win10_1507_TS1/x64/System32/hal.dll/Standalone/_KDPC.h
    class KDPC(Struct):
        _fields_ = (
            ('Type', ctypes.c_uint8),
            ('Importance', ctypes.c_uint8),
            ('Number', ctypes.c_uint16),
            ('DpcListEntry', ListEntry),
            ('DeferredRoutine', pointer_type),
            ('DeferredContext', pointer_type),
            ('SystemArgument1', pointer_type),
            ('SystemArgument2', pointer_type),
            ('DpcData', pointer_type)
        )

    class DISPATCHER_HEADER(Struct):
        _fields_ = (
            ('Lock', ctypes.c_int32),
            ('SignalState', ctypes.c_int32),
            ('WaitListHead', ListEntry)
        )

    # https://docs.microsoft.com/vi-vn/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_object
    class DEVICE_OBJECT(Struct):
        _fields_ = (
            ('Type', ctypes.c_int16),
            ('Size', ctypes.c_uint16),
            ('ReferenceCount', ctypes.c_int32),
            ('DriverObject', pointer_type),
            ('NextDevice', pointer_type),
            ('AttachedDevice', pointer_type),
            ('CurrentIrp', pointer_type),
            ('Timer', pointer_type),
            ('Flags', ctypes.c_uint32),
            ('Characteristics', ctypes.c_uint32),
            ('Vpb', pointer_type),
            ('DeviceExtension', native_type),
            ('DeviceType', ctypes.c_uint32),
            ('StackSize', ctypes.c_int16),
            ('Queue', WAIT_CONTEXT_BLOCK),
            ('AlignmentRequirement', ctypes.c_uint32),
            ('DeviceQueue', KDEVICE_QUEUE),
            ('Dpc', KDPC),
            ('ActiveThreadCount', ctypes.c_uint32),
            ('SecurityDescriptor', pointer_type),
            ('DeviceLock', DISPATCHER_HEADER),
            ('SectorSize', ctypes.c_uint16),
            ('Spare1', ctypes.c_uint16),
            ('DeviceObjectExtension', pointer_type),
            ('Reserved', pointer_type)
        )

    return DEVICE_OBJECT


def make_io_stack_location(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)
    Union = struct.get_aligned_union(archbits)

    pointer_type = native_type

    class IO_STACK_LOCATION_FILESYSTEMCONTROL(Struct):
        _fields_ = (
            ('OutputBufferLength', native_type),  # c_uint32 padded to native size
            ('InputBufferLength', native_type),   # c_uint32 padded to native size
            ('FsControlCode', ctypes.c_uint32),
            ('Type3InputBuffer', pointer_type)
        )

    class IO_STACK_LOCATION_DEVICEIOCONTROL(Struct):
        _fields_ = (
            ('OutputBufferLength',native_type),  # c_uint32 padded to native size
            ('InputBufferLength', native_type),  # c_uint32 padded to native size
            ('IoControlCode', ctypes.c_uint32),
            ('Type3InputBuffer', pointer_type)
        )

    class IO_STACK_LOCATION_WRITE(Struct):
        _fields_ = (
            ('Length', native_type),             # c_uint32 padded to native size
            ('Key', ctypes.c_uint32),
            ('Flags', ctypes.c_uint32),
            ('ByteOffset', LARGE_INTEGER)
        )

    class IO_STACK_LOCATION_PARAM(Union):
        _fields_ = (
            ('FileSystemControl', IO_STACK_LOCATION_FILESYSTEMCONTROL),
            ('DeviceIoControl', IO_STACK_LOCATION_DEVICEIOCONTROL),
            ('Write', IO_STACK_LOCATION_WRITE)
        )

    class IO_STACK_LOCATION(Struct):
        _fields_ = (
            ('MajorFunction', ctypes.c_byte),
            ('MinorFunction', ctypes.c_byte),
            ('Flags', ctypes.c_byte),
            ('Control', ctypes.c_byte),
            ('Parameters', IO_STACK_LOCATION_PARAM),
            ('DeviceObject', pointer_type),
            ('FileObject', pointer_type),
            ('CompletionRoutine', pointer_type),
            ('Context', pointer_type)
        )

    return IO_STACK_LOCATION


def make_irp(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)
    Union = struct.get_aligned_union(archbits)

    pointer_type = native_type
    ListEntry = make_list_entry(archbits)

    class IO_STATUS_BLOCK_DUMMY(Union):
        _fields_ = (
            ('Status', ctypes.c_int32),
            ('Pointer', pointer_type)
        )

    class IO_STATUS_BLOCK(Struct):
        _fields_ = (
            ('Status', IO_STATUS_BLOCK_DUMMY),
            ('Information', pointer_type)
        )

    class AssociatedIrp(Union):
        _fields_ = (
            ('MasterIrp', pointer_type),
            ('IrpCount', ctypes.c_uint32),
            ('SystemBuffer', pointer_type)
        )

    sz_factor = archbits // 32

    class IRP(Struct):
        _fields_ = (
            ('Type', ctypes.c_uint16),
            ('Size', ctypes.c_uint16),
            ('MdlAddress', pointer_type),
            ('Flags', ctypes.c_uint32),
            ('AssociatedIrp', AssociatedIrp),
            ('ThreadListEntry', ListEntry),
            ('IoStatus', IO_STATUS_BLOCK),
            ('_padding3', ctypes.c_char * 8),
            ('UserIosb', pointer_type),
            ('UserEvent', pointer_type),
            ('Overlay', ctypes.c_char * (8 * sz_factor)),
            ('CancelRoutine', pointer_type),
            ('UserBuffer', pointer_type),
            ('_padding1', ctypes.c_char * (32 * sz_factor)),
            ('irpstack', pointer_type),     # points to a IO_STACK_LOCATION structure
            ('_padding2', ctypes.c_char * (8 * sz_factor))
        )

    return IRP


# typedef struct _MDL {
#   struct _MDL      *Next;
#   CSHORT           Size;
#   CSHORT           MdlFlags;
#   struct _EPROCESS *Process;
#   PVOID            MappedSystemVa;
#   PVOID            StartVa;
#   ULONG            ByteCount;
#   ULONG            ByteOffset;
# } MDL, *PMDL;

def make_mdl(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    pointer_type = native_type

    class MDL(Struct):
        _fields_ = (
            ('Next', pointer_type),
            ('Size', ctypes.c_uint16),
            ('MdlFlags', ctypes.c_uint16),
            ('Process', pointer_type),
            ('MappedSystemVa', pointer_type),
            ('StartVa', pointer_type),
            ('ByteCount', ctypes.c_uint32),
            ('ByteOffset', ctypes.c_uint32)
        )

    return MDL

# NOTE: the following classes are currently not needed
#
# class DISPATCHER_HEADER64(ctypes.Structure):
#     _fields_ = (
#         ('Lock', ctypes.c_int32),
#         ('Type', ctypes.c_uint8),
#         ('TimerControlFlags', ctypes.c_uint8),
#         ('ThreadControlFlags', ctypes.c_uint8),
#         ('TimerMiscFlags', ctypes.c_uint8),
#         ('SignalState', ctypes.c_int32),
#         ('WaitListHead', LIST_ENTRY64),
#     )
#
#
# class DISPATCHER_HEADER32(ctypes.Structure):
#     _fields_ = (
#         ('Lock', ctypes.c_int32),
#         ('SignalState', ctypes.c_int32),
#         ('WaitListHead', LIST_ENTRY32),
#         ('Type', ctypes.c_uint8),
#         ('TimerControlFlags', ctypes.c_uint8),
#         ('ThreadControlFlags', ctypes.c_uint8),
#         ('TimerMiscFlags', ctypes.c_uint8),
#     )
#
#
# class KAPC_STATE64(ctypes.Structure):
#     _fields_ = (
#         ('ApcListHead', LIST_ENTRY64 * 2),
#         ('Process', POINTER64),
#         ('KernelApcInProgress', ctypes.c_uint8),
#         ('KernelApcPending', ctypes.c_uint8),
#         ('UserApcPending', ctypes.c_uint8),
#     )
#
#
# class KAPC_STATE32(ctypes.Structure):
#     _fields_ = (
#         ('ApcListHead', LIST_ENTRY32 * 2),
#         ('Process', POINTER32),
#         ('KernelApcInProgress', ctypes.c_uint8),
#         ('KernelApcPending', ctypes.c_uint8),
#         ('UserApcPending', ctypes.c_uint8),
#     )
#
#
# class KTIMER64(ctypes.Structure):
#     _fields_ = (
#         ('Header', DISPATCHER_HEADER64),
#         ('DueTime', LARGE_INTEGER),
#         ('TimerListEntry', LIST_ENTRY64),
#         ('Dpc', POINTER64),
#         ('Period', ctypes.c_uint32),
#     )
#
#
# class KTIMER32(ctypes.Structure):
#     _fields_ = (
#         ('Header', DISPATCHER_HEADER32),
#         ('DueTime', LARGE_INTEGER),
#         ('TimerListEntry', LIST_ENTRY32),
#         ('Dpc', POINTER32),
#         ('Period', ctypes.c_uint32),
#     )
#
#
# class KWAIT_BLOCK64(ctypes.Structure):
#     _fields_ = (
#         ('WaitListEntry', LIST_ENTRY64),
#         ('Thread', POINTER64),
#         ('Object', POINTER64),
#         ('NextWaitBlock', POINTER64),
#         ('WaitKey', ctypes.c_uint16),
#         ('WaitType', ctypes.c_uint8),
#         ('BlockState', ctypes.c_uint8),
#     )
#
#
# class KWAIT_BLOCK32(ctypes.Structure):
#     _fields_ = (
#         ('WaitListEntry', LIST_ENTRY32),
#         ('Thread', POINTER32),
#         ('Object', POINTER32),
#         ('NextWaitBlock', POINTER32),
#         ('WaitKey', ctypes.c_uint16),
#         ('WaitType', ctypes.c_uint8),
#         ('BlockState', ctypes.c_uint8),
#     )
#
#
# class GROUP_AFFINITY64(ctypes.Structure):
#     _fields_ = (('Mask', ctypes.c_uint64), ('Group', ctypes.c_uint16),
#                 ('Reserved', ctypes.c_uint16 * 3))
#
#
# class GROUP_AFFINITY32(ctypes.Structure):
#     _fields_ = (('Mask', ctypes.c_uint32), ('Group', ctypes.c_uint16),
#                 ('Reserved', ctypes.c_uint16 * 3))
#
#
# class KAPC64(ctypes.Structure):
#     _pack_ = 8
#     _fields_ = (
#         ('Type', ctypes.c_uint8),
#         ('SpareByte0', ctypes.c_uint8),
#         ('Size', ctypes.c_uint8),
#         ('SpareByte1', ctypes.c_uint8),
#         ('SpareLong0', ctypes.c_uint32),
#         ('Thread', POINTER64),
#         ('ApcListEntry', LIST_ENTRY64),
#         ('KernelRoutine', POINTER64),
#         ('RundownRoutine', POINTER64),
#         ('NormalRoutine', POINTER64),
#         ('NormalContext', POINTER64),
#         ('SystemArgument1', POINTER64),
#         ('SystemArgument2', POINTER64),
#         ('ApcStateIndex', ctypes.c_uint8),
#         ('ApcMode', ctypes.c_uint8),
#         ('Inserted', ctypes.c_uint8),
#     )
#
#
# class KAPC32(ctypes.Structure):
#     _fields_ = ()
#
#
# class KSEMAPHORE64(ctypes.Structure):
#     _pack_ = 8
#     _fields_ = (("Header", DISPATCHER_HEADER64), ("Limit", ctypes.c_int32))
#
#
# class COUNTER_READING64(ctypes.Structure):
#     _pack_ = 8
#     _fields_ = (
#         ("Type", ctypes.c_uint32),
#         ("Index", ctypes.c_uint32),
#         ("Start", ctypes.c_uint64),
#         ("Total", ctypes.c_uint64),
#     )
#
#
# class KTHREAD_COUNTERS64(ctypes.Structure):
#     _pack_ = 8
#     _fields_ = (
#         ("WaitReasonBitMap", ctypes.c_int64),
#         ("UserData", POINTER64),
#         ("Flags", ctypes.c_uint32),
#         ("ContextSwitches", ctypes.c_uint32),
#         ("CycleTimeBias", ctypes.c_uint64),
#         ("HardwareCounters", ctypes.c_uint64),
#         ("HwCounter", COUNTER_READING64 * 16),
#     )
#
#
# class KTHREAD64(ctypes.Structure):
#     _pack_ = 8
#     _fields_ = (
#         ('Header', DISPATCHER_HEADER64),
#         ('CycleTime', ctypes.c_uint64),
#         ('QuantumTarget', ctypes.c_uint64),
#         ('InitialStack', POINTER64),
#         ('StackLimit', POINTER64),
#         ('KernelStack', POINTER64),
#         ('ThreadLock', ctypes.c_uint64),
#         ('WaitRegister', ctypes.c_uint8),  # _KWAIT_STATUS_REGISTER
#         ('Running', ctypes.c_uint8),
#         ('Alerted', ctypes.c_uint8 * 2),
#         ('MiscFlags', ctypes.c_uint32),
#         ('ApcState', KAPC_STATE64),
#         ('DeferredProcessor', ctypes.c_uint32),
#         ('ApcQueueLock', ctypes.c_uint64),
#         ('WaitStatus', ctypes.c_int64),
#         ('WaitBlockList', POINTER64),
#         ('WaitListEntry', LIST_ENTRY64),
#         ('Queue', POINTER64),
#         ('Teb', POINTER64),
#         ('Timer', KTIMER64),
#         ('ThreadFlags', ctypes.c_int32),
#         ('Spare0', ctypes.c_uint32),
#         ('WaitBlock', KWAIT_BLOCK64 * 4),
#         ('QueueListEntry', LIST_ENTRY64),
#         ('TrapFrame', POINTER64),
#         ('FirstArgument', POINTER64),
#         ('CallbackStack', POINTER64),
#         ('ApcStateIndex', ctypes.c_uint8),
#         ('BasePriority', ctypes.c_char),
#         ('PriorityDecrement', ctypes.c_char),
#         ('Preempted', ctypes.c_uint8),
#         ('AdjustReason', ctypes.c_uint8),
#         ('AdjustIncrement', ctypes.c_char),
#         ('PreviousMode', ctypes.c_char),
#         ('Saturation', ctypes.c_char),
#         ('SystemCallNumber', ctypes.c_uint32),
#         ('FreezeCount', ctypes.c_uint32),
#         ('UserAffinity', GROUP_AFFINITY64),
#         ('Process', POINTER64),
#         ('Affinity', GROUP_AFFINITY64),
#         ('IdealProcessor', ctypes.c_uint32),
#         ('UserIdealProcessor', ctypes.c_uint32),
#         ('ApcStatePointer', POINTER64 * 2),
#         ('SavedApcState', KAPC_STATE64),
#         ('Win32Thread', POINTER64),
#         ('StackBase', POINTER64),
#         ('SuspendApc', KAPC64),
#         ('SuspendSemaphore', KSEMAPHORE64),
#         ('ThreadListEntry', LIST_ENTRY64),
#         ('MutantListHead', LIST_ENTRY64),
#         ('SListFaultAddress', POINTER64),
#         ('ReadOperationCount', ctypes.c_int64),
#         ('WriteOperationCount', ctypes.c_int64),
#         ('OtherOperationCount', ctypes.c_int64),
#         ('ReadTransferCount', ctypes.c_int64),
#         ('WriteTransferCount', ctypes.c_int64),
#         ('OtherTransferCount', ctypes.c_int64),
#         ('ThreadCounters', POINTER64),
#         ('XStateSave', POINTER64))


# struct _RTL_PROCESS_MODULE_INFORMATION {
#     HANDLE Section;
#     PVOID MappedBase;
#     PVOID ImageBase;
#     ULONG ImageSize;
#     ULONG Flags;
#     USHORT LoadOrderIndex;
#     USHORT InitOrderIndex;
#     USHORT LoadCount;
#     USHORT OffsetToFileName;
#     UCHAR FullPathName[256];
# } RTL_PROCESS_MODULE_INFORMATION,

def make_rtl_process_modules(archbits: int, num_modules: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    class RTL_PROCESS_MODULE_INFORMATION(Struct):
        _fields_ = (
            ('Section',          native_type),
            ('MappedBase',       native_type),
            ('ImageBase',        native_type),
            ('ImageSize',        ctypes.c_uint32),
            ('Flags',            ctypes.c_uint32),
            ('LoadOrderIndex',   ctypes.c_uint16),
            ('InitOrderIndex',   ctypes.c_uint16),
            ('LoadCount',        ctypes.c_uint16),
            ('OffsetToFileName', ctypes.c_uint16),
            ('FullPathName',     ctypes.c_char * 256)
        )

    class RTL_PROCESS_MODULES(Struct):
        _fields_ = (
            ('NumberOfModules', ctypes.c_uint32),
            ('Modules', RTL_PROCESS_MODULE_INFORMATION * num_modules)
        )

    return RTL_PROCESS_MODULES


# struct _EPROCESS {
#     struct _KPROCESS Pcb;                                               //0x0
#     struct _EX_PUSH_LOCK ProcessLock;                                   //0x160
#     union _LARGE_INTEGER CreateTime;                                    //0x168
#     union _LARGE_INTEGER ExitTime;                                      //0x170
#     struct _EX_RUNDOWN_REF RundownProtect;                              //0x178
#     VOID* UniqueProcessId;                                              //0x180
#     struct _LIST_ENTRY ActiveProcessLinks;                              //0x188
#     ULONGLONG ProcessQuotaUsage[2];                                     //0x198
#     ULONGLONG ProcessQuotaPeak[2];                                      //0x1a8
#     volatile ULONGLONG CommitCharge;                                    //0x1b8
#     struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                           //0x1c0
#     struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;                          //0x1c8
#     ULONGLONG PeakVirtualSize;                                          //0x1d0
#     ULONGLONG VirtualSize;                                              //0x1d8
#     struct _LIST_ENTRY SessionProcessLinks;                             //0x1e0
#     VOID* DebugPort;                                                    //0x1f0
#     union {
#         VOID* ExceptionPortData;                                        //0x1f8
#         ULONGLONG ExceptionPortValue;                                   //0x1f8
#         ULONGLONG ExceptionPortState:3;                                 //0x1f8
#     };
#     struct _HANDLE_TABLE* ObjectTable;                                  //0x200
#     struct _EX_FAST_REF Token;                                          //0x208
#     ULONGLONG WorkingSetPage;                                           //0x210
#     struct _EX_PUSH_LOCK AddressCreationLock;                           //0x218
#     struct _ETHREAD* RotateInProgress;                                  //0x220
#     struct _ETHREAD* ForkInProgress;                                    //0x228
#     ULONGLONG HardwareTrigger;                                          //0x230
#     struct _MM_AVL_TABLE* PhysicalVadRoot;                              //0x238
#     VOID* CloneRoot;                                                    //0x240
#     volatile ULONGLONG NumberOfPrivatePages;                            //0x248
#     volatile ULONGLONG NumberOfLockedPages;                             //0x250
#     VOID* Win32Process;                                                 //0x258
#     struct _EJOB* volatile Job;                                         //0x260
#     VOID* SectionObject;                                                //0x268
#     VOID* SectionBaseAddress;                                           //0x270
#     ULONG Cookie;                                                       //0x278
#     ULONG UmsScheduledThreads;                                          //0x27c
#     struct _PAGEFAULT_HISTORY* WorkingSetWatch;                         //0x280
#     VOID* Win32WindowStation;                                           //0x288
#     VOID* InheritedFromUniqueProcessId;                                 //0x290
#     VOID* LdtInformation;                                               //0x298
#     VOID* Spare;                                                        //0x2a0
#     ULONGLONG ConsoleHostProcess;                                       //0x2a8
#     VOID* DeviceMap;                                                    //0x2b0
#     VOID* EtwDataSource;                                                //0x2b8
#     VOID* FreeTebHint;                                                  //0x2c0
#     VOID* FreeUmsTebHint;                                               //0x2c8
#     union {
#         struct _HARDWARE_PTE PageDirectoryPte;                          //0x2d0
#         ULONGLONG Filler;                                               //0x2d0
#     };
#     VOID* Session;                                                      //0x2d8
#     UCHAR ImageFileName[15];                                            //0x2e0
#     UCHAR PriorityClass;                                                //0x2ef
#     struct _LIST_ENTRY JobLinks;                                        //0x2f0
#     VOID* LockedPagesList;                                              //0x300
#     struct _LIST_ENTRY ThreadListHead;                                  //0x308
#     VOID* SecurityPort;                                                 //0x318
#     VOID* Wow64Process;                                                 //0x320
#     volatile ULONG ActiveThreads;                                       //0x328
#     ULONG ImagePathHash;                                                //0x32c
#     ULONG DefaultHardErrorProcessing;                                   //0x330
#     LONG LastThreadExitStatus;                                          //0x334
#     struct _PEB* Peb;                                                   //0x338
#     struct _EX_FAST_REF PrefetchTrace;                                  //0x340
#     union _LARGE_INTEGER ReadOperationCount;                            //0x348
#     union _LARGE_INTEGER WriteOperationCount;                           //0x350
#     union _LARGE_INTEGER OtherOperationCount;                           //0x358
#     union _LARGE_INTEGER ReadTransferCount;                             //0x360
#     union _LARGE_INTEGER WriteTransferCount;                            //0x368
#     union _LARGE_INTEGER OtherTransferCount;                            //0x370
#     ULONGLONG CommitChargeLimit;                                        //0x378
#     volatile ULONGLONG CommitChargePeak;                                //0x380
#     VOID* AweInfo;                                                      //0x388
#     struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;  //0x390
#     struct _MMSUPPORT Vm;                                               //0x398
#     struct _LIST_ENTRY MmProcessLinks;                                  //0x420
#     VOID* HighestUserAddress;                                           //0x430
#     ULONG ModifiedPageCount;                                            //0x438
#     union {
#         ULONG Flags2;                                                   //0x43c
#         struct {
#             ULONG JobNotReallyActive:1;                                 //0x43c
#             ULONG AccountingFolded:1;                                   //0x43c
#             ULONG NewProcessReported:1;                                 //0x43c
#             ULONG ExitProcessReported:1;                                //0x43c
#             ULONG ReportCommitChanges:1;                                //0x43c
#             ULONG LastReportMemory:1;                                   //0x43c
#             ULONG ReportPhysicalPageChanges:1;                          //0x43c
#             ULONG HandleTableRundown:1;                                 //0x43c
#             ULONG NeedsHandleRundown:1;                                 //0x43c
#             ULONG RefTraceEnabled:1;                                    //0x43c
#             ULONG NumaAware:1;                                          //0x43c
#             ULONG ProtectedProcess:1;                                   //0x43c
#             ULONG DefaultPagePriority:3;                                //0x43c
#             ULONG PrimaryTokenFrozen:1;                                 //0x43c
#             ULONG ProcessVerifierTarget:1;                              //0x43c
#             ULONG StackRandomizationDisabled:1;                         //0x43c
#             ULONG AffinityPermanent:1;                                  //0x43c
#             ULONG AffinityUpdateEnable:1;                               //0x43c
#             ULONG PropagateNode:1;                                      //0x43c
#             ULONG ExplicitAffinity:1;                                   //0x43c
#         };
#     };
#     union {
#         ULONG Flags;                                                    //0x440
#         struct {
#             ULONG CreateReported:1;                                     //0x440
#             ULONG NoDebugInherit:1;                                     //0x440
#             ULONG ProcessExiting:1;                                     //0x440
#             ULONG ProcessDelete:1;                                      //0x440
#             ULONG Wow64SplitPages:1;                                    //0x440
#             ULONG VmDeleted:1;                                          //0x440
#             ULONG OutswapEnabled:1;                                     //0x440
#             ULONG Outswapped:1;                                         //0x440
#             ULONG ForkFailed:1;                                         //0x440
#             ULONG Wow64VaSpace4Gb:1;                                    //0x440
#             ULONG AddressSpaceInitialized:2;                            //0x440
#             ULONG SetTimerResolution:1;                                 //0x440
#             ULONG BreakOnTermination:1;                                 //0x440
#             ULONG DeprioritizeViews:1;                                  //0x440
#             ULONG WriteWatch:1;                                         //0x440
#             ULONG ProcessInSession:1;                                   //0x440
#             ULONG OverrideAddressSpace:1;                               //0x440
#             ULONG HasAddressSpace:1;                                    //0x440
#             ULONG LaunchPrefetched:1;                                   //0x440
#             ULONG InjectInpageErrors:1;                                 //0x440
#             ULONG VmTopDown:1;                                          //0x440
#             ULONG ImageNotifyDone:1;                                    //0x440
#             ULONG PdeUpdateNeeded:1;                                    //0x440
#             ULONG VdmAllowed:1;                                         //0x440
#             ULONG CrossSessionCreate:1;                                 //0x440
#             ULONG ProcessInserted:1;                                    //0x440
#             ULONG DefaultIoPriority:3;                                  //0x440
#             ULONG ProcessSelfDelete:1;                                  //0x440
#             ULONG SetTimerResolutionLink:1;                             //0x440
#         };
#     };
#     LONG ExitStatus;                                                    //0x444
#     struct _MM_AVL_TABLE VadRoot;                                       //0x448
#     struct _ALPC_PROCESS_CONTEXT AlpcContext;                           //0x488
#     struct _LIST_ENTRY TimerResolutionLink;                             //0x4a8
#     ULONG RequestedTimerResolution;                                     //0x4b8
#     ULONG ActiveThreadsHighWatermark;                                   //0x4bc
#     ULONG SmallestTimerResolution;                                      //0x4c0
#     struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;           //0x4c8
# };

def make_eprocess(archbits: int):
    Struct = struct.get_aligned_struct(archbits)

    obj_size = {
        32: 0x2c0,
        64: 0x4d0
    }[archbits]

    class EPROCESS(Struct):
        # FIXME: define meaningful fields
        _fields_ = (
            ('dummy', ctypes.c_char * obj_size),
        )

    return EPROCESS


def make_ldr_data(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    ListEntry = make_list_entry(archbits)

    class PEB_LDR_DATA(Struct):
        _fields_ = (
            ('Length',                  ctypes.c_uint32),
            ('Initialized',             ctypes.c_uint32),
            ('SsHandle',                native_type),
            ('InLoadOrderModuleList',   ListEntry),
            ('InMemoryOrderModuleList', ListEntry),
            ('InInitializationOrderModuleList', ListEntry),
            ('EntryInProgress',         native_type),
            ('ShutdownInProgress',      native_type),
            ('selfShutdownThreadId',    native_type)
        )

    return PEB_LDR_DATA


def make_ldr_data_table_entry(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    pointer_type = native_type
    ListEntry = make_list_entry(archbits)
    UniString = make_unicode_string(archbits)

    class RTL_BALANCED_NODE(Struct):
        _fields_ = (
            ('Left',  pointer_type),
            ('Right', pointer_type)
        )

    class LdrDataTableEntry(Struct):
        _fields_ = (
            ('InLoadOrderLinks', ListEntry),
            ('InMemoryOrderLinks', ListEntry),
            ('InInitializationOrderLinks', ListEntry),
            ('DllBase', native_type),
            ('EntryPoint', native_type),
            ('SizeOfImage', native_type),
            ('FullDllName', UniString),
            ('BaseDllName', UniString),
            ('Flags', native_type),
            ('ObsoleteLoadCount', ctypes.c_uint16),
            ('TlsIndex', ctypes.c_uint16),
            ('HashLinks', ListEntry),
            ('TimedateStamp', native_type),
            ('EntryPointActivationContext', native_type),
            ('Lock', native_type),
            ('DdagNode', pointer_type),
            ('NodeModuleLink', ListEntry),
            ('LoadContext', native_type),
            ('ParentDllBase', native_type),
            ('SwitchBackContext', native_type),
            ('BaseAddressIndexNode', RTL_BALANCED_NODE),
            ('MappingInfoIndexNode', RTL_BALANCED_NODE),
            ('OriginalBase', native_type),
            ('LoadTime', LARGE_INTEGER),
            ('BaseNameHashValue', native_type),
            ('LoadReason', ctypes.c_uint32),
            ('ImplicitPathOptions', native_type),
            ('ReferenceCount', native_type),
        	# 1607+
            ('DependentLoadFlags', native_type),
            # 1703+
            ('SigningLevel', ctypes.c_uint8)
        )

    return LdrDataTableEntry


class FILETIME(struct.BaseStruct):
    _fields_ = (
        ('dwLowDateTime',  ctypes.c_uint32),
        ('dwHighDateTime', ctypes.c_int32)
    )

# https://docs.microsoft.com/en-us/windows/console/coord-str
class COORD(struct.BaseStruct):
    _fields_ = (
        ('X', ctypes.c_uint16),
        ('Y', ctypes.c_uint16)
    )

# https://docs.microsoft.com/en-us/windows/console/small-rect-str
class SMALL_RECT(struct.BaseStruct):
    _fields_ = (
        ('Left',   ctypes.c_uint16),
        ('Top',    ctypes.c_uint16),
        ('Right',  ctypes.c_uint16),
        ('Bottom', ctypes.c_uint16)
    )

# https://docs.microsoft.com/en-us/windows/console/console-screen-buffer-info-str
class CONSOLE_SCREEN_BUFFER_INFO(struct.BaseStruct):
    _fields_ = (
        ('dwSize',              COORD),
        ('dwCursorPosition',    COORD),
        ('wAttributes',         ctypes.c_uint16),
        ('srWindow',            SMALL_RECT),
        ('dwMaximumWindowSize', COORD)
    )

# https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
def make_process_basic_info(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    class PROCESS_BASIC_INFORMATION(Struct):
        _fields_ = (
            ('ExitStatus', ctypes.c_uint32),
            ('PebBaseAddress', native_type),
            ('AffinityMask', native_type),
            ('BasePriority', ctypes.c_uint32),
            ('UniqueProcessId', native_type),
            ('InheritedFromUniqueProcessId', native_type)
        )

    return PROCESS_BASIC_INFORMATION

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoa
def make_os_version_info(archbits: int, *, wide: bool):
    Struct = struct.get_aligned_struct(archbits)

    char_type = (ctypes.c_wchar if wide else ctypes.c_char)

    class OSVERSIONINFO(Struct):
        _fields_ = (
            ('dwOSVersionInfoSize', ctypes.c_uint32),
            ('dwMajorVersion',      ctypes.c_uint32),
            ('dwMinorVersion',      ctypes.c_uint32),
            ('dwBuildNumber',       ctypes.c_uint32),
            ('dwPlatformId',        ctypes.c_uint32),
            ('szCSDVersion',        char_type * 128)
        )

    return OSVERSIONINFO


# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
def make_os_version_info_ex(archbits: int, *, wide: bool):
    Struct = struct.get_aligned_struct(archbits)

    char_type = (ctypes.c_wchar if wide else ctypes.c_char)

    class OSVERSIONINFOEX(Struct):
        _fields_ = (
            ('dwOSVersionInfoSize', ctypes.c_uint32),
            ('dwMajorVersion',      ctypes.c_uint32),
            ('dwMinorVersion',      ctypes.c_uint32),
            ('dwBuildNumber',       ctypes.c_uint32),
            ('dwPlatformId',        ctypes.c_uint32),
            ('szCSDVersion',        char_type * 128),
            ('wServicePackMajor',   ctypes.c_uint16),
            ('wServicePackMinor',   ctypes.c_uint16),
            ('wSuiteMask',          ctypes.c_uint16),
            ('wProductType',        ctypes.c_uint8),
            ('wReserved',           ctypes.c_uint8)
        )

    return OSVERSIONINFOEX


class WindowsStruct:

    def __init__(self, ql):
        self.ql = ql
        self.addr = None
        self.ULONG_SIZE = 8
        self.LONG_SIZE = 4
        self.POINTER_SIZE = self.ql.arch.pointersize
        self.INT_SIZE = 2
        self.DWORD_SIZE = 4
        self.WORD_SIZE = 2
        self.SHORT_SIZE = 2
        self.BYTE_SIZE = 1
        self.USHORT_SIZE = 2

    def write(self, addr):
        # I want to force the subclasses to implement it
        raise NotImplementedError

    def read(self, addr):
        # I want to force the subclasses to implement it
        raise NotImplementedError

    def generic_write(self, addr: int, attributes: list):
        self.ql.log.debug("Writing Windows object " + self.__class__.__name__)
        already_written = 0
        for elem in attributes:
            (val, size, endianness, typ) = elem
            if typ == int:
                value = val.to_bytes(size, endianness)
                self.ql.log.debug("Writing to %#x with value %s" % (addr + already_written, value))
                self.ql.mem.write(addr + already_written, value)
            elif typ == bytes:
                if isinstance(val, bytearray):
                    value = bytes(val)
                else:
                    value = val
                self.ql.log.debug("Writing at addr %#x value %s" % (addr + already_written, value))

                self.ql.mem.write(addr + already_written, value)
            elif issubclass(typ, WindowsStruct):
                val.write(addr)
            else:
                raise QlErrorNotImplemented("API not implemented")

            already_written += size
        self.addr = addr

    def generic_read(self, addr: int, attributes: list):
        self.ql.log.debug("Reading Windows object " + self.__class__.__name__)
        already_read = 0
        for elem in attributes:
            (val, size, endianness, type) = elem
            value = self.ql.mem.read(addr + already_read, size)
            self.ql.log.debug("Reading from %#x value %s" % (addr + already_read, value))
            if type == int:
                elem[0] = int.from_bytes(value, endianness)
            elif type == bytes:
                elem[0] = value
            elif issubclass(type, WindowsStruct):
                obj = type(self.ql)
                obj.read(addr)
                elem[0] = obj
            else:
                raise QlErrorNotImplemented("API not implemented")
            already_read += size
        self.addr = addr

class AlignedWindowsStruct(WindowsStruct):
    def __init__(self, ql):
        super().__init__(ql)

    def write(self, addr):
        super().write(addr)

    def read(self, addr):
        super().read(addr)

    def generic_write(self, addr: int, attributes: list):
        super().generic_write(addr, attributes)

    def generic_read(self, addr: int, attributes: list):
        self.ql.log.debug("Reading unpacked Windows object aligned " + self.__class__.__name__)
        already_read = 0
        for elem in attributes:
            (val, size, endianness, type, alignment) = elem
            if already_read != 0:
                modulo = already_read % alignment
                already_read = already_read + modulo

            value = self.ql.mem.read(addr + already_read, size)
            self.ql.log.debug("Reading from %x value %s" % (addr + already_read, value))
            if type == int:
                elem[0] = int.from_bytes(value, endianness)
            elif type == bytes:
                elem[0] = value
            elif issubclass(type, WindowsStruct):
                obj = type(self.ql)
                obj.read(addr)
                elem[0] = obj
            else:
                raise QlErrorNotImplemented("API not implemented")
            already_read += size
        self.addr = addr

class Token:
    class TokenInformationClass(IntEnum):
        # https://docs.microsoft.com/it-it/windows/win32/api/winnt/ne-winnt-token_information_class
        TokenUser = 1,
        TokenGroups = 2,
        TokenPrivileges = 3,
        TokenOwner = 4,
        TokenPrimaryGroup = 5,
        TokenDefaultDacl = 6,
        TokenSource = 7,
        TokenType = 8,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenRestrictedSids = 11,
        TokenSessionId = 12,
        TokenGroupsAndPrivileges = 13,
        TokenSessionReference = 14,
        TokenSandBoxInert = 15,
        TokenAuditPolicy = 16,
        TokenOrigin = 17,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
        TokenElevation = 20,
        TokenHasRestrictions = 21,
        TokenAccessInformation = 22,
        TokenVirtualizationAllowed = 23,
        TokenVirtualizationEnabled = 24,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenMandatoryPolicy = 27,
        TokenLogonSid = 28,
        TokenIsAppContainer = 29,
        TokenCapabilities = 30,
        TokenAppContainerSid = 31,
        TokenAppContainerNumber = 32,
        TokenUserClaimAttributes = 33,
        TokenDeviceClaimAttributes = 34,
        TokenRestrictedUserClaimAttributes = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups = 37,
        TokenRestrictedDeviceGroups = 38,
        TokenSecurityAttributes = 39,
        TokenIsRestricted = 40,
        TokenProcessTrustLevel = 41,
        TokenPrivateNameSpace = 42,
        TokenSingletonAttributes = 43,
        TokenBnoIsolation = 44,
        TokenChildProcessFlags = 45,
        TokenIsLessPrivilegedAppContainer = 46,
        TokenIsSandboxed = 47,
        TokenOriginatingProcessTrustLevel = 48,
        MaxTokenInfoClass = 49

    def __init__(self, ql):
        # We will create them when we need it. There are too many structs
        self.struct = {}

        # TODO find a GOOD reference paper for the values
        self.struct[Token.TokenInformationClass.TokenUIAccess.value] = ql.pack(0x1)
        self.struct[Token.TokenInformationClass.TokenGroups.value] = ql.pack(0x1)

        # still not sure why 0x1234 executes gandcrab as admin, but 544 no. No idea (see sid refs for the values)
        subauths = (0x1234 if ql.os.profile["SYSTEM"]["permission"] == "root" else 545,)

        sid_struct = make_sid(auth_count=len(subauths))
        sid_addr = ql.os.heap.alloc(sid_struct.sizeof())

        sid_obj = sid_struct(
            Revision = 1,
            SubAuthorityCount = len(subauths),
            IdentifierAuthority = (1,),
            SubAuthority = tuple(ql.pack32(v) for v in subauths)
        )

        sid_obj.save_to(ql.mem, sid_addr)

        handle = Handle(obj=sid_obj, id=sid_addr)
        ql.os.handle_manager.append(handle)
        self.struct[Token.TokenInformationClass.TokenIntegrityLevel] = ql.pack(sid_addr)

    def get(self, value):
        res = self.struct[value]

        if res is None:
            raise QlErrorNotImplemented("API not implemented")

        return res


# Identf Authority
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
def make_sid(auth_count: int):

    # this structure should be a 6-bytes big endian integer. this is an attempt
    # to approximate that, knowing that in practice only the most significant
    # byte is actually used.
    #
    # see: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_identifier_authority
    class SID_IDENTIFIER_AUTHORITY(ctypes.BigEndianStructure):
        _pack_ = 1
        _fields_ = (
            ('Value', ctypes.c_uint32),
            ('_pad', ctypes.c_byte * 2)
        )

    assert ctypes.sizeof(SID_IDENTIFIER_AUTHORITY) == 6

    # https://geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/sertl/sid.htm
    class SID(struct.BaseStruct):
        _fields_ = (
            ('Revision', ctypes.c_uint8),
            ('SubAuthorityCount', ctypes.c_uint8),
            ('IdentifierAuthority', SID_IDENTIFIER_AUTHORITY),

            # note that ctypes does not have a way to define an array whose size is unknown
            # or flexible. although the number of items should be reflected in SubAuthorityCount,
            # this cannot be implemented. any change to that field will result in an inconsistency
            # and should be avoided

            ('SubAuthority', ctypes.c_uint32 * auth_count)
        )

        # the need of a big-endian structure forces us to define a non-BaseStruct structure field
        # which breaks the 'volatile_ref' mechanism. we here prevent the user from doing that
        @classmethod
        def volatile_ref(cls, *args):
            raise NotImplementedError(f'{cls.__name__} is not capable of volatile references')

        # let SID structures be comparable
        def __eq__(self, other):
            if not isinstance(other, SID):
                return False

            # since SID structure is not padded, we can simply memcmp the instances
            return memoryview(self).cast('B') == memoryview(other).cast('B')

    return SID


class Mutex:
    def __init__(self, name: str, type: str):
        self.name = name
        self.locked = False
        self.type = type

    def lock(self) -> None:
        self.locked = True

    def unlock(self) -> None:
        self.locked = False

    def isFree(self) -> bool:
        return not self.locked


# class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
#     _fields_ = (
#         ('OriginalFirstThunk', ctypes.c_uint32),
#         ('TimeDateStamp', ctypes.c_uint32),
#         ('ForwarderChain', ctypes.c_uint32), 
#         ('Name', ctypes.c_uint32),
#         ('FirstThunk', ctypes.c_uint32)
#     )
#
#
# class CLIENT_ID32(ctypes.Structure):
#     _fields_ = (
#         ('UniqueProcess', ctypes.c_uint32),
#         ('UniqueThread', ctypes.c_uint32)
#     )
#
#
# class CLIENT_ID64(ctypes.Structure):
#     _fields_ = (
#         ('UniqueProcess', ctypes.c_uint64),
#         ('UniqueThread', ctypes.c_uint64)
#     )

# typedef struct tagPOINT {
#   LONG x;
#   LONG y;
# } POINT, *PPOINT;
class Point(WindowsStruct):
    def __init__(self, ql, x=None, y=None):
        super().__init__(ql)
        self.x = [x, self.LONG_SIZE, "little", int]
        self.y = [y, self.LONG_SIZE, "little", int]
        self.size = self.LONG_SIZE * 2

    def write(self, addr):
        super().generic_write(addr, [self.x, self.y])

    def read(self, addr):
        super().generic_read(addr, [self.x, self.y])

# typedef struct _SYSTEM_BASIC_INFORMATION
# {
# 	ULONG Reserved;
# 	ULONG TimerResolution;
# 	ULONG PageSize;
# 	ULONG NumberOfPhysicalPages;
# 	ULONG LowestPhysicalPageNumber;
# 	ULONG HighestPhysicalPageNumber;
# 	ULONG AllocationGranularity;
# 	ULONG_PTR c;
# 	ULONG_PTR MaximumUserModeAddress;
# 	ULONG_PTR ActiveProcessorsAffinityMask;
# 	CCHAR NumberOfProcessors;
# } SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

class SystemBasicInforation(WindowsStruct):
    def __init__(self,ql, Reserved,TimerResolution,PageSize=None, NumberOfPhysicalPages=None, LowestPhysicalPageNumber=None,
                 HighestPhysicalPageNumber=None, AllocationGranularity=None,MinimumUserModeAddress=None,
                 MaximumUserModeAddress=None,ActiveProcessorsAffinityMask=None,NumberOfProcessors=None):
        super().__init__(ql)
        self.size=self.BYTE_SIZE * 24 + 5*self.POINTER_SIZE
        self.Reserved =[Reserved, self.DWORD_SIZE, "little", int]
        self.TimerResolution=[TimerResolution, self.DWORD_SIZE, "little", int]
        self.PageSize=[PageSize, self.DWORD_SIZE, "little", int]
        self.NumberOfPhysicalPages = [NumberOfPhysicalPages, self.DWORD_SIZE, "little", int]
        self.LowestPhysicalPageNumber = [LowestPhysicalPageNumber, self.DWORD_SIZE, "little", int]
        self.HighestPhysicalPageNumber = [HighestPhysicalPageNumber, self.DWORD_SIZE, "little", int]
        self.AllocationGranularity = [AllocationGranularity, self.DWORD_SIZE, "little", int]
        self.MinimumUserModeAddress = [MinimumUserModeAddress, self.POINTER_SIZE, "little", int]
        self.MaximumUserModeAddress = [MaximumUserModeAddress, self.POINTER_SIZE, "little", int]
        self.ActiveProcessorsAffinityMask = [ActiveProcessorsAffinityMask, self.POINTER_SIZE, "little", int]
        self.NumberOfProcessors = [NumberOfProcessors, self.POINTER_SIZE, "little", int]
    def write(self, addr):

        super().generic_write(addr, [self.Reserved, self.TimerResolution, self.PageSize, self.NumberOfPhysicalPages,
               self.LowestPhysicalPageNumber, self.HighestPhysicalPageNumber ,self.AllocationGranularity,
               self.MinimumUserModeAddress,self.MaximumUserModeAddress,self.ActiveProcessorsAffinityMask,
               self.NumberOfProcessors])

    def read(self, addr):
        super().generic_read(addr, [self.Reserved, self.TimerResolution, self.PageSize, self.NumberOfPhysicalPages,
               self.LowestPhysicalPageNumber, self.HighestPhysicalPageNumber ,self.AllocationGranularity,
               self.MinimumUserModeAddress,self.MaximumUserModeAddress,self.ActiveProcessorsAffinityMask,
               self.NumberOfProcessors])

# typedef struct hostent {
#  char  *h_name;
#  char  **h_aliases;
#  short h_addrtype;
#  short h_length;
#  char  **h_addr_list;
# } HOSTENT, *PHOSTENT, *LPHOSTENT;
class Hostent(WindowsStruct):
    def __init__(self, ql, name=None, aliases=None, addr_type=None, length=None, addr_list=None):
        super().__init__(ql)
        self.name = [name, self.POINTER_SIZE, "little", int]
        self.aliases = [aliases, self.POINTER_SIZE, "little", int]
        self.addr_type = [addr_type, self.SHORT_SIZE, "little", int]
        self.length = [length, self.SHORT_SIZE, "little", int]
        self.addr_list = [addr_list, len(addr_list), "little", bytes]
        self.size = self.POINTER_SIZE * 2 + self.SHORT_SIZE * 2 + len(addr_list)

    def write(self, addr):
        super().generic_write(addr, [self.name, self.aliases, self.addr_type, self.length, self.addr_list])

    def read(self, addr):
        super().generic_read(addr, [self.name, self.aliases, self.addr_type, self.length, self.addr_list])


# typedef struct _SYSTEM_INFO {
#   union {
#     DWORD dwOemId;
#     struct {
#       WORD wProcessorArchitecture;
#       WORD wReserved;
#     } DUMMYSTRUCTNAME;
#   } DUMMYUNIONNAME;
#   DWORD     dwPageSize;
#   LPVOID    lpMinimumApplicationAddress;
#   LPVOID    lpMaximumApplicationAddress;
#   DWORD_PTR dwActiveProcessorMask;
#   DWORD     dwNumberOfProcessors;
#   DWORD     dwProcessorType;
#   DWORD     dwAllocationGranularity;
#   WORD      wProcessorLevel;
#   WORD      wProcessorRevision;
# } SYSTEM_INFO, *LPSYSTEM_INFO;

def make_system_info(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)
    Union = struct.get_aligned_union(archbits)

    pointer_type = native_type

    class DUMMYSTRUCTNAME(Struct):
        _fields_ = (
            ('wProcessorArchitecture', ctypes.c_uint16),
            ('wReserved',              ctypes.c_uint16)
        )

    class DUMMYUNIONNAME(Union):
        _anonymous_ = ('_anon_0')

        _fields_ = (
            ('dwOemId', ctypes.c_uint32),
            ('_anon_0', DUMMYSTRUCTNAME)
        )

    assert ctypes.sizeof(DUMMYUNIONNAME) == 4

    class SYSTEM_INFO(Struct):
        _anonymous_ = ('_anon_1')

        _fields_ = (
            ('_anon_1',                     DUMMYUNIONNAME),
            ('dwPageSize',                  ctypes.c_uint32),
            ('lpMinimumApplicationAddress', pointer_type),
            ('lpMaximumApplicationAddress', pointer_type),
            ('dwActiveProcessorMask',       pointer_type),
            ('dwNumberOfProcessors',        ctypes.c_uint32),
            ('dwProcessorType',             ctypes.c_uint32),
            ('dwAllocationGranularity',     ctypes.c_uint32),
            ('wProcessorLevel',             ctypes.c_uint16),
            ('wProcessorRevision',          ctypes.c_uint16)
        )

    return SYSTEM_INFO


class SYSTEMTIME(struct.BaseStruct):
    _fields_ = (
        ('wYear',         ctypes.c_uint16),
        ('wMonth',        ctypes.c_uint16),
        ('wDayOfWeek',    ctypes.c_uint16),
        ('wDay',          ctypes.c_uint16),
        ('wHour',         ctypes.c_uint16),
        ('wMinute',       ctypes.c_uint16),
        ('wSecond',       ctypes.c_uint16),
        ('wMilliseconds', ctypes.c_uint16)
    )


# typedef struct _STARTUPINFO {
#   DWORD  cb;
#   LPTSTR lpReserved;
#   LPTSTR lpDesktop;
#   LPTSTR lpTitle;
#   DWORD  dwX;
#   DWORD  dwY;
#   DWORD  dwXSize;
#   DWORD  dwYSize;
#   DWORD  dwXCountChars;
#   DWORD  dwYCountChars;
#   DWORD  dwFillAttribute;
#   DWORD  dwFlags;
#   WORD   wShowWindow;
#   WORD   cbReserved2;
#   LPBYTE lpReserved2;
#   HANDLE hStdInput;
#   HANDLE hStdOutput;
#   HANDLE hStdError;
# } STARTUPINFO, *LPSTARTUPINFO;
class StartupInfo(WindowsStruct):
    def __init__(self, ql, desktop=None, title=None, x=None, y=None, x_size=None, y_size=None, x_chars=None,
                 y_chars=None, fill_attribute=None, flags=None, show=None, std_input=None, output=None, error=None):
        super().__init__(ql)
        self.size = 53 + 3 * self.ql.arch.pointersize
        self.cb = [self.size, self.DWORD_SIZE, "little", int]
        self.reserved = [0, self.POINTER_SIZE, "little", int]
        self.desktop = [desktop, self.POINTER_SIZE, "little", int]
        self.title = [title, self.POINTER_SIZE, "little", int]
        self.x = [x, self.DWORD_SIZE, "little", int]
        self.y = [y, self.DWORD_SIZE, "little", int]
        self.x_size = [x_size, self.DWORD_SIZE, "little", int]
        self.y_size = [y_size, self.DWORD_SIZE, "little", int]
        self.x_chars = [x_chars, self.DWORD_SIZE, "little", int]
        self.y_chars = [y_chars, self.DWORD_SIZE, "little", int]
        self.fill_attribute = [fill_attribute, self.DWORD_SIZE, "little", int]
        self.flags = [flags, self.DWORD_SIZE, "little", int]
        self.show = [show, self.WORD_SIZE, "little", int]
        self.reserved2 = [0, self.WORD_SIZE, "little", int]
        self.reserved3 = [0, self.POINTER_SIZE, "little", int]
        self.input = [std_input, self.POINTER_SIZE, "little", int]
        self.output = [output, self.POINTER_SIZE, "little", int]
        self.error = [error, self.POINTER_SIZE, "little", int]

    def read(self, addr):
        super().generic_read(addr, [self.cb, self.reserved, self.desktop, self.title, self.x, self.y, self.x_size,
                                    self.y_size, self.x_chars, self.y_chars, self.fill_attribute, self.flags, self.show,
                                    self.reserved2, self.reserved3, self.input, self.output, self.error])
        self.size = self.cb

    def write(self, addr):
        super().generic_write(addr, [self.cb, self.reserved, self.desktop, self.title, self.x, self.y, self.x_size,
                                     self.y_size, self.x_chars, self.y_chars, self.fill_attribute, self.flags,
                                     self.show,
                                     self.reserved2, self.reserved3, self.input, self.output, self.error])


# typedef struct _SHELLEXECUTEINFOA {
#   DWORD     cbSize;
#   ULONG     fMask;
#   HWND      hwnd;
#   LPCSTR    lpVerb;
#   LPCSTR    lpFile;
#   LPCSTR    lpParameters;
#   LPCSTR    lpDirectory;
#   int       nShow;
#   HINSTANCE hInstApp;
#   void      *lpIDList;
#   LPCSTR    lpClass;
#   HKEY      hkeyClass;
#   DWORD     dwHotKey;
#   union {
#     HANDLE hIcon;
#     HANDLE hMonitor;
#   } DUMMYUNIONNAME;
#   HANDLE    hProcess;
# } SHELLEXECUTEINFOA, *LPSHELLEXECUTEINFOA;
class ShellExecuteInfoA(WindowsStruct):
    def __init__(self, ql, fMask=None, hwnd=None, lpVerb=None, lpFile=None, lpParams=None, lpDir=None, show=None,
                 instApp=None, lpIDList=None, lpClass=None, hkeyClass=None,
                 dwHotKey=None, dummy=None, hProcess=None):
        super().__init__(ql)
        self.size = self.DWORD_SIZE + self.ULONG_SIZE + self.INT_SIZE * 2 + self.POINTER_SIZE * 11
        self.cb = [self.size, self.DWORD_SIZE, "little", int]
        # FIXME: check how longs behave, is strange that i have to put big here
        self.mask = [fMask, self.ULONG_SIZE, "big", int]
        self.hwnd = [hwnd, self.POINTER_SIZE, "little", int]
        self.verb = [lpVerb, self.POINTER_SIZE, "little", int]
        self.file = [lpFile, self.POINTER_SIZE, "little", int]
        self.params = [lpParams, self.POINTER_SIZE, "little", int]
        self.dir = [lpDir, self.POINTER_SIZE, "little", int]
        self.show = [show, self.INT_SIZE, "little", int]
        self.instApp = [instApp, self.POINTER_SIZE, "little", int]
        self.id_list = [lpIDList, self.POINTER_SIZE, "little", int]
        self.class_name = [lpClass, self.POINTER_SIZE, "little", int]
        self.class_key = [hkeyClass, self.POINTER_SIZE, "little", int]
        self.hot_key = [dwHotKey, self.INT_SIZE, "little", int]
        self.dummy = [dummy, self.POINTER_SIZE, "little", int]
        self.process = [hProcess, self.POINTER_SIZE, "little", int]

    def write(self, addr):
        super().generic_write(addr, [self.cb, self.mask, self.hwnd, self.verb, self.file, self.params, self.dir,
                                     self.show, self.instApp, self.id_list, self.class_name, self.class_key,
                                     self.hot_key, self.dummy, self.process])

    def read(self, addr):
        super().generic_read(addr, [self.cb, self.mask, self.hwnd, self.verb, self.file, self.params, self.dir,
                                    self.show, self.instApp, self.id_list, self.class_name, self.class_key,
                                    self.hot_key, self.dummy, self.process])
        self.size = self.cb


# typedef struct _UNICODE_STRING {
#   USHORT Length;
#   USHORT MaximumLength;
#   PWSTR  Buffer;
# } UNICODE_STRING
class UnicodeString(AlignedWindowsStruct):
    def write(self, addr):
        super().generic_write(addr, [self.length, self.maxLength, self.buffer])

    def read(self, addr):
        super().generic_read(addr, [self.length, self.maxLength, self.buffer])

    def __init__(self, ql, length=None, maxLength=None, buffer=None):
        super().__init__(ql)

        # on x64, self.buffer is aligned to 8
        if ql.arch.bits == 32:
            self.size = self.USHORT_SIZE * 2 + self.POINTER_SIZE
        else:
            self.size = self.USHORT_SIZE * 2 + 4 + self.POINTER_SIZE

        self.length = [length, self.USHORT_SIZE, "little", int]
        self.maxLength = [maxLength, self.USHORT_SIZE, "little", int]
        self.buffer = [buffer, self.POINTER_SIZE, "little", int]


# typedef struct _OBJECT_TYPE_INFORMATION {
# 	UNICODE_STRING TypeName;
# 	ULONG TotalNumberOfObjects;
# 	ULONG TotalNumberOfHandles;
# } OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
class ObjectTypeInformation(WindowsStruct):
    def write(self, addr):
        super().generic_write(addr, [self.us, self.handles, self.objects])

    def read(self, addr):
        super().generic_read(addr, [self.us, self.handles, self.objects])

    def __init__(self, ql, typeName: UnicodeString = None, handles=None, objects=None):
        super().__init__(ql)
        self.size = self.ULONG_SIZE * 2 + (self.USHORT_SIZE * 2 + self.POINTER_SIZE)
        self.us = [typeName, self.USHORT_SIZE * 2 + self.POINTER_SIZE, "little", UnicodeString]
        # FIXME: understand if is correct to set them as big
        self.handles = [handles, self.ULONG_SIZE, "big", int]
        self.objects = [objects, self.ULONG_SIZE, "big", int]


# typedef struct _OBJECT_ALL_TYPES_INFORMATION {
# 	ULONG NumberOfObjectTypes;
# 	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
# } OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;
class ObjectAllTypesInformation(WindowsStruct):
    def write(self, addr):
        super().generic_write(addr, [self.number, self.typeInfo])

    def read(self, addr):
        super().generic_read(addr, [self.number, self.typeInfo])

    def __init__(self, ql, objects=None, objectTypeInfo: ObjectTypeInformation = None):
        super().__init__(ql)
        self.size = self.ULONG_SIZE + (self.ULONG_SIZE * 2 + (self.USHORT_SIZE * 2 + self.POINTER_SIZE))
        # FIXME: understand if is correct to set them as big
        self.number = [objects, self.ULONG_SIZE, "big", int]
        self.typeInfo = [objectTypeInfo, self.ULONG_SIZE * 2 + (self.USHORT_SIZE * 2 + self.POINTER_SIZE), "little",
                         ObjectTypeInformation]


# typedef struct _WIN32_FIND_DATAA {
#   DWORD    dwFileAttributes;
#   FILETIME ftCreationTime;
#   FILETIME ftLastAccessTime;
#   FILETIME ftLastWriteTime;
#   DWORD    nFileSizeHigh;
#   DWORD    nFileSizeLow;
#   DWORD    dwReserved0;
#   DWORD    dwReserved1;
#   CHAR     cFileName[MAX_PATH];
#   CHAR     cAlternateFileName[14];
#   DWORD    dwFileType;
#   DWORD    dwCreatorType;
#   WORD     wFinderFlags;
# } WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;
class Win32FindData(WindowsStruct):
    def write(self, addr):
        super().generic_write(addr, 
            [
                self.file_attributes, self.creation_time,
                self.last_acces_time, self.last_write_time, 
                self.file_size_high, self.file_size_low, 
                self.reserved_0, self.reserved_1, self.file_name,
                self.alternate_file_name, self.file_type, 
                self.creator_type, self.finder_flags
            ])
    
    def read(self, addr):
        super().generic_read(addr, 
            [
                self.file_attributes, self.creation_time,
                self.last_acces_time, self.last_write_time, 
                self.file_size_high, self.file_size_low, 
                self.reserved_0, self.reserved_1, self.file_name,
                self.alternate_file_name, self.file_type, 
                self.creator_type, self.finder_flags
            ])

    def __init__(self, 
                ql, 
                file_attributes=None, 
                creation_time=None, 
                last_acces_time=None,
                last_write_time=None, 
                file_size_high=None,
                file_size_low=None,
                reserved_0=None, 
                reserved_1=None, 
                file_name=None,
                alternate_filename=None,
                file_type=None, 
                creator_type=None, 
                finder_flags=None):
        super().__init__(ql)
        
        # Size of FileTime == 2*(DWORD)
        self.size = (
            self.DWORD_SIZE               # dwFileAttributes
            + (3 * (2 * self.DWORD_SIZE)) # ftCreationTime, ftLastAccessTime, ftLastWriteTime
            + self.DWORD_SIZE             # nFileSizeHigh
            + self.DWORD_SIZE             # nFileSizeLow
            + self.DWORD_SIZE             # dwReservered0
            + self.DWORD_SIZE             # dwReservered1
            + (self.BYTE_SIZE * 260)      # cFileName[MAX_PATH]
            + (self.BYTE_SIZE * 14)       # cAlternateFileName[14]
            + self.DWORD_SIZE             # dwFileType
            + self.DWORD_SIZE             # dwCreatorType
            + self.WORD_SIZE)             # wFinderFlags
        
        self.file_attributes = file_attributes
        self.creation_time = creation_time
        self.last_acces_time = last_acces_time
        self.last_write_time = last_write_time
        self.file_size_high = file_size_high
        self.file_size_low = file_size_low
        self.reserved_0 = reserved_0
        self.reserved_1 = reserved_1
        self.file_name = file_name
        self.alternate_file_name = alternate_filename
        self.file_type = file_type
        self.creator_type = creator_type
        self.finder_flags = finder_flags

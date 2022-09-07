#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from enum import IntEnum
from functools import lru_cache

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

class NT_TIB(struct.BaseStruct):
    '''
    _NT_TIB structure

    Below output is from Windows RS4
    0: kd> dt _NT_TIB
    nt!_NT_TIB
        +0x000 ExceptionList    : Ptr64 _EXCEPTION_REGISTRATION_RECORD
        +0x008 StackBase        : Ptr64 Void
        +0x010 StackLimit       : Ptr64 Void
        +0x018 SubSystemTib     : Ptr64 Void
        +0x020 FiberData        : Ptr64 Void
        +0x020 Version          : Uint4B
        +0x028 ArbitraryUserPointer : Ptr64 Void
        +0x030 Self             : Ptr64 _NT_TIB
    '''

    _fields_ = (
        ('ExceptionList',           ctypes.c_void_p),
        ('StackBase',               ctypes.c_void_p),
        ('StackLimit',              ctypes.c_void_p),
        ('SubSystemTib',            ctypes.c_void_p),
        ('FiberData',               ctypes.c_void_p),
        ('Version',                 ctypes.c_uint * 4),
        ('ArbitraryUserPointer',    ctypes.c_void_p),
        ('Self',                    ctypes.c_void_p),
    )



# https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
@lru_cache(maxsize=2)
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

class KTHREAD(struct.BaseStruct):
    '''
    Definition for 64-bit KTHREAD structure
    '''

    _fields_ = (
        ('Header',              ctypes.c_void_p),   # Supposed to be DISPATCHER_HEADER64
        ('CycleTime',           ctypes.c_uint64),
        ('QuantumTarget',       ctypes.c_uint64),
        ('InitialStack',        ctypes.c_void_p),   # Supposed to be POINTER64
        ('StackLimit',          ctypes.c_void_p),   # Supposed to be POINTER64
        ('KernelStack',         ctypes.c_void_p),   # Supposed to be POINTER64
        ('ThreadLock',          ctypes.c_uint64),
        ('WaitRegister',        ctypes.c_uint8),
        ('Running',             ctypes.c_uint8),
        ('Alerted',             ctypes.c_uint8),
        ('MiscFlags',           ctypes.c_uint32),
        ('ApcState',            ctypes.c_void_p),   # Supposed to be KAPC_STATE64
        ('DeferredProcessor',   ctypes.c_uint32),
        ('ApcQueueLock',        ctypes.c_uint64),
        ('WaitStatus',          ctypes.c_int64),
        ('WaitBlockList',       ctypes.c_void_p),   # Supposed to be POINTER64
        ('WaitListEntry',       ctypes.c_void_p),   # Supposed to be LIST_ENTRY64
        ('Queue',               ctypes.c_void_p),   # Supposed to be POINTER64
        ('Teb',                 ctypes.c_void_p),   # Supposed to be POINTER64
        ('Timer',               ctypes.c_void_p),   # Supposed to be KTIMER64
        ('ThreadFlags',         ctypes.c_int32),
        ('Spare0',              ctypes.c_uint32),
        ('WaitBlock',           ctypes.c_void_p),   # Supposed to be KWAIT_BLOCK64 * 4
        ('QueueListEntry',      ctypes.c_void_p),   # Supposed to be LIST_ENTRY64
        ('TrapFrame',           ctypes.c_void_p),   # Supposed to be POINTER64
        ('FirstArgument',       ctypes.c_void_p),   # Supposed to be POINTER64
        ('CallbackStack',       ctypes.c_void_p),   # Supposed to be POINTER64
        ('ApcStateIndex',       ctypes.c_uint8),
        ('BasePriority',        ctypes.c_char),
        ('PriorityDecrement',   ctypes.c_char),
        ('Preempted',           ctypes.c_uint8),
        ('AdjustReason',        ctypes.c_uint8),
        ('AdjustIncrement',     ctypes.c_char),
        ('PreviousMode',        ctypes.c_char),
        ('Saturation',          ctypes.c_char),
        ('SystemCallNumber',    ctypes.c_uint32),
        ('FreezeCount',         ctypes.c_uint32),
        ('UserAffinity',        ctypes.c_void_p),   # Supposed to be GROUP_AFFINITY64
        ('Process',             ctypes.c_void_p),   # Supposed to be POINTER64
        ('Affinity',            ctypes.c_void_p),   # Supposed to be GROUP_AFFINITY64
        ('IdealProcessor',      ctypes.c_uint32),
        ('UserIdealProcessor',  ctypes.c_uint32),
        ('ApcStatePointer',     ctypes.c_void_p),   # Supposed to be POINTER 64 * 2
        ('SavedApcState',       ctypes.c_void_p),   # Supposed to be KAPC_STATE64
        ('Win32Thread',         ctypes.c_void_p),   # Supposed to be POINTER64
        ('StackBase',           ctypes.c_void_p),   # Supposed to be POINTER64
        ('SuspendApc',          ctypes.c_void_p),   # Supposed to be KAPC64
        ('SuspendSemaphore',    ctypes.c_void_p),   # Supposed to be KSEMAPHORE64
        ('ThreadListEntry',     ctypes.c_void_p),   # Supposed to be LIST_ENTRY64
        ('MutantListHead',      ctypes.c_void_p),   # Supposed to be LIST_ENTRY64
        ('SListFaultAddress',   ctypes.c_void_p),   # Supposed to be POINTER64
        ('ReadOperationCount',  ctypes.c_int64),
        ('WriteOperationCount', ctypes.c_int64),
        ('OtherOperationCount', ctypes.c_int64),
        ('ReadTransferCount',   ctypes.c_int64),
        ('WriteTransferCount',  ctypes.c_int64),
        ('OtherTransferCount',  ctypes.c_int64),
        ('ThreadCounters',      ctypes.c_void_p),   # Supposed to be POINTER64
        ('XStateSave',          ctypes.c_void_p)
    )   # Supposed to be POINTER64

class KNODE(struct.BaseStruct):
    '''
    Below output is from Windows 10 RS4
    ntdll!_KNODE
        +0x000 IdleNonParkedCpuSet : Uint8B
        +0x008 IdleSmtSet       : Uint8B
        +0x010 IdleCpuSet       : Uint8B
        +0x040 DeepIdleSet      : Uint8B
        +0x048 IdleConstrainedSet : Uint8B
        +0x050 NonParkedSet     : Uint8B
        +0x058 NonIsrTargetedSet : Uint8B
        +0x060 ParkLock         : Int4B
        +0x064 Seed             : Uint4B
        +0x080 SiblingMask      : Uint4B
        +0x088 Affinity         : _GROUP_AFFINITY
        +0x088 AffinityFill     : [10] UChar
        +0x092 NodeNumber       : Uint2B
        +0x094 PrimaryNodeNumber : Uint2B
        +0x096 Stride           : UChar
        +0x097 Spare0           : UChar
        +0x098 SharedReadyQueueLeaders : Uint8B
        +0x0a0 ProximityId      : Uint4B
        +0x0a4 Lowest           : Uint4B
        +0x0a8 Highest          : Uint4B
        +0x0ac MaximumProcessors : UChar
        +0x0ad Flags            : _flags
        +0x0ae Spare10          : UChar
        +0x0b0 HeteroSets       : [5] _KHETERO_PROCESSOR_SET
        +0x128 PpmConfiguredQosSets : [4] Uint8B
    '''

    _fields_ = (
        ('IdleNonParkedCpuSet',     ctypes.c_uint8),
        ('IdleSmtSet',              ctypes.c_uint8),
        ('IdleCpuSet',              ctypes.c_uint8),
        ('DeepIdleSet',             ctypes.c_uint8),
        ('IdleConstrainedSet',      ctypes.c_uint8),
        ('NonParkedSet',            ctypes.c_uint8),
        ('NonIsrTargetedSet',       ctypes.c_uint8),
        ('ParkLock',                ctypes.c_int),
        ('Seed',                    ctypes.c_uint),
        ('SiblingMask',             ctypes.c_uint),
        ('Affinity',                ctypes.c_void_p),
        ('AffinityFill',            ctypes.c_char * 10),
        ('NodeNumber',              ctypes.c_uint),
        ('PrimaryNodeNumber',       ctypes.c_uint),
        ('Stride',                  ctypes.c_char),
        ('Spare0',                  ctypes.c_char),
        ('SharedReadyQueueLeaders', ctypes.c_uint8),
        ('ProximityId',             ctypes.c_uint),
        ('Lowest',                  ctypes.c_uint),
        ('Highest',                 ctypes.c_uint),
        ('MaximumProcessors',       ctypes.c_char),
        ('Flags',                   ctypes.c_void_p),
        ('Spare10',                 ctypes.c_char),
        ('HeteroSets',              ctypes.c_void_p),
        ('PpmConfiguredQosSets',    ctypes.c_uint8 * 8)
    )


class KPRCB(struct.BaseStruct):
    '''
    Definition for 64-bit KPRCB structure

    Windows 10 RS4
    ntdll!_KPRCB
   +0x000 MxCsr            : Uint4B
   +0x004 LegacyNumber     : UChar
   +0x005 ReservedMustBeZero : UChar
   +0x006 InterruptRequest : UChar
   +0x007 IdleHalt         : UChar
   +0x008 CurrentThread    : Ptr64 _KTHREAD
   +0x010 NextThread       : Ptr64 _KTHREAD
   +0x018 IdleThread       : Ptr64 _KTHREAD
   +0x020 NestingLevel     : UChar
   +0x021 ClockOwner       : UChar
   +0x022 PendingTickFlags : UChar
   +0x022 PendingTick      : Pos 0, 1 Bit
   +0x022 PendingBackupTick : Pos 1, 1 Bit
   +0x023 IdleState        : UChar
   +0x024 Number           : Uint4B
   +0x028 RspBase          : Uint8B
   +0x030 PrcbLock         : Uint8B
   +0x038 PriorityState    : Ptr64 Char
   +0x040 CpuType          : Char
   +0x041 CpuID            : Char
   +0x042 CpuStep          : Uint2B
   +0x042 CpuStepping      : UChar
   +0x043 CpuModel         : UChar
   +0x044 MHz              : Uint4B
   +0x048 HalReserved      : [8] Uint8B
   +0x088 MinorVersion     : Uint2B
   +0x08a MajorVersion     : Uint2B
   +0x08c BuildType        : UChar
   +0x08d CpuVendor        : UChar
   +0x08e CoresPerPhysicalProcessor : UChar
   +0x08f LogicalProcessorsPerCore : UChar
   +0x090 PrcbPad04        : [6] Uint8B
   +0x0c0 ParentNode       : Ptr64 _KNODE
   +0x0c8 GroupSetMember   : Uint8B
   +0x0d0 Group            : UChar
   +0x0d1 GroupIndex       : UChar
   +0x0d2 PrcbPad05        : [2] UChar
   +0x0d4 InitialApicId    : Uint4B
   +0x0d8 ScbOffset        : Uint4B
   +0x0dc ApicMask         : Uint4B
   +0x0e0 AcpiReserved     : Ptr64 Void
   +0x0e8 CFlushSize       : Uint4B
   +0x0ec PrcbFlags        : _KPRCBFLAG
   +0x0f0 TrappedSecurityDomain : Uint8B
   +0x0f8 BpbState         : UChar
   +0x0f8 BpbCpuIdle       : Pos 0, 1 Bit
   +0x0f8 BpbFlushRsbOnTrap : Pos 1, 1 Bit
   +0x0f8 BpbIbpbOnReturn  : Pos 2, 1 Bit
   +0x0f8 BpbIbpbOnTrap    : Pos 3, 1 Bit
   +0x0f8 BpbStateReserved : Pos 4, 4 Bits
   +0x0f9 BpbFeatures      : UChar
   +0x0f9 BpbClearOnIdle   : Pos 0, 1 Bit
   +0x0f9 BpbEnabled       : Pos 1, 1 Bit
   +0x0f9 BpbSmep          : Pos 2, 1 Bit
   +0x0f9 BpbFeaturesReserved : Pos 3, 5 Bits
   +0x0fa BpbCurrentSpecCtrl : UChar
   +0x0fb BpbKernelSpecCtrl : UChar
   +0x0fc BpbNmiSpecCtrl   : UChar
   +0x0fd BpbUserSpecCtrl  : UChar
   +0x0fe BpbPad           : [2] UChar
   +0x0f0 PrcbPad11        : [2] Uint8B
   +0x100 ProcessorState   : _KPROCESSOR_STATE
   +0x6c0 ExtendedSupervisorState : Ptr64 _XSAVE_AREA_HEADER
   +0x6c8 ProcessorSignature : Uint4B
   +0x6cc PrcbPad11a       : Uint4B
   +0x6d0 PrcbPad12        : [4] Uint8B
   +0x6f0 LockQueue        : [17] _KSPIN_LOCK_QUEUE
   +0x800 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x900 PPNxPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x1500 PPNPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x2100 PPPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x2d00 PrcbPad20        : Uint8B
   +0x2d08 DeferredReadyListHead : _SINGLE_LIST_ENTRY
   +0x2d10 MmPageFaultCount : Int4B
   +0x2d14 MmCopyOnWriteCount : Int4B
   +0x2d18 MmTransitionCount : Int4B
   +0x2d1c MmDemandZeroCount : Int4B
   +0x2d20 MmPageReadCount  : Int4B
   +0x2d24 MmPageReadIoCount : Int4B
   +0x2d28 MmDirtyPagesWriteCount : Int4B
   +0x2d2c MmDirtyWriteIoCount : Int4B
   +0x2d30 MmMappedPagesWriteCount : Int4B
   +0x2d34 MmMappedWriteIoCount : Int4B
   +0x2d38 KeSystemCalls    : Uint4B
   +0x2d3c KeContextSwitches : Uint4B
   +0x2d40 PrcbPad40        : Uint4B
   +0x2d44 CcFastReadNoWait : Uint4B
   +0x2d48 CcFastReadWait   : Uint4B
   +0x2d4c CcFastReadNotPossible : Uint4B
   +0x2d50 CcCopyReadNoWait : Uint4B
   +0x2d54 CcCopyReadWait   : Uint4B
   +0x2d58 CcCopyReadNoWaitMiss : Uint4B
   +0x2d5c IoReadOperationCount : Int4B
   +0x2d60 IoWriteOperationCount : Int4B
   +0x2d64 IoOtherOperationCount : Int4B
   +0x2d68 IoReadTransferCount : _LARGE_INTEGER
   +0x2d70 IoWriteTransferCount : _LARGE_INTEGER
   +0x2d78 IoOtherTransferCount : _LARGE_INTEGER
   +0x2d80 PacketBarrier    : Int4B
   +0x2d84 TargetCount      : Int4B
   +0x2d88 IpiFrozen        : Uint4B
   +0x2d8c PrcbPad30        : Uint4B
   +0x2d90 IsrDpcStats      : Ptr64 Void
   +0x2d98 DeviceInterrupts : Uint4B
   +0x2d9c LookasideIrpFloat : Int4B
   +0x2da0 InterruptLastCount : Uint4B
   +0x2da4 InterruptRate    : Uint4B
   +0x2da8 LastNonHrTimerExpiration : Uint8B
   +0x2db0 PrcbPad35        : [2] Uint8B
   +0x2dc0 InterruptObjectPool : _SLIST_HEADER
   +0x2dd0 PrcbPad41        : [6] Uint8B
   +0x2e00 DpcData          : [2] _KDPC_DATA
   +0x2e50 DpcStack         : Ptr64 Void
   +0x2e58 MaximumDpcQueueDepth : Int4B
   +0x2e5c DpcRequestRate   : Uint4B
   +0x2e60 MinimumDpcRate   : Uint4B
   +0x2e64 DpcLastCount     : Uint4B
   +0x2e68 ThreadDpcEnable  : UChar
   +0x2e69 QuantumEnd       : UChar
   +0x2e6a DpcRoutineActive : UChar
   +0x2e6b IdleSchedule     : UChar
   +0x2e6c DpcRequestSummary : Int4B
   +0x2e6c DpcRequestSlot   : [2] Int2B
   +0x2e6c NormalDpcState   : Int2B
   +0x2e6e ThreadDpcState   : Int2B
   +0x2e6c DpcNormalProcessingActive : Pos 0, 1 Bit
   +0x2e6c DpcNormalProcessingRequested : Pos 1, 1 Bit
   +0x2e6c DpcNormalThreadSignal : Pos 2, 1 Bit
   +0x2e6c DpcNormalTimerExpiration : Pos 3, 1 Bit
   +0x2e6c DpcNormalDpcPresent : Pos 4, 1 Bit
   +0x2e6c DpcNormalLocalInterrupt : Pos 5, 1 Bit
   +0x2e6c DpcNormalSpare   : Pos 6, 10 Bits
   +0x2e6c DpcThreadActive  : Pos 16, 1 Bit
   +0x2e6c DpcThreadRequested : Pos 17, 1 Bit
   +0x2e6c DpcThreadSpare   : Pos 18, 14 Bits
   +0x2e70 LastTimerHand    : Uint4B
   +0x2e74 LastTick         : Uint4B
   +0x2e78 ClockInterrupts  : Uint4B
   +0x2e7c ReadyScanTick    : Uint4B
   +0x2e80 InterruptObject  : [256] Ptr64 Void
   +0x3680 TimerTable       : _KTIMER_TABLE
   +0x5880 DpcGate          : _KGATE
   +0x5898 PrcbPad52        : Ptr64 Void
   +0x58a0 CallDpc          : _KDPC
   +0x58e0 ClockKeepAlive   : Int4B
   +0x58e4 PrcbPad60        : [2] UChar
   +0x58e6 NmiActive        : Uint2B
   +0x58e8 DpcWatchdogPeriod : Int4B
   +0x58ec DpcWatchdogCount : Int4B
   +0x58f0 KeSpinLockOrdering : Int4B
   +0x58f4 DpcWatchdogProfileCumulativeDpcThreshold : Uint4B
   +0x58f8 CachedPtes       : Ptr64 Void
   +0x5900 WaitListHead     : _LIST_ENTRY
   +0x5910 WaitLock         : Uint8B
   +0x5918 ReadySummary     : Uint4B
   +0x591c AffinitizedSelectionMask : Int4B
   +0x5920 QueueIndex       : Uint4B
   +0x5924 PrcbPad75        : [3] Uint4B
   +0x5930 TimerExpirationDpc : _KDPC
   +0x5970 ScbQueue         : _RTL_RB_TREE
   +0x5980 DispatcherReadyListHead : [32] _LIST_ENTRY
   +0x5b80 InterruptCount   : Uint4B
   +0x5b84 KernelTime       : Uint4B
   +0x5b88 UserTime         : Uint4B
   +0x5b8c DpcTime          : Uint4B
   +0x5b90 InterruptTime    : Uint4B
   +0x5b94 AdjustDpcThreshold : Uint4B
   +0x5b98 DebuggerSavedIRQL : UChar
   +0x5b99 GroupSchedulingOverQuota : UChar
   +0x5b9a DeepSleep        : UChar
   +0x5b9b PrcbPad80        : UChar
   +0x5b9c DpcTimeCount     : Uint4B
   +0x5ba0 DpcTimeLimit     : Uint4B
   +0x5ba4 PeriodicCount    : Uint4B
   +0x5ba8 PeriodicBias     : Uint4B
   +0x5bac AvailableTime    : Uint4B
   +0x5bb0 KeExceptionDispatchCount : Uint4B
   +0x5bb4 ReadyThreadCount : Uint4B
   +0x5bb8 ReadyQueueExpectedRunTime : Uint8B
   +0x5bc0 StartCycles      : Uint8B
   +0x5bc8 TaggedCyclesStart : Uint8B
   +0x5bd0 TaggedCycles     : [2] Uint8B
   +0x5be0 GenerationTarget : Uint8B
   +0x5be8 AffinitizedCycles : Uint8B
   +0x5bf0 ImportantCycles  : Uint8B
   +0x5bf8 UnimportantCycles : Uint8B
   +0x5c00 DpcWatchdogProfileSingleDpcThreshold : Uint4B
   +0x5c04 MmSpinLockOrdering : Int4B
   +0x5c08 CachedStack      : Ptr64 Void
   +0x5c10 PageColor        : Uint4B
   +0x5c14 NodeColor        : Uint4B
   +0x5c18 NodeShiftedColor : Uint4B
   +0x5c1c SecondaryColorMask : Uint4B
   +0x5c20 PrcbPad81        : [7] UChar
   +0x5c27 TbFlushListActive : UChar
   +0x5c28 PrcbPad82        : [2] Uint8B
   +0x5c38 CycleTime        : Uint8B
   +0x5c40 Cycles           : [4] [2] Uint8B
   +0x5c80 CcFastMdlReadNoWait : Uint4B
   +0x5c84 CcFastMdlReadWait : Uint4B
   +0x5c88 CcFastMdlReadNotPossible : Uint4B
   +0x5c8c CcMapDataNoWait  : Uint4B
   +0x5c90 CcMapDataWait    : Uint4B
   +0x5c94 CcPinMappedDataCount : Uint4B
   +0x5c98 CcPinReadNoWait  : Uint4B
   +0x5c9c CcPinReadWait    : Uint4B
   +0x5ca0 CcMdlReadNoWait  : Uint4B
   +0x5ca4 CcMdlReadWait    : Uint4B
   +0x5ca8 CcLazyWriteHotSpots : Uint4B
   +0x5cac CcLazyWriteIos   : Uint4B
   +0x5cb0 CcLazyWritePages : Uint4B
   +0x5cb4 CcDataFlushes    : Uint4B
   +0x5cb8 CcDataPages      : Uint4B
   +0x5cbc CcLostDelayedWrites : Uint4B
   +0x5cc0 CcFastReadResourceMiss : Uint4B
   +0x5cc4 CcCopyReadWaitMiss : Uint4B
   +0x5cc8 CcFastMdlReadResourceMiss : Uint4B
   +0x5ccc CcMapDataNoWaitMiss : Uint4B
   +0x5cd0 CcMapDataWaitMiss : Uint4B
   +0x5cd4 CcPinReadNoWaitMiss : Uint4B
   +0x5cd8 CcPinReadWaitMiss : Uint4B
   +0x5cdc CcMdlReadNoWaitMiss : Uint4B
   +0x5ce0 CcMdlReadWaitMiss : Uint4B
   +0x5ce4 CcReadAheadIos   : Uint4B
   +0x5ce8 MmCacheTransitionCount : Int4B
   +0x5cec MmCacheReadCount : Int4B
   +0x5cf0 MmCacheIoCount   : Int4B
   +0x5cf4 PrcbPad91        : Uint4B
   +0x5cf8 MmInternal       : Ptr64 Void
   +0x5d00 PowerState       : _PROCESSOR_POWER_STATE
   +0x5f00 HyperPte         : Ptr64 Void
   +0x5f08 ScbList          : _LIST_ENTRY
   +0x5f18 ForceIdleDpc     : _KDPC
   +0x5f58 DpcWatchdogDpc   : _KDPC
   +0x5f98 DpcWatchdogTimer : _KTIMER
   +0x5fd8 Cache            : [5] _CACHE_DESCRIPTOR
   +0x6014 CacheCount       : Uint4B
   +0x6018 CachedCommit     : Uint4B
   +0x601c CachedResidentAvailable : Uint4B
   +0x6020 WheaInfo         : Ptr64 Void
   +0x6028 EtwSupport       : Ptr64 Void
   +0x6030 ExSaPageArray    : Ptr64 Void
   +0x6038 KeAlignmentFixupCount : Uint4B
   +0x603c PrcbPad95        : Uint4B
   +0x6040 HypercallPageList : _SLIST_HEADER
   +0x6050 StatisticsPage   : Ptr64 Uint8B
   +0x6058 PrcbPad85        : [5] Uint8B
   +0x6080 HypercallCachedPages : Ptr64 Void
   +0x6088 VirtualApicAssist : Ptr64 Void
   +0x6090 PackageProcessorSet : _KAFFINITY_EX
   +0x6138 PackageId        : Uint4B
   +0x613c PrcbPad86        : Uint4B
   +0x6140 SharedReadyQueueMask : Uint8B
   +0x6148 SharedReadyQueue : Ptr64 _KSHARED_READY_QUEUE
   +0x6150 SharedQueueScanOwner : Uint4B
   +0x6154 ScanSiblingIndex : Uint4B
   +0x6158 CoreProcessorSet : Uint8B
   +0x6160 ScanSiblingMask  : Uint8B
   +0x6168 LLCMask          : Uint8B
   +0x6170 CacheProcessorMask : [5] Uint8B
   +0x6198 ProcessorProfileControlArea : Ptr64 _PROCESSOR_PROFILE_CONTROL_AREA
   +0x61a0 ProfileEventIndexAddress : Ptr64 Void
   +0x61a8 DpcWatchdogProfile : Ptr64 Ptr64 Void
   +0x61b0 DpcWatchdogProfileCurrentEmptyCapture : Ptr64 Ptr64 Void
   +0x61b8 SchedulerAssist  : Ptr64 Void
   +0x61c0 SynchCounters    : _SYNCH_COUNTERS
   +0x6278 PrcbPad94        : Uint8B
   +0x6280 FsCounters       : _FILESYSTEM_DISK_COUNTERS
   +0x6290 VendorString     : [13] UChar
   +0x629d PrcbPad100       : [3] UChar
   +0x62a0 FeatureBits      : Uint8B
   +0x62a8 UpdateSignature  : _LARGE_INTEGER
   +0x62b0 PteBitCache      : Uint8B
   +0x62b8 PteBitOffset     : Uint4B
   +0x62bc PrcbPad105       : Uint4B
   +0x62c0 Context          : Ptr64 _CONTEXT
   +0x62c8 ContextFlagsInit : Uint4B
   +0x62cc PrcbPad115       : Uint4B
   +0x62d0 ExtendedState    : Ptr64 _XSAVE_AREA
   +0x62d8 IsrStack         : Ptr64 Void
   +0x62e0 EntropyTimingState : _KENTROPY_TIMING_STATE
   +0x6430 PrcbPad110       : Uint8B
   +0x6438 PrcbPad111       : [7] Uint8B
   +0x6470 AbSelfIoBoostsList : _SINGLE_LIST_ENTRY
   +0x6478 AbPropagateBoostsList : _SINGLE_LIST_ENTRY
   +0x6480 AbDpc            : _KDPC
   +0x64c0 IoIrpStackProfilerCurrent : _IOP_IRP_STACK_PROFILER
   +0x6514 IoIrpStackProfilerPrevious : _IOP_IRP_STACK_PROFILER
   +0x6568 SecureFault      : _KSECURE_FAULT_INFORMATION
   +0x6578 PrcbPad120       : Uint8B
   +0x6580 LocalSharedReadyQueue : _KSHARED_READY_QUEUE
   +0x67f0 PrcbPad125       : [2] Uint8B
   +0x6800 TimerExpirationTraceCount : Uint4B
   +0x6804 PrcbPad127       : Uint4B
   +0x6808 TimerExpirationTrace : [16] _KTIMER_EXPIRATION_TRACE
   +0x6908 PrcbPad128       : [7] Uint8B
   +0x6940 Mailbox          : Ptr64 _REQUEST_MAILBOX
   +0x6948 PrcbPad130       : [7] Uint8B
   +0x6980 SelfmapLockHandle : [4] _KLOCK_QUEUE_HANDLE
   +0x69e0 PrcbPad135       : [1184] UChar
   +0x6e80 KernelDirectoryTableBase : Uint8B
   +0x6e88 RspBaseShadow    : Uint8B
   +0x6e90 UserRspShadow    : Uint8B
   +0x6e98 ShadowFlags      : Uint4B
   +0x6e9c VerwSelector     : Uint2B
   +0x6e9e PrcbPad139       : Uint2B
   +0x6ea0 PrcbPad140       : [508] Uint8B
   +0x7e80 RequestMailbox   : [1] _REQUEST_MAILBOX
    '''

    # We need a native pointer so that we can write the address of _KTREAD structure
    native_type = struct.get_native_type(64)
    pointer_type = native_type

    _fields_ = (
        ('MxCsr',                       ctypes.c_ulong),
        ('Number',                      ctypes.c_ushort),
        ('LegacyNumber',                ctypes.c_char),
        ('ReservedMustBeZero',          ctypes.c_char),
        ('InterruptRequest',            ctypes.c_bool),
        ('IdleHalt',                    ctypes.c_bool),
        ('CurrentThread',               pointer_type),          # _KTHREAD
        ('NextThread',                  pointer_type),          # _KTHREAD
        ('IdleThread',                  pointer_type),          # _KTHREAD
        ('NestingLevel',                ctypes.c_char),
        ('ClockOwner',                  ctypes.c_char),
        ('PendingTickFlags',            ctypes.c_char),
        ('PendingTick',                 ctypes.c_void_p),       # POS 0 : BIT 1
        ('PendingBackupTick',           ctypes.c_void_p),       # POS 1 : BIT 1
        ('IdleState',                   ctypes.c_char),
        ('Number',                      ctypes.c_uint),
        ('RspBase',                     ctypes.c_uint8),
        ('PrcbLock',                    ctypes.c_uint8),
        ('PriorityState',               ctypes.c_char_p),
        ('CpuType',                     ctypes.c_char),
        ('CpuStep',                     ctypes.c_uint),
        ('CpuStepping',                 ctypes.c_char),
        ('CpuModel',                    ctypes.c_char),
        ('MHz',                         ctypes.c_uint),
        ('HalReserved',                 ctypes.c_uint8 * 8),
        ('MinorVersion',                ctypes.c_uint),
        ('MajorVersion',                ctypes.c_uint),
        ('BuildType',                   ctypes.c_char),
        ('CpuVendor',                   ctypes.c_char),
        ('CoresPerPhysicalProcessor',   ctypes.c_char),
        ('LogicalProcessorPerCore',     ctypes.c_char),
        ('PrcbPad04',                   ctypes.c_uint8 * 6),
        ('ParentNode',                  pointer_type),            # _KNODE
        ('_padding0',                   ctypes.c_uint8 * 0x7DC0)    # 0x7E80 (request mailbox) - 0xC0 (parent node)
    )

class KPCR(struct.BaseStruct):
    '''
    Defintion for 64-bit KPCR structure.

    Windows 10 RS4
    nt!_KPCR
        +0x000 NtTib            : _NT_TIB
        +0x000 GdtBase          : Ptr64 _KGDTENTRY64
        +0x008 TssBase          : Ptr64 _KTSS64
        +0x010 UserRsp          : Uint8B
        +0x018 Self             : Ptr64 _KPCR
        +0x020 CurrentPrcb      : Ptr64 _KPRCB
        +0x028 LockArray        : Ptr64 _KSPIN_LOCK_QUEUE
        +0x030 Used_Self        : Ptr64 Void
        +0x038 IdtBase          : Ptr64 _KIDTENTRY64
        +0x040 Unused           : [2] Uint8B
        +0x050 Irql             : UChar
        +0x051 SecondLevelCacheAssociativity : UChar
        +0x052 ObsoleteNumber   : UChar
        +0x053 Fill0            : UChar
        +0x054 Unused0          : [3] Uint4B
        +0x060 MajorVersion     : Uint2B
        +0x062 MinorVersion     : Uint2B
        +0x064 StallScaleFactor : Uint4B
        +0x068 Unused1          : [3] Ptr64 Void
        +0x080 KernelReserved   : [15] Uint4B
        +0x0bc SecondLevelCacheSize : Uint4B
        +0x0c0 HalReserved      : [16] Uint4B
        +0x100 Unused2          : Uint4B
        +0x108 KdVersionBlock   : Ptr64 Void
        +0x110 Unused3          : Ptr64 Void
        +0x118 PcrAlign1        : [24] Uint4B
        +0x180 Prcb             : _KPRCB
    '''

    # Get 64-bit native_type
    native_type = struct.get_native_type(64)
    pointer_type = native_type

    _fields_ = (
        ('NtTib',                           NT_TIB),
        ('GdtBase',                         ctypes.c_void_p),       # _KGDTENTRY64
        ('TssBase',                         ctypes.c_void_p),       # _KTSS64
        ('UserRsp',                         ctypes.c_uint8),
        ('Self',                            pointer_type),          # _KPCR
        ('CurrentPrcb',                     pointer_type),          # _KPRCB
        ('LockArray',                       ctypes.c_void_p),       # _KSPIN_LOCK_QUEUE
        ('UsedSelf',                        ctypes.c_void_p),       
        ('IdtBase',                         ctypes.c_void_p),       # This is meant to be a KIDTENTRY64 pointer
        ('Unused',                          ctypes.c_ulong),        # [0x2]
        ('Irql',                            ctypes.c_void_p),       # This is meant to be a KIRQL structure
        ('SecondLevelCacheAssociativity',   ctypes.c_char),
        ('ObsoleteNumber',                  ctypes.c_char),
        ('Fill0',                           ctypes.c_char),
        ('Unused0',                         ctypes.c_ulong),        # [0x3]
        ('MajorVersion',                    ctypes.c_ushort),
        ('MinorVersion',                    ctypes.c_ushort),
        ('StallScaleFactor',                ctypes.c_ulong),
        ('Unused1',                         ctypes.c_void_p),       # [0x3]
        ('KernelReserved',                  ctypes.c_ulong),        # [0x0F]
        ('SecondLevelCacheSize',            ctypes.c_ulong),
        ('HalReserved',                     ctypes.c_ulong),        # [0x10]
        ('Unused2',                         ctypes.c_ulong),
        ('KdVersionBlock',                  ctypes.c_void_p),
        ('Unused3',                         ctypes.c_void_p),
        ('PcrAlign1',                       ctypes.c_ulong),        # [0x18]
        ('Prcb',                            pointer_type))          # _KPRCB


class KPROCESS(struct.BaseStruct):
    '''
    Defintion for KPROCESS 64

    Windows 10 RS4
    ntdll!_KPROCESS
        +0x000 Header           : _DISPATCHER_HEADER
        +0x018 ProfileListHead  : _LIST_ENTRY
        +0x028 DirectoryTableBase : Uint8B
        +0x030 ThreadListHead   : _LIST_ENTRY
        +0x040 ProcessLock      : Uint4B
        +0x044 ProcessTimerDelay : Uint4B
        +0x048 DeepFreezeStartTime : Uint8B
        +0x050 Affinity         : _KAFFINITY_EX
        +0x0f8 ReadyListHead    : _LIST_ENTRY
        +0x108 SwapListEntry    : _SINGLE_LIST_ENTRY
        +0x110 ActiveProcessors : _KAFFINITY_EX
        +0x1b8 AutoAlignment    : Pos 0, 1 Bit
        +0x1b8 DisableBoost     : Pos 1, 1 Bit
        +0x1b8 DisableQuantum   : Pos 2, 1 Bit
        +0x1b8 DeepFreeze       : Pos 3, 1 Bit
        +0x1b8 TimerVirtualization : Pos 4, 1 Bit
        +0x1b8 CheckStackExtents : Pos 5, 1 Bit
        +0x1b8 CacheIsolationEnabled : Pos 6, 1 Bit
        +0x1b8 PpmPolicy        : Pos 7, 3 Bits
        +0x1b8 ActiveGroupsMask : Pos 10, 20 Bits
        +0x1b8 VaSpaceDeleted   : Pos 30, 1 Bit
        +0x1b8 ReservedFlags    : Pos 31, 1 Bit
        +0x1b8 ProcessFlags     : Int4B
        +0x1bc BasePriority     : Char
        +0x1bd QuantumReset     : Char
        +0x1be Visited          : Char
        +0x1bf Flags            : _KEXECUTE_OPTIONS
        +0x1c0 ThreadSeed       : [20] Uint4B
        +0x210 IdealNode        : [20] Uint2B
        +0x238 IdealGlobalNode  : Uint2B
        +0x23a Spare1           : Uint2B
        +0x23c StackCount       : _KSTACK_COUNT
        +0x240 ProcessListEntry : _LIST_ENTRY
        +0x250 CycleTime        : Uint8B
        +0x258 ContextSwitches  : Uint8B
        +0x260 SchedulingGroup  : Ptr64 _KSCHEDULING_GROUP
        +0x268 FreezeCount      : Uint4B
        +0x26c KernelTime       : Uint4B
        +0x270 UserTime         : Uint4B
        +0x274 ReadyTime        : Uint4B
        +0x278 UserDirectoryTableBase : Uint8B
        +0x280 AddressPolicy    : UChar
        +0x281 Spare2           : [71] UChar
        +0x2c8 InstrumentationCallback : Ptr64 Void
        +0x2d0 SecureState      : <unnamed-tag>
    '''
    _fields_ = (
        ('Header',              ctypes.c_void_p),
        ('ProfileListHead',     ctypes.c_void_p),
        ('DirectoryTableBase',  ctypes.c_uint8),
        ('ThreadListHead',      ctypes.c_void_p),
        ('ProcessLock',         ctypes.c_uint),
        ('ProcessTimerDelay',   ctypes.c_uint),
        ('DeepFreezeStartTime', ctypes.c_uint8),
        ('Affinity',            ctypes.c_void_p),
        ('ReadyListHead',       ctypes.c_void_p),
        ('SwapListEntry',       ctypes.c_void_p),
        ('ActiveProcessors',    ctypes.c_void_p),
        ('AutoAlignment',       ctypes.c_int, 1),
        ('DisableBoost',        ctypes.c_int, 1),
        ('DisableQuantum',      ctypes.c_int, 1),
        ('DeepFreeze',          ctypes.c_int, 1),
        ('TimerVirtualization', ctypes.c_int, 1),
        ('CheckStackExtentns',  ctypes.c_int, 1),
        ('CacheIsolationEnabled', ctypes.c_int, 1),
        ('PpmPolicy',           ctypes.c_int, 3),
        ('ActiveGroupsMask',    ctypes.c_int, 20),
        ('VaSpaceDeleted',      ctypes.c_int, 1),
        ('ReservedFlags',       ctypes.c_int, 1),
        ('ProcessFlags',        ctypes.c_int),
        ('BasePriority',        ctypes.c_char),
        ('QuantumReset',        ctypes.c_char),
        ('Visited',             ctypes.c_char),
        ('Flags',               ctypes.c_void_p),
        ('ThreadSeed',          ctypes.c_uint * 20),
        ('IdealNode',           ctypes.c_uint * 20),
        ('IdealGlobalNode',     ctypes.c_uint),
        ('Spare1',              ctypes.c_uint),
        ('StackCount',          ctypes.c_void_p),
        ('ProcessListEntry',    ctypes.c_void_p),
        ('CycleTime',           ctypes.c_uint8),
        ('ContextSwitches',     ctypes.c_uint8),
        ('SchedulingGroup',     ctypes.c_void_p),
        ('FreezeCount',         ctypes.c_uint),
        ('KernelTime',          ctypes.c_uint),
        ('UserTime',            ctypes.c_uint),
        ('ReadyTime',           ctypes.c_uint),
        ('UserDirectoryTableBase', ctypes.c_uint8),
        ('AddressPolicy',       ctypes.c_char),
        ('Spare2',              ctypes.c_char * 71),
        ('InstrumentationCallback', ctypes.c_void_p),
        ('SecureState',         ctypes.c_void_p)
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
# class KAPC_STATE64(ctypes.Structure):
#     _fields_ = (
#         ('ApcListHead', LIST_ENTRY64 * 2),
#         ('Process', POINTER64),
#         ('KernelApcInProgress', ctypes.c_uint8),
#         ('KernelApcPending', ctypes.c_uint8),
#         ('UserApcPending', ctypes.c_uint8),
#     )
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
            SubAuthority = subauths
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


class Point(struct.BaseStruct):
    _fields_ = (
        ('x', ctypes.c_int32),
        ('y', ctypes.c_int32)
    )


# https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/basic.htm
def make_system_basic_info(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    pointer_type = native_type

    class SYSTEM_BASIC_INFORMATION(Struct):
        _fields_ = (
            ('Reserved',                     ctypes.c_uint32),
            ('TimerResolution',              ctypes.c_uint32),
            ('PageSize',                     ctypes.c_uint32),
            ('NumberOfPhysicalPages',        ctypes.c_uint32),
            ('LowestPhysicalPageNumber',     ctypes.c_uint32),
            ('HighestPhysicalPageNumber',    ctypes.c_uint32),
            ('AllocationGranularity',        ctypes.c_uint32),
            ('MinimumUserModeAddress',       pointer_type),
            ('MaximumUserModeAddress',       pointer_type),
            ('ActiveProcessorsAffinityMask', pointer_type),
            ('NumberOfProcessors',           ctypes.c_uint8)
        )

    return SYSTEM_BASIC_INFORMATION


# https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-hostent
def make_hostent(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    pointer_type = native_type

    class HOSTENT(Struct):
        _fields_ = (
            ('h_name',      pointer_type),
            ('h_aliases',   pointer_type),
            ('h_addrtype',  ctypes.c_int16),
            ('h_length',    ctypes.c_int16),
            ('h_addr_list', pointer_type),
        )

    return HOSTENT


# https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
def make_sockaddr_in():

    # https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
    class in_addr(ctypes.BigEndianStructure):
        _fields_ = (
            ('s_b1', ctypes.c_uint8),
            ('s_b2', ctypes.c_uint8),
            ('s_b3', ctypes.c_uint8),
            ('s_b4', ctypes.c_uint8)
        )

    class sockaddr_in(ctypes.BigEndianStructure):
        _fields_ = (
            ('sin_family', ctypes.c_int16),
            ('sin_port',   ctypes.c_uint16),
            ('sin_addr',   in_addr),
            ('sin_zero',   ctypes.c_byte * 8)
        )

    return sockaddr_in

# https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
def make_sockaddr_in6():

    # https://docs.microsoft.com/en-us/windows/win32/api/in6addr/ns-in6addr-in6_addr
    class in6_addr(ctypes.BigEndianStructure):
        _fields_ = (
            ('Byte', ctypes.c_uint8 * 16)
        )

    class sockaddr_in6(ctypes.BigEndianStructure):
        _fields_ = (
            ('sin6_family',   ctypes.c_int16),
            ('sin6_port',     ctypes.c_uint16),
            ('sin6_flowinfo', ctypes.c_uint32),
            ('sin6_addr',     in6_addr),
            ('sin6_scope_id', ctypes.c_uint32)
        )

    return sockaddr_in6


# https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
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
        _anonymous_ = ('_anon_0',)

        _fields_ = (
            ('dwOemId', ctypes.c_uint32),
            ('_anon_0', DUMMYSTRUCTNAME)
        )

    assert ctypes.sizeof(DUMMYUNIONNAME) == 4

    class SYSTEM_INFO(Struct):
        _anonymous_ = ('_anon_1',)

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


# https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
def make_startup_info(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)

    pointer_type = native_type

    class STARTUPINFO(Struct):
        _fields_ = (
            ('cb',              ctypes.c_uint32),
            ('lpReserved',      pointer_type),
            ('lpDesktop',       pointer_type),
            ('lpTitle',         pointer_type),
            ('dwX',             ctypes.c_uint32),
            ('dwY',             ctypes.c_uint32),
            ('dwXSize',         ctypes.c_uint32),
            ('dwYSize',         ctypes.c_uint32),
            ('dwXCountChars',   ctypes.c_uint32),
            ('dwYCountChars',   ctypes.c_uint32),
            ('dwFillAttribute', ctypes.c_uint32),
            ('dwFlags',         ctypes.c_uint32),
            ('wShowWindow',     ctypes.c_uint16),
            ('cbReserved2',     ctypes.c_uint16),
            ('lpReserved2',     pointer_type),
            ('hStdInput',       pointer_type),
            ('hStdOutput',      pointer_type),
            ('hStdError',       pointer_type)
        )

    return STARTUPINFO


# https://docs.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfoa
def make_shellex_info(archbits: int):
    native_type = struct.get_native_type(archbits)
    Struct = struct.get_aligned_struct(archbits)
    Union = struct.get_aligned_union(archbits)

    pointer_type = native_type

    class DUMMYUNIONNAME(Union):
        _fields_ = (
            ('hIcon',    pointer_type),
            ('hMonitor', pointer_type)
        )

    class SHELLEXECUTEINFO(Struct):
        _anonymous_ = ('_anon_0',)

        _fields_ = (
            ('cbSize',       ctypes.c_uint32),
            ('fMask',        ctypes.c_uint32),
            ('hwnd',         pointer_type),
            ('lpVerb',       pointer_type),
            ('lpFile',       pointer_type),
            ('lpParameters', pointer_type),
            ('lpDirectory',  pointer_type),
            ('nShow',        ctypes.c_int32),
            ('hInstApp',     pointer_type),
            ('lpIDList',     pointer_type),
            ('lpClass',      pointer_type),
            ('hkeyClass',    pointer_type),
            ('dwHotKey',     ctypes.c_uint32),
            ('_anon_0',      DUMMYUNIONNAME),
            ('hProcess',     pointer_type)
        )

    return SHELLEXECUTEINFO


# https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/obquery/type.htm
@lru_cache(maxsize=2)
def make_object_type_info(archbits: int):
    Struct = struct.get_aligned_struct(archbits)

    UniStr = make_unicode_string(archbits)

    # this is only a pratial definition of the structure.
    # for some reason, the last two fields are swapped in al-khaser
    class OBJECT_TYPE_INFORMATION(Struct):
        _fields_ = (
            ('TypeName',             UniStr),
            ('TotalNumberOfObjects', ctypes.c_uint32),
            ('TotalNumberOfHandles', ctypes.c_uint32)
        )

    return OBJECT_TYPE_INFORMATION


def make_object_all_types_info(archbits: int, nobjs: int):
    Struct = struct.get_aligned_struct(archbits)

    ObjTypeInfo = make_object_type_info(archbits)

    class OBJECT_ALL_TYPES_INFORMATION(Struct):
        _fields_ = (
            ('NumberOfObjectTypes',   ctypes.c_uint32),
            ('ObjectTypeInformation', ObjTypeInfo * nobjs)
        )

    return OBJECT_ALL_TYPES_INFORMATION


# https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
def make_win32_find_data(archbits: int, *, wide: bool):
    Struct = struct.get_aligned_struct(archbits)

    char_type = (ctypes.c_wchar if wide else ctypes.c_char)

    class WIN32_FIND_DATA(Struct):
        _fields_ = (
            ('dwFileAttributes',   ctypes.c_uint32),
            ('ftCreationTime',     FILETIME),
            ('ftLastAccessTime',   FILETIME),
            ('ftLastWriteTime',    FILETIME),
            ('nFileSizeHigh',      ctypes.c_uint32),
            ('nFileSizeLow',       ctypes.c_uint32),
            ('dwReserved0',        ctypes.c_uint32),
            ('dwReserved1',        ctypes.c_uint32),
            ('cFileName',          char_type * MAX_PATH),
            ('cAlternateFileName', char_type * 14),
            ('dwFileType',         ctypes.c_uint32),
            ('dwCreatorType',      ctypes.c_uint32),
            ('wFinderFlags',       ctypes.c_uint16)
        )

    return WIN32_FIND_DATA

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, struct

from enum import IntEnum

from unicorn.x86_const import *


from qiling.const import *
from qiling.os.windows.handle import *
from qiling.exception import *
from .wdk_const import *


class POINTER32(ctypes.Structure):
    _fields_ = [('value', ctypes.c_uint32)]


class POINTER64(ctypes.Structure):
    _fields_ = [('value', ctypes.c_uint64)]


class TEB:
    def __init__(self,
                 ql,
                 base=0,
                 exception_list=0,
                 stack_base=0,
                 stack_limit=0,
                 sub_system_tib=0,
                 fiber_data=0,
                 arbitrary_user_pointer=0,
                 Self=0,
                 environment_pointer=0,
                 client_id_unique_process=0,
                 client_id_unique_thread=0,
                 rpc_handle=0,
                 tls_storage=0,
                 peb_address=0,
                 last_error_value=0,
                 last_status_value=0,
                 count_owned_locks=0,
                 hard_error_mode=0):
        self.ql = ql
        self.base = base
        self.ExceptionList = exception_list
        self.StackBase = stack_base
        self.StackLimit = stack_limit
        self.SubSystemTib = sub_system_tib
        self.FiberData = fiber_data
        self.ArbitraryUserPointer = arbitrary_user_pointer
        self.Self = Self
        self.EnvironmentPointer = environment_pointer
        self.ClientIdUniqueProcess = client_id_unique_process
        self.ClientIdUniqueThread = client_id_unique_thread
        self.RpcHandle = rpc_handle
        self.Tls_Storage = tls_storage
        self.PEB_Address = peb_address
        self.LastErrorValue = last_error_value
        self.LastStatusValue = last_status_value
        self.Count_Owned_Locks = count_owned_locks
        self.HardErrorMode = hard_error_mode

    def bytes(self):
        s = b''
        s += self.ql.pack(self.ExceptionList)  # 0x00
        s += self.ql.pack(self.StackBase)  # 0x04
        s += self.ql.pack(self.StackLimit)  # 0x08
        s += self.ql.pack(self.SubSystemTib)  # 0x0c
        s += self.ql.pack(self.FiberData)  # 0x10
        s += self.ql.pack(self.ArbitraryUserPointer)  # 0x14
        s += self.ql.pack(self.Self)  # 0x18
        s += self.ql.pack(self.EnvironmentPointer)  # 0x1c
        s += self.ql.pack(self.ClientIdUniqueProcess)  # 0x20
        s += self.ql.pack(self.ClientIdUniqueThread)  # 0x24
        s += self.ql.pack(self.RpcHandle)  # 0x28
        s += self.ql.pack(self.Tls_Storage)  # 0x2c
        s += self.ql.pack(self.PEB_Address)  # 0x30
        s += self.ql.pack(self.LastErrorValue)  # 0x34
        s += self.ql.pack(self.LastStatusValue)  # 0x38
        s += self.ql.pack(self.Count_Owned_Locks)  # 0x3c
        s += self.ql.pack(self.HardErrorMode)  # 0x40
        return s


# https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm


class PEB:
    def __init__(self,
                 ql,
                 base=0,
                 flag=0,
                 mutant=0,
                 image_base_address=0,
                 ldr_address=0,
                 process_parameters=0,
                 sub_system_data=0,
                 process_heap=0,
                 fast_peb_lock=0,
                 alt_thunk_s_list_ptr=0,
                 ifeo_key=0,
                 number_processors=0):
        self.ql = ql
        self.base = base
        self.flag = flag
        self.ImageBaseAddress = image_base_address
        self.Mutant = mutant
        self.LdrAddress = ldr_address
        self.ProcessParameters = process_parameters
        self.SubSystemData = sub_system_data
        self.ProcessHeap = process_heap
        self.FastPebLock = fast_peb_lock
        self.AtlThunkSListPtr = alt_thunk_s_list_ptr
        self.IFEOKey = ifeo_key
        self.numberOfProcessors = number_processors
        if self.ql.archtype == 32:
            self.size = 0x0468
        else:
            self.size = 0x07B0

    def write(self, addr):
        s = b''
        s += self.ql.pack(self.flag)  # 0x0 / 0x0
        s += self.ql.pack(self.Mutant)  # 0x4 / 0x8
        s += self.ql.pack(self.ImageBaseAddress)  # 0x8 / 0x10
        s += self.ql.pack(self.LdrAddress)  # 0xc / 0x18
        s += self.ql.pack(self.ProcessParameters)  # 0x10 / 0x20
        s += self.ql.pack(self.SubSystemData)  # 0x14 / 0x28
        s += self.ql.pack(self.ProcessHeap)  # 0x18 / 0x30
        s += self.ql.pack(self.FastPebLock)  # 0x1c / 0x38
        s += self.ql.pack(self.AtlThunkSListPtr)  # 0x20 / 0x40
        s += self.ql.pack(self.IFEOKey)  # 0x24 / 0x48
        self.ql.mem.write(addr, s)
        # FIXME: understand how each attribute of the PEB works before adding it
        self.ql.mem.write(addr + 0x64, self.ql.pack(self.numberOfProcessors))


class LDR_DATA:
    def __init__(self,
                 ql,
                 base=0,
                 Length=0,
                 Initialized=0,
                 SsHandle=0,
                 InLoadOrderModuleList={
                     'Flink': 0,
                     'Blink': 0
                 },
                 InMemoryOrderModuleList={
                     'Flink': 0,
                     'Blink': 0
                 },
                 InInitializationOrderModuleList={
                     'Flink': 0,
                     'Blink': 0
                 },
                 EntryInProgress=0,
                 ShutdownInProgress=0,
                 ShutdownThreadId=0):
        self.ql = ql
        self.base = base
        self.Length = Length
        self.Initialized = Initialized
        self.SsHandle = SsHandle
        self.InLoadOrderModuleList = InLoadOrderModuleList
        self.InMemoryOrderModuleList = InMemoryOrderModuleList
        self.InInitializationOrderModuleList = InInitializationOrderModuleList
        self.EntryInProgress = EntryInProgress
        self.ShutdownInProgress = ShutdownInProgress
        self.selfShutdownThreadId = ShutdownThreadId

    def bytes(self):
        s = b''
        s += self.ql.pack32(self.Length)  # 0x0
        s += self.ql.pack32(self.Initialized)  # 0x4
        s += self.ql.pack(self.SsHandle)  # 0x8
        s += self.ql.pack(self.InLoadOrderModuleList['Flink'])  # 0x0c
        s += self.ql.pack(self.InLoadOrderModuleList['Blink'])
        s += self.ql.pack(self.InMemoryOrderModuleList['Flink'])  # 0x14
        s += self.ql.pack(self.InMemoryOrderModuleList['Blink'])
        s += self.ql.pack(
            self.InInitializationOrderModuleList['Flink'])  # 0x1C
        s += self.ql.pack(self.InInitializationOrderModuleList['Blink'])
        s += self.ql.pack(self.EntryInProgress)
        s += self.ql.pack(self.ShutdownInProgress)
        s += self.ql.pack(self.selfShutdownThreadId)

        return s


class LDR_DATA_TABLE_ENTRY:
    def __init__(self,
                 ql,
                 base=0,
                 InLoadOrderLinks={
                     'Flink': 0,
                     'Blink': 0
                 },
                 InMemoryOrderLinks={
                     'Flink': 0,
                     'Blink': 0
                 },
                 InInitializationOrderLinks={
                     'Flink': 0,
                     'Blink': 0
                 },
                 DllBase=0,
                 EntryPoint=0,
                 SizeOfImage=0,
                 FullDllName='',
                 BaseDllName='',
                 Flags=0,
                 LoadCount=0,
                 TlsIndex=0,
                 HashLinks=0,
                 SectionPointer=0,
                 CheckSum=0,
                 TimeDateStamp=0,
                 LoadedImports=0,
                 EntryPointActivationContext=0,
                 PatchInformation=0,
                 ForwarderLinks=0,
                 ServiceTagLinks=0,
                 StaticLinks=0,
                 ContextInformation=0,
                 OriginalBase=0,
                 LoadTime=0):
        self.ql = ql
        self.base = base
        self.InLoadOrderLinks = InLoadOrderLinks
        self.InMemoryOrderLinks = InMemoryOrderLinks
        self.InInitializationOrderLinks = InInitializationOrderLinks
        self.DllBase = DllBase
        self.EntryPoint = EntryPoint
        self.SizeOfImage = SizeOfImage

        FullDllName = FullDllName.encode("utf-16le")
        self.FullDllName = {}
        self.FullDllName['Length'] = len(FullDllName)
        self.FullDllName['MaximumLength'] = len(FullDllName) + 2
        self.FullDllName['BufferPtr'] = ql.heap.alloc(
            self.FullDllName['MaximumLength'])
        ql.mem.write(self.FullDllName['BufferPtr'], FullDllName + b"\x00\x00")

        BaseDllName = BaseDllName.encode("utf-16le")
        self.BaseDllName = {}
        self.BaseDllName['Length'] = len(BaseDllName)
        self.BaseDllName['MaximumLength'] = len(BaseDllName) + 2
        self.BaseDllName['BufferPtr'] = ql.heap.alloc(
            self.BaseDllName['MaximumLength'])
        ql.mem.write(self.BaseDllName['BufferPtr'], BaseDllName + b"\x00\x00")

        self.Flags = Flags
        self.LoadCount = LoadCount
        self.TlsIndex = TlsIndex
        self.HashLinks = HashLinks
        self.SectionPointer = SectionPointer
        self.CheckSum = CheckSum
        self.TimeDateStamp = TimeDateStamp
        self.LoadedImports = LoadedImports
        self.EntryPointActivationContext = EntryPointActivationContext
        self.PatchInformation = PatchInformation
        self.ForwarderLinks = ForwarderLinks
        self.ServiceTagLinks = ServiceTagLinks
        self.StaticLinks = StaticLinks
        self.ContextInformation = ContextInformation
        self.OriginalBase = OriginalBase
        self.LoadTime = LoadTime

    def attrs(self):
        return ", ".join("{}={}".format(k, getattr(self, k))
                         for k in self.__dict__.keys())

    def print(self):
        return "[{}:{}]".format(self.__class__.__name__, self.attrs())

    def bytes(self):
        s = b''
        s += self.ql.pack(self.InLoadOrderLinks['Flink'])  # 0x0
        s += self.ql.pack(self.InLoadOrderLinks['Blink'])
        s += self.ql.pack(self.InMemoryOrderLinks['Flink'])  # 0x8
        s += self.ql.pack(self.InMemoryOrderLinks['Blink'])
        s += self.ql.pack(self.InInitializationOrderLinks['Flink'])  # 0x10
        s += self.ql.pack(self.InInitializationOrderLinks['Blink'])
        s += self.ql.pack(self.DllBase)  # 0x18
        s += self.ql.pack(self.EntryPoint)  # 0x1c
        s += self.ql.pack(self.SizeOfImage)  # 0x20
        s += self.ql.pack16(self.FullDllName['Length'])  # 0x24
        s += self.ql.pack16(self.FullDllName['MaximumLength'])  # 0x26

        if self.ql.arch == QL_ARCH.X8664:
            s += self.ql.pack32(0)

        s += self.ql.pack(self.FullDllName['BufferPtr'])  # 0x28
        s += self.ql.pack16(self.BaseDllName['Length'])
        s += self.ql.pack16(self.BaseDllName['MaximumLength'])

        if self.ql.arch == QL_ARCH.X8664:
            s += self.ql.pack32(0)

        s += self.ql.pack(self.BaseDllName['BufferPtr'])
        s += self.ql.pack(self.Flags)
        s += self.ql.pack(self.LoadCount)
        s += self.ql.pack(self.TlsIndex)
        s += self.ql.pack(self.HashLinks)
        s += self.ql.pack(self.SectionPointer)
        s += self.ql.pack(self.CheckSum)
        s += self.ql.pack(self.TimeDateStamp)
        s += self.ql.pack(self.LoadedImports)
        s += self.ql.pack(self.EntryPointActivationContext)
        s += self.ql.pack(self.PatchInformation)
        s += self.ql.pack(self.ForwarderLinks)
        s += self.ql.pack(self.ServiceTagLinks)
        s += self.ql.pack(self.StaticLinks)
        s += self.ql.pack(self.ContextInformation)
        s += self.ql.pack(self.OriginalBase)
        s += self.ql.pack(self.LoadTime)

        return s


'''
https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
'''


class UNICODE_STRING64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('Length', ctypes.c_uint16), ('MaximumLength', ctypes.c_int16),
                ('Buffer', ctypes.c_uint64))


class UNICODE_STRING32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (('Length', ctypes.c_uint16), ('MaximumLength', ctypes.c_int16),
                ('Buffer', ctypes.c_uint32))


'''
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object

typedef struct _DRIVER_OBJECT {
  CSHORT             Type;
  CSHORT             Size;
  PDEVICE_OBJECT     DeviceObject;
  ULONG              Flags;
  PVOID              DriverStart;
  ULONG              DriverSize;
  PVOID              DriverSection;
  PDRIVER_EXTENSION  DriverExtension;
  UNICODE_STRING     DriverName;
  PUNICODE_STRING    HardwareDatabase;
  PFAST_IO_DISPATCH  FastIoDispatch;
  PDRIVER_INITIALIZE DriverInit;
  PDRIVER_STARTIO    DriverStartIo;
  PDRIVER_UNLOAD     DriverUnload;
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
'''


class DRIVER_OBJECT64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("_Type", ctypes.c_uint16),
        ("_Size", ctypes.c_uint16),
        ("_DeviceObject", POINTER64),
        ("_Flags", ctypes.c_uint32),
        ("_DriverStart", POINTER64),
        ("_DriverSize", ctypes.c_uint32),
        ("_DriverSection", POINTER64),
        ("_DriverExtension", POINTER64),
        ("_DriverName", UNICODE_STRING64),
        ("_HardwareDatabase", POINTER64),
        ("_FastIoDispatch", POINTER64),
        ("_DriverInit", POINTER64),
        ("_DriverStartIo", POINTER64),
        ("_DriverUnload", POINTER64),
        ("_MajorFunction", ctypes.c_uint64 * (IRP_MJ_MAXIMUM_FUNCTION + 1)))

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    # get MajorFunction
    @property
    def MajorFunction(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return obj._MajorFunction

    @property
    def DeviceObject(self):
        # TODO: improve this code to avoid reading the whole object
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return obj._DeviceObject.value

    @DeviceObject.setter
    def DeviceObject(self, value):
        # TODO: improve this code to avoid reading/writing the whole object
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        obj._DeviceObject.value = value
        # update back to memory.
        self.ql.mem.write(self.base, bytes(obj))

    @property
    def DriverUnload(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return obj._DriverUnload.value


class DRIVER_OBJECT32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ("_Type", ctypes.c_uint16),
        ("_Size", ctypes.c_uint16),
        ("_DeviceObject", POINTER32),
        ("_Flags", ctypes.c_uint32),
        ("_DriverStart", POINTER32),
        ("_DriverSize", ctypes.c_uint32),
        ("_DriverSection", POINTER32),
        ("_DriverExtension", POINTER32),
        ("_DriverName", UNICODE_STRING32),
        ("_HardwareDatabase", POINTER32),
        ("_FastIoDispatch", POINTER32),
        ("_DriverInit", POINTER32),
        ("_DriverStartIo", POINTER32),
        ("_DriverUnload", POINTER32),
        ("_MajorFunction", ctypes.c_uint32 * (IRP_MJ_MAXIMUM_FUNCTION + 1)))

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    # get MajorFunction
    @property
    def MajorFunction(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return obj._MajorFunction

    @property
    def DeviceObject(self):
        # TODO: improve this code to avoid reading the whole object
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return obj._DeviceObject.value

    @DeviceObject.setter
    def DeviceObject(self, value):
        # TODO: improve this code to avoid reading/writing the whole object
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        obj._DeviceObject.value = value
        # update back to memory.
        self.ql.mem.write(self.base, bytes(obj))

    @property
    def DriverUnload(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return obj._DriverUnload.value



class KSYSTEM_TIME(ctypes.Structure):
    _fields_ = (('LowPart', ctypes.c_uint32), ('High1Time', ctypes.c_int32),
                ('High2Time', ctypes.c_int32))


class LARGE_INTEGER_DUMMYSTRUCTNAME(ctypes.Structure):
    _fields_ = (
        ('LowPart', ctypes.c_uint32),
        ('HighPart', ctypes.c_int32),
    )


class LARGE_INTEGER(ctypes.Union):
    _fields_ = (
        ('u', LARGE_INTEGER_DUMMYSTRUCTNAME),
        ('QuadPart', ctypes.c_int64),
    )


class KUSER_SHARED_DATA(ctypes.Structure):
    _fields_ = (
        ('TickCountLowDeprecated', ctypes.c_uint32),
        ('TickCountMultiplier', ctypes.c_uint32),
        ('InterruptTime', KSYSTEM_TIME),
        ('SystemTime', KSYSTEM_TIME),
        ('TimeZoneBias', KSYSTEM_TIME),
        ('ImageNumberLow', ctypes.c_uint16),
        ('ImageNumberHigh', ctypes.c_uint16),
        ('NtSystemRoot', ctypes.c_uint16 * 260),
        ('MaxStackTraceDepth', ctypes.c_uint32),
        ('CryptoExponent', ctypes.c_uint32),
        ('TimeZoneId', ctypes.c_uint32),
        ('LargePageMinimum', ctypes.c_uint32),
        ('Reserved2', ctypes.c_uint32 * 7),
        ('NtProductType', ctypes.c_uint32),
        ('ProductTypeIsValid', ctypes.c_uint32),
        ('NtMajorVersion', ctypes.c_uint32),
        ('NtMinorVersion', ctypes.c_uint32),
        ('ProcessorFeatures', ctypes.c_uint8 * PROCESSOR_FEATURE_MAX),
        ('Reserved1', ctypes.c_uint32),
        ('Reserved3', ctypes.c_uint32),
        ('TimeSlip', ctypes.c_uint32),
        ('AlternativeArchitecture', ctypes.c_uint32),
        ('AltArchitecturePad', ctypes.c_uint32),
        ('SystemExpirationDate', LARGE_INTEGER),
        ('SuiteMask', ctypes.c_uint32),
        ('KdDebuggerEnabled', ctypes.c_uint8),
        ('NXSupportPolicy', ctypes.c_uint8),
        ('ActiveConsoleId', ctypes.c_uint32),
        ('DismountCount', ctypes.c_uint32),
        ('ComPlusPackage', ctypes.c_uint32),
        ('LastSystemRITEventTickCount', ctypes.c_uint32),
        ('NumberOfPhysicalPages', ctypes.c_uint32),
        ('SafeBootMode', ctypes.c_uint8),
        ('TscQpcData', ctypes.c_uint8),
        ('TscQpcFlags', ctypes.c_uint8),
        ('TscQpcPad', ctypes.c_uint8 * 3),
        ('SharedDataFlags', ctypes.c_uint8),
        ('DataFlagsPad', ctypes.c_uint8 * 3),
        ('TestRetInstruction', ctypes.c_uint8),
        ('_padding0', ctypes.c_uint8 * 0x2F8))


class LIST_ENTRY32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('Flink', ctypes.c_uint32),
        ('Blink', ctypes.c_uint32),
    )


class KDEVICE_QUEUE_ENTRY32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('DeviceListEntry', LIST_ENTRY32),
        ('SortKey', ctypes.c_uint32),
        ('Inserted', ctypes.c_uint8)
        )


class WAIT_ENTRY32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('DmaWaitEntry', LIST_ENTRY32),
        ('NumberOfChannels', ctypes.c_uint32),
        ('DmaContext', ctypes.c_uint32)
        )


class WAIT_QUEUE_UNION32(ctypes.Union):
    _pack_ = 4
    _fields_ = ("WaitQueueEntry", KDEVICE_QUEUE_ENTRY32), ("Dma", WAIT_ENTRY32)


class WAIT_CONTEXT_BLOCK32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (('WaitQueue', WAIT_QUEUE_UNION32),
                ('DeviceRoutine', POINTER32),
                ('DeviceContext', POINTER32),
                ('NumberOfMapRegisters', ctypes.c_uint32),
                ('DeviceObject', POINTER32),
                ('CurrentIrp', POINTER32),
                ('BufferChainingDpc', POINTER32))


class KDEVICE_QUEUE32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (('Type', ctypes.c_int16), ('Size', ctypes.c_int16),
                ('DeviceListHead', LIST_ENTRY32), ('Lock', ctypes.c_uint32),
                ('Busy', ctypes.c_uint8))


class SINGLE_LIST_ENTRY32(ctypes.Structure):
    _fields_ = [(('Next', ctypes.c_uint32))]


# https://github.com/ntdiff/headers/blob/master/Win10_1507_TS1/x64/System32/hal.dll/Standalone/_KDPC.h
class KDPC32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('Type', ctypes.c_uint8),
        ('Importance', ctypes.c_uint8),
        ('Number', ctypes.c_uint16),
        ('DpcListEntry', LIST_ENTRY32),
        ('DeferredRoutine', POINTER32),
        ('DeferredContext', POINTER32),
        ('SystemArgument1', POINTER32),
        ('SystemArgument2', POINTER32),
        ('DpcData', POINTER32),
    )


class DISPATCHER_HEADER32(ctypes.Structure):
    _fields_ = (
        ('Lock', ctypes.c_int32),
        ('SignalState', ctypes.c_int32),
        ('WaitListHead', LIST_ENTRY32),
    )


# https://docs.microsoft.com/vi-vn/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_object
class DEVICE_OBJECT32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('Type', ctypes.c_int16),
        ('Size', ctypes.c_uint16),
        ('ReferenceCount', ctypes.c_int32),
        ('DriverObject', POINTER32),
        ('NextDevice', POINTER32),
        ('AttachedDevice', POINTER32),
        ('CurrentIrp', POINTER32),
        ('Timer', POINTER32),
        ('Flags', ctypes.c_uint32),
        ('Characteristics', ctypes.c_uint32),
        ('Vpb', POINTER32),
        ('DeviceExtension', ctypes.c_uint32),
        ('DeviceType', ctypes.c_uint32),
        ('StackSize', ctypes.c_int16),
        ('Queue', WAIT_CONTEXT_BLOCK32),
        ('AlignmentRequirement', ctypes.c_uint32),
        ('DeviceQueue', KDEVICE_QUEUE32),
        ('Dpc', KDPC32),
        ('ActiveThreadCount', ctypes.c_uint32),
        ('SecurityDescriptor', POINTER32),
        ('DeviceLock', DISPATCHER_HEADER32),
        ('SectorSize', ctypes.c_uint16),
        ('Spare1', ctypes.c_uint16),
        ('DeviceObjectExtension', POINTER32),
        ('Reserved', POINTER32),
    )


## 64bit structures
class LIST_ENTRY64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Flink', ctypes.c_uint64),
        ('Blink', ctypes.c_uint64),
    )


class KDEVICE_QUEUE_ENTRY64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('DeviceListEntry', LIST_ENTRY64),
                ('SortKey', ctypes.c_uint32), ('Inserted', ctypes.c_uint8))


class WAIT_ENTRY64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('DmaWaitEntry', LIST_ENTRY64),
                ('NumberOfChannels', ctypes.c_uint32), ('DmaContext',
                                                        ctypes.c_uint32))


class WAIT_QUEUE_UNION64(ctypes.Union):
    _fields_ = ("WaitQueueEntry", KDEVICE_QUEUE_ENTRY64), ("Dma", WAIT_ENTRY64)


class WAIT_CONTEXT_BLOCK64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('WaitQueue', WAIT_QUEUE_UNION64),
                ('DeviceRoutine', POINTER64), ('DeviceContext', POINTER64),
                ('NumberOfMapRegisters', ctypes.c_uint32), ('DeviceObject',
                                                            POINTER64),
                ('CurrentIrp', POINTER64), ('BufferChainingDpc', POINTER64))


class KDEVICE_QUEUE64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('Type', ctypes.c_int16), ('Size', ctypes.c_int16),
                ('DeviceListHead', LIST_ENTRY64), ('Lock', ctypes.c_uint32),
                ('Busy', ctypes.c_uint8))


class SINGLE_LIST_ENTRY64(ctypes.Structure):
    _pack_ = 8
    _fields_ = [(('Next', ctypes.c_uint64))]


class KDPC64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Type', ctypes.c_uint8),
        ('Importance', ctypes.c_uint8),
        ('Number', ctypes.c_uint16),
        ('DpcListEntry', LIST_ENTRY64),
        ('DeferredRoutine', POINTER64),
        ('DeferredContext', POINTER64),
        ('SystemArgument1', POINTER64),
        ('SystemArgument2', POINTER64),
        ('DpcData', POINTER64),
    )


class DISPATCHER_HEADER64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Lock', ctypes.c_int32),
        ('SignalState', ctypes.c_int32),
        ('WaitListHead', LIST_ENTRY64),
    )


class DEVICE_OBJECT64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Type', ctypes.c_int16),
        ('Size', ctypes.c_uint16),
        ('ReferenceCount', ctypes.c_int32),
        ('DriverObject', POINTER64),
        ('NextDevice', POINTER64),
        ('AttachedDevice', POINTER64),
        ('CurrentIrp', POINTER64),
        ('Timer', POINTER64),
        ('Flags', ctypes.c_uint32),
        ('Characteristics', ctypes.c_uint32),
        ('Vpb', POINTER64),
        ('DeviceExtension', ctypes.c_uint64),
        ('DeviceType', ctypes.c_uint32),
        ('StackSize', ctypes.c_int16),
        ('Queue', WAIT_CONTEXT_BLOCK64),
        ('AlignmentRequirement', ctypes.c_uint32),
        ('DeviceQueue', KDEVICE_QUEUE64),
        ('Dpc', KDPC64),
        ('ActiveThreadCount', ctypes.c_uint32),
        ('SecurityDescriptor', POINTER64),
        ('DeviceLock', DISPATCHER_HEADER64),
        ('SectorSize', ctypes.c_uint16),
        ('Spare1', ctypes.c_uint16),
        ('DeviceObjectExtension', POINTER64),
        ('Reserved', POINTER64),
    )


# struct IO_STATUS_BLOCK {
#   union {
#     NTSTATUS Status;
#     PVOID    Pointer;
#   } DUMMYUNIONNAME;
#   ULONG_PTR Information;
# };


class IO_STATUS_BLOCK_DUMMY64(ctypes.Union):
    _pack_ = 8
    _fields_ = (
        ('Status', ctypes.c_int32),
        ('Pointer', POINTER64),
    )


class IO_STATUS_BLOCK64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('Status', IO_STATUS_BLOCK_DUMMY64), ('Information',
                                                      POINTER64))


class IO_STATUS_BLOCK_DUMMY32(ctypes.Union):
    _fields_ = (
        ('Status', ctypes.c_int32),
        ('Pointer', POINTER32),
    )


class IO_STATUS_BLOCK32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (('Status', IO_STATUS_BLOCK_DUMMY32), ('Information',
                                                      POINTER32))


# struct IO_STACK_LOCATION {
#     UCHAR                  MajorFunction;
#     UCHAR                  MinorFunction;
#     UCHAR                  Flags;
#     UCHAR                  Control;
#     union {
#         struct {
#             char  _padding1[4];
#             ULONG                   OutputBufferLength;
#             char  _padding2[4];
#             ULONG POINTER_ALIGNMENT InputBufferLength;
#             char  _padding3[4];
#             ULONG POINTER_ALIGNMENT FsControlCode;
#             char  _padding4[4];
#             PVOID                   Type3InputBuffer;
#         } FileSystemControl;
#         struct {
#             char  _padding5[4];
#             ULONG                   OutputBufferLength;
#             ULONG POINTER_ALIGNMENT InputBufferLength;  // 10
#             char  _padding7[4];
#             ULONG POINTER_ALIGNMENT IoControlCode;      // 18
#             char  _padding8[4];
#             PVOID                   Type3InputBuffer;   // 20
#         } DeviceIoControl;
#     } Parameters;
# };
class IO_STACK_LOCATION_FILESYSTEMCONTROL64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('OutputBufferLength', ctypes.c_uint32), ('_padding1',
                                                          ctypes.c_uint32),
                ('InputBufferLength', ctypes.c_uint32), ('_padding2',
                                                         ctypes.c_uint32),
                ('FsControlCode', ctypes.c_uint32), ('Type3InputBuffer',
                                                     POINTER64))


class IO_STACK_LOCATION_FILESYSTEMCONTROL32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('OutputBufferLength', ctypes.c_uint32),
        ('InputBufferLength', ctypes.c_uint32),
        ('FsControlCode', ctypes.c_uint32),
        ('Type3InputBuffer', POINTER32))


class IO_STACK_LOCATION_DEVICEIOCONTROL64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('OutputBufferLength', ctypes.c_uint32),
        ('_padding1', ctypes.c_uint32),
        ('InputBufferLength', ctypes.c_uint32),
        ('_padding2', ctypes.c_uint32),
        ('IoControlCode', ctypes.c_uint32),
        ('Type3InputBuffer', POINTER64))


class IO_STACK_LOCATION_DEVICEIOCONTROL32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('OutputBufferLength', ctypes.c_uint32),
        ('InputBufferLength', ctypes.c_uint32),
        ('IoControlCode', ctypes.c_uint32),
        ('Type3InputBuffer', POINTER32)
        )

class IO_STACK_LOCATION_WRITE64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Length', ctypes.c_uint32),
        ('_padding1', ctypes.c_uint32),
        ('Key', ctypes.c_uint32),
        ('Flags', ctypes.c_uint32),
        ('ByteOffset', LARGE_INTEGER)
    )

class IO_STACK_LOCATION_WRITE32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('Length', ctypes.c_uint32),
        ('Key', ctypes.c_uint32),
        ('Flags', ctypes.c_uint32),
        ('ByteOffset', LARGE_INTEGER)
    )

class IO_STACK_LOCATION_PARAM64(ctypes.Union):
    _pack_ = 8
    _fields_ = (('FileSystemControl', IO_STACK_LOCATION_FILESYSTEMCONTROL64),
                ('DeviceIoControl', IO_STACK_LOCATION_DEVICEIOCONTROL64),
                ('Write', IO_STACK_LOCATION_WRITE64))


class IO_STACK_LOCATION_PARAM32(ctypes.Union):
    _pack_ = 4
    _fields_ = (('FileSystemControl', IO_STACK_LOCATION_FILESYSTEMCONTROL32),
                ('DeviceIoControl', IO_STACK_LOCATION_DEVICEIOCONTROL32),
                ('Write', IO_STACK_LOCATION_WRITE32))


class IO_STACK_LOCATION64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('MajorFunction', ctypes.c_byte),
        ('MinorFunction', ctypes.c_byte),
        ('Flags', ctypes.c_byte),
        ('Control', ctypes.c_byte),
        ('_padding1', ctypes.c_byte * 0x4),
        ('Parameters', IO_STACK_LOCATION_PARAM64),
        ('DeviceObject', POINTER64),
        ('FileObject', POINTER64),
        ('CompletionRoutine', POINTER64),
        ('Context', POINTER64),
    )


class IO_STACK_LOCATION32(ctypes.Structure):
    _pack_ = 4
    _fields_ = (
        ('MajorFunction', ctypes.c_byte),
        ('MinorFunction', ctypes.c_byte),
        ('Flags', ctypes.c_byte),
        ('Control', ctypes.c_byte),
        ('Parameters', IO_STACK_LOCATION_PARAM32),
        ('DeviceObject', POINTER32),
        ('FileObject', POINTER32),
        ('CompletionRoutine', POINTER32),
        ('Context', POINTER32),
    )


# union {
#   struct _IRP     *MasterIrp;
#   __volatile LONG IrpCount;
#   PVOID           SystemBuffer;
# } AssociatedIrp;


class AssociatedIrp64(ctypes.Union):
    _fields_ = (
        ('MasterIrp', POINTER64),  # ('MasterIrp', ctypes.POINTER(IRP64)),
        ('IrpCount', ctypes.c_uint32),
        ('SystemBuffer', POINTER64))


class AssociatedIrp32(ctypes.Union):
    _fields_ = (
        ('MasterIrp', POINTER32),  # ('MasterIrp', ctypes.POINTER(IRP32)),
        ('IrpCount', ctypes.c_uint32),
        ('SystemBuffer', POINTER32))


# struct _IRP {
#     char                _padding1[0x30];
#     IO_STATUS_BLOCK     IoStatus;   // distance is 0x30??
#     char                _padding2[0x70 - 0x30 - sizeof(io_status_block)];
#     PVOID               UserBuffer; // distance is 0x70 from _IRP
#     char                _padding3[0xB8 - 0x70 - sizeof(PVOID)];
#     IO_STACK_LOCATION   *irpstack;
# };
class IRP64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Type', ctypes.c_uint16),
        ('Size', ctypes.c_uint16),
        ('MdlAddress', POINTER64),
        ('Flags', ctypes.c_uint32),
        ('AssociatedIrp', AssociatedIrp64),
        ('ThreadListEntry', LIST_ENTRY64),
        ('IoStatus', IO_STATUS_BLOCK64),
        ('_padding1', ctypes.c_char * 0x8),
        ('UserIosb', POINTER64),
        ('UserEvent', POINTER64),
        ('Overlay', ctypes.c_char * 0x10),
        ('CancelRoutine', POINTER64),
        ('UserBuffer', POINTER64),
        ('_padding1', ctypes.c_char * 0x40),
        ('irpstack', ctypes.POINTER(IO_STACK_LOCATION64)),
        ('_padding2', ctypes.c_char * 0x10),
    )


class IRP32(ctypes.Structure):
    _fields_ = (
        ('Type', ctypes.c_uint16),
        ('Size', ctypes.c_uint16),
        ('MdlAddress', POINTER32),
        ('Flags', ctypes.c_uint32),
        ('AssociatedIrp', AssociatedIrp32),
        ('ThreadListEntry', LIST_ENTRY32),
        ('IoStatus', IO_STATUS_BLOCK32),
        ('_padding1', ctypes.c_char * 0x8),
        ('UserIosb', POINTER32),  # 0x28
        ('UserEvent', POINTER32),
        ('Overlay', ctypes.c_char * 8),
        ('CancelRoutine', POINTER32),
        ('UserBuffer', POINTER32),
        ('_padding1', ctypes.c_char * 0x20),
        ('irpstack', ctypes.POINTER(IO_STACK_LOCATION32)),
        ('_padding2', ctypes.c_char * 8),
    )


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


class MDL64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('Next', POINTER64), ('Size', ctypes.c_uint16),
                ('MdlFlags', ctypes.c_uint16), ('Process', POINTER64),
                ('MappedSystemVa', POINTER64), ('StartVa', POINTER64),
                ('ByteCount', ctypes.c_uint32), ('ByteOffset',
                                                 ctypes.c_uint32))


class MDL32(ctypes.Structure):
    _fields_ = (('Next', POINTER32), ('Size', ctypes.c_uint16),
                ('MdlFlags', ctypes.c_uint16), ('Process', POINTER32),
                ('MappedSystemVa', POINTER32), ('StartVa', POINTER32),
                ('ByteCount', ctypes.c_uint32), ('ByteOffset',
                                                 ctypes.c_uint32))

#TODO: Repeated and might not be needed

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


class KAPC_STATE64(ctypes.Structure):
    _fields_ = (
        ('ApcListHead', LIST_ENTRY64 * 2),
        ('Process', POINTER64),
        ('KernelApcInProgress', ctypes.c_uint8),
        ('KernelApcPending', ctypes.c_uint8),
        ('UserApcPending', ctypes.c_uint8),
    )


class KAPC_STATE32(ctypes.Structure):
    _fields_ = (
        ('ApcListHead', LIST_ENTRY32 * 2),
        ('Process', POINTER32),
        ('KernelApcInProgress', ctypes.c_uint8),
        ('KernelApcPending', ctypes.c_uint8),
        ('UserApcPending', ctypes.c_uint8),
    )


class KTIMER64(ctypes.Structure):
    _fields_ = (
        ('Header', DISPATCHER_HEADER64),
        ('DueTime', LARGE_INTEGER),
        ('TimerListEntry', LIST_ENTRY64),
        ('Dpc', POINTER64),
        ('Period', ctypes.c_uint32),
    )


class KTIMER32(ctypes.Structure):
    _fields_ = (
        ('Header', DISPATCHER_HEADER32),
        ('DueTime', LARGE_INTEGER),
        ('TimerListEntry', LIST_ENTRY32),
        ('Dpc', POINTER32),
        ('Period', ctypes.c_uint32),
    )


class KWAIT_BLOCK64(ctypes.Structure):
    _fields_ = (
        ('WaitListEntry', LIST_ENTRY64),
        ('Thread', POINTER64),
        ('Object', POINTER64),
        ('NextWaitBlock', POINTER64),
        ('WaitKey', ctypes.c_uint16),
        ('WaitType', ctypes.c_uint8),
        ('BlockState', ctypes.c_uint8),
    )


class KWAIT_BLOCK32(ctypes.Structure):
    _fields_ = (
        ('WaitListEntry', LIST_ENTRY32),
        ('Thread', POINTER32),
        ('Object', POINTER32),
        ('NextWaitBlock', POINTER32),
        ('WaitKey', ctypes.c_uint16),
        ('WaitType', ctypes.c_uint8),
        ('BlockState', ctypes.c_uint8),
    )


class GROUP_AFFINITY64(ctypes.Structure):
    _fields_ = (('Mask', ctypes.c_uint64), ('Group', ctypes.c_uint16),
                ('Reserved', ctypes.c_uint16 * 3))


class GROUP_AFFINITY32(ctypes.Structure):
    _fields_ = (('Mask', ctypes.c_uint32), ('Group', ctypes.c_uint16),
                ('Reserved', ctypes.c_uint16 * 3))


class KAPC64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Type', ctypes.c_uint8),
        ('SpareByte0', ctypes.c_uint8),
        ('Size', ctypes.c_uint8),
        ('SpareByte1', ctypes.c_uint8),
        ('SpareLong0', ctypes.c_uint32),
        ('Thread', POINTER64),
        ('ApcListEntry', LIST_ENTRY64),
        ('KernelRoutine', POINTER64),
        ('RundownRoutine', POINTER64),
        ('NormalRoutine', POINTER64),
        ('NormalContext', POINTER64),
        ('SystemArgument1', POINTER64),
        ('SystemArgument2', POINTER64),
        ('ApcStateIndex', ctypes.c_uint8),
        ('ApcMode', ctypes.c_uint8),
        ('Inserted', ctypes.c_uint8),
    )


class KAPC32(ctypes.Structure):
    _fields_ = ()


class KSEMAPHORE64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (("Header", DISPATCHER_HEADER64), ("Limit", ctypes.c_int32))


class COUNTER_READING64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("Type", ctypes.c_uint32),
        ("Index", ctypes.c_uint32),
        ("Start", ctypes.c_uint64),
        ("Total", ctypes.c_uint64),
    )


class KTHREAD_COUNTERS64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("WaitReasonBitMap", ctypes.c_int64),
        ("UserData", POINTER64),
        ("Flags", ctypes.c_uint32),
        ("ContextSwitches", ctypes.c_uint32),
        ("CycleTimeBias", ctypes.c_uint64),
        ("HardwareCounters", ctypes.c_uint64),
        ("HwCounter", COUNTER_READING64 * 16),
    )


class KTHREAD64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Header', DISPATCHER_HEADER64),
        ('CycleTime', ctypes.c_uint64),
        ('QuantumTarget', ctypes.c_uint64),
        ('InitialStack', POINTER64),
        ('StackLimit', POINTER64),
        ('KernelStack', POINTER64),
        ('ThreadLock', ctypes.c_uint64),
        ('WaitRegister', ctypes.c_uint8),  # _KWAIT_STATUS_REGISTER
        ('Running', ctypes.c_uint8),
        ('Alerted', ctypes.c_uint8 * 2),
        ('MiscFlags', ctypes.c_uint32),
        ('ApcState', KAPC_STATE64),
        ('DeferredProcessor', ctypes.c_uint32),
        ('ApcQueueLock', ctypes.c_uint64),
        ('WaitStatus', ctypes.c_int64),
        ('WaitBlockList', POINTER64),
        ('WaitListEntry', LIST_ENTRY64),
        ('Queue', POINTER64),
        ('Teb', POINTER64),
        ('Timer', KTIMER64),
        ('ThreadFlags', ctypes.c_int32),
        ('Spare0', ctypes.c_uint32),
        ('WaitBlock', KWAIT_BLOCK64 * 4),
        ('QueueListEntry', LIST_ENTRY64),
        ('TrapFrame', POINTER64),
        ('FirstArgument', POINTER64),
        ('CallbackStack', POINTER64),
        ('ApcStateIndex', ctypes.c_uint8),
        ('BasePriority', ctypes.c_char),
        ('PriorityDecrement', ctypes.c_char),
        ('Preempted', ctypes.c_uint8),
        ('AdjustReason', ctypes.c_uint8),
        ('AdjustIncrement', ctypes.c_char),
        ('PreviousMode', ctypes.c_char),
        ('Saturation', ctypes.c_char),
        ('SystemCallNumber', ctypes.c_uint32),
        ('FreezeCount', ctypes.c_uint32),
        ('UserAffinity', GROUP_AFFINITY64),
        ('Process', POINTER64),
        ('Affinity', GROUP_AFFINITY64),
        ('IdealProcessor', ctypes.c_uint32),
        ('UserIdealProcessor', ctypes.c_uint32),
        ('ApcStatePointer', POINTER64 * 2),
        ('SavedApcState', KAPC_STATE64),
        ('Win32Thread', POINTER64),
        ('StackBase', POINTER64),
        ('SuspendApc', KAPC64),
        ('SuspendSemaphore', KSEMAPHORE64),
        ('ThreadListEntry', LIST_ENTRY64),
        ('MutantListHead', LIST_ENTRY64),
        ('SListFaultAddress', POINTER64),
        ('ReadOperationCount', ctypes.c_int64),
        ('WriteOperationCount', ctypes.c_int64),
        ('OtherOperationCount', ctypes.c_int64),
        ('ReadTransferCount', ctypes.c_int64),
        ('WriteTransferCount', ctypes.c_int64),
        ('OtherTransferCount', ctypes.c_int64),
        ('ThreadCounters', POINTER64),
        ('XStateSave', POINTER64))


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
class RTL_PROCESS_MODULE_INFORMATION64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ('Section', ctypes.c_uint64),
        ('MappedBase', ctypes.c_uint64),
        ('ImageBase', ctypes.c_uint64),
        ('ImageSize', ctypes.c_uint32),
        ('Flags', ctypes.c_uint32),
        ('LoadOrderIndex', ctypes.c_uint16),
        ('InitOrderIndex', ctypes.c_uint16),
        ('LoadCount', ctypes.c_uint16),
        ('OffsetToFileName', ctypes.c_uint16),
        ('FullPathName', ctypes.c_char * 256)
    )


class RTL_PROCESS_MODULE_INFORMATION32(ctypes.Structure):
    _fields_ = (
        ('Section', ctypes.c_uint32),
        ('MappedBase', ctypes.c_uint32),
        ('ImageBase', ctypes.c_uint32),
        ('ImageSize', ctypes.c_uint32),
        ('Flags', ctypes.c_uint32),
        ('LoadOrderIndex', ctypes.c_uint16),
        ('InitOrderIndex', ctypes.c_uint16),
        ('LoadCount', ctypes.c_uint16),
        ('OffsetToFileName', ctypes.c_uint16),
        ('FullPathName', ctypes.c_char * 256)
    )


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
class EPROCESS64(ctypes.Structure):
    _pack_ = 8
    _fields_ = (('dummy', ctypes.c_char * 0x4d0), )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base


class EPROCESS32(ctypes.Structure):
    _fields_ = (('dummy', ctypes.c_char * 0x2c0), )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base


# FIXME: duplicate class
class LdrData:
    def __init__(self,
                 ql,
                 base=0,
                 length=0,
                 initialized=0,
                 ss_handle=0,
                 in_load_order_module_list={
                     'Flink': 0,
                     'Blink': 0
                 },
                 in_memory_order_module_list={
                     'Flink': 0,
                     'Blink': 0
                 },
                 in_initialization_order_module_list={
                     'Flink': 0,
                     'Blink': 0
                 },
                 entry_in_progress=0,
                 shutdown_in_progress=0,
                 shutdown_thread_id=0):
        self.ql = ql
        self.base = base
        self.Length = length
        self.Initialized = initialized
        self.SsHandle = ss_handle
        self.InLoadOrderModuleList = in_load_order_module_list
        self.InMemoryOrderModuleList = in_memory_order_module_list
        self.InInitializationOrderModuleList = in_initialization_order_module_list
        self.EntryInProgress = entry_in_progress
        self.ShutdownInProgress = shutdown_in_progress
        self.selfShutdownThreadId = shutdown_thread_id

    def bytes(self):
        s = b''
        s += self.ql.pack32(self.Length)  # 0x0
        s += self.ql.pack32(self.Initialized)  # 0x4
        s += self.ql.pack(self.SsHandle)  # 0x8
        s += self.ql.pack(self.InLoadOrderModuleList['Flink'])  # 0x0c
        s += self.ql.pack(self.InLoadOrderModuleList['Blink'])
        s += self.ql.pack(self.InMemoryOrderModuleList['Flink'])  # 0x14
        s += self.ql.pack(self.InMemoryOrderModuleList['Blink'])
        s += self.ql.pack(
            self.InInitializationOrderModuleList['Flink'])  # 0x1C
        s += self.ql.pack(self.InInitializationOrderModuleList['Blink'])
        s += self.ql.pack(self.EntryInProgress)
        s += self.ql.pack(self.ShutdownInProgress)
        s += self.ql.pack(self.selfShutdownThreadId)
        return s


class LdrDataTableEntry:
    def __init__(self,
                 ql,
                 base=0,
                 in_load_order_links={
                     'Flink': 0,
                     'Blink': 0
                 },
                 in_memory_order_links={
                     'Flink': 0,
                     'Blink': 0
                 },
                 in_initialization_order_links={
                     'Flink': 0,
                     'Blink': 0
                 },
                 dll_base=0,
                 entry_point=0,
                 size_of_image=0,
                 full_dll_name='',
                 base_dll_name='',
                 flags=0,
                 load_count=0,
                 tls_index=0,
                 hash_links=0,
                 section_pointer=0,
                 check_sum=0,
                 time_date_stamp=0,
                 loaded_imports=0,
                 entry_point_activation_context=0,
                 patch_information=0,
                 forwarder_links=0,
                 service_tag_links=0,
                 static_links=0,
                 context_information=0,
                 original_base=0,
                 load_time=0):
        self.ql = ql
        self.base = base
        self.InLoadOrderLinks = in_load_order_links
        self.InMemoryOrderLinks = in_memory_order_links
        self.InInitializationOrderLinks = in_initialization_order_links
        self.DllBase = dll_base
        self.EntryPoint = entry_point
        self.SizeOfImage = size_of_image

        full_dll_name = full_dll_name.encode("utf-16le")
        self.FullDllName = {
            'Length': len(full_dll_name),
            'MaximumLength': len(full_dll_name) + 2
        }
        self.FullDllName['BufferPtr'] = self.ql.os.heap.alloc(
            self.FullDllName['MaximumLength'])
        ql.mem.write(self.FullDllName['BufferPtr'],
                     full_dll_name + b"\x00\x00")

        base_dll_name = base_dll_name.encode("utf-16le")
        self.BaseDllName = {
            'Length': len(base_dll_name),
            'MaximumLength': len(base_dll_name) + 2
        }
        self.BaseDllName['BufferPtr'] = self.ql.os.heap.alloc(
            self.BaseDllName['MaximumLength'])
        ql.mem.write(self.BaseDllName['BufferPtr'],
                     base_dll_name + b"\x00\x00")

        self.Flags = flags
        self.LoadCount = load_count
        self.TlsIndex = tls_index
        self.HashLinks = hash_links
        self.SectionPointer = section_pointer
        self.CheckSum = check_sum
        self.TimeDateStamp = time_date_stamp
        self.LoadedImports = loaded_imports
        self.EntryPointActivationContext = entry_point_activation_context
        self.PatchInformation = patch_information
        self.ForwarderLinks = forwarder_links
        self.ServiceTagLinks = service_tag_links
        self.StaticLinks = static_links
        self.ContextInformation = context_information
        self.OriginalBase = original_base
        self.LoadTime = load_time

    def attrs(self):
        return ", ".join("{}={}".format(k, getattr(self, k))
                         for k in self.__dict__.keys())

    def print(self):
        return "[{}:{}]".format(self.__class__.__name__, self.attrs())

    def bytes(self):
        s = b''
        s += self.ql.pack(self.InLoadOrderLinks['Flink'])  # 0x0
        s += self.ql.pack(self.InLoadOrderLinks['Blink'])
        s += self.ql.pack(self.InMemoryOrderLinks['Flink'])  # 0x8
        s += self.ql.pack(self.InMemoryOrderLinks['Blink'])
        s += self.ql.pack(self.InInitializationOrderLinks['Flink'])  # 0x10
        s += self.ql.pack(self.InInitializationOrderLinks['Blink'])
        s += self.ql.pack(self.DllBase)  # 0x18
        s += self.ql.pack(self.EntryPoint)  # 0x1c
        s += self.ql.pack(self.SizeOfImage)  # 0x20
        s += self.ql.pack16(self.FullDllName['Length'])  # 0x24
        s += self.ql.pack16(self.FullDllName['MaximumLength'])  # 0x26
        if self.ql.archtype == QL_ARCH.X8664:
            s += self.ql.pack32(0)
        s += self.ql.pack(self.FullDllName['BufferPtr'])  # 0x28
        s += self.ql.pack16(self.BaseDllName['Length'])
        s += self.ql.pack16(self.BaseDllName['MaximumLength'])
        if self.ql.archtype == QL_ARCH.X8664:
            s += self.ql.pack32(0)
        s += self.ql.pack(self.BaseDllName['BufferPtr'])
        s += self.ql.pack(self.Flags)
        s += self.ql.pack(self.LoadCount)
        s += self.ql.pack(self.TlsIndex)
        s += self.ql.pack(self.HashLinks)
        s += self.ql.pack(self.SectionPointer)
        s += self.ql.pack(self.CheckSum)
        s += self.ql.pack(self.TimeDateStamp)
        s += self.ql.pack(self.LoadedImports)
        s += self.ql.pack(self.EntryPointActivationContext)
        s += self.ql.pack(self.PatchInformation)
        s += self.ql.pack(self.ForwarderLinks)
        s += self.ql.pack(self.ServiceTagLinks)
        s += self.ql.pack(self.StaticLinks)
        s += self.ql.pack(self.ContextInformation)
        s += self.ql.pack(self.OriginalBase)
        s += self.ql.pack(self.LoadTime)

        return s


class WindowsStruct:

    def __init__(self, ql):
        self.ql = ql
        self.addr = None
        self.ULONG_SIZE = 8
        self.LONG_SIZE = 4
        self.POINTER_SIZE = self.ql.pointersize
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
                self.ql.log.debug("Writing to %d with value %s" % (addr + already_written, value))
                self.ql.mem.write(addr + already_written, value)
            elif typ == bytes:
                if isinstance(val, bytearray):
                    value = bytes(val)
                else:
                    value = val
                self.ql.log.debug("Writing at addr %d value %s" % (addr + already_written, value))

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
            self.ql.log.debug("Reading from %d value %s" % (addr + already_read, value))
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
        self.ql = ql
        # TODO find a GOOD reference paper for the values
        self.struct[Token.TokenInformationClass.TokenUIAccess.value] = self.ql.pack(0x1)
        self.struct[Token.TokenInformationClass.TokenGroups.value] = self.ql.pack(0x1)
        # still not sure why 0x1234 executes gandcrab as admin, but 544 no. No idea (see sid refs for the values)
        sub = 0x1234 if ql.os.profile["SYSTEM"]["permission"] == "root" else 545
        sub = sub.to_bytes(4, "little")
        sid = Sid(self.ql, identifier=1, revision=1, subs_count=1, subs=sub)
        sid_addr = self.ql.os.heap.alloc(sid.size)
        sid.write(sid_addr)
        handle = Handle(obj=sid, id=sid_addr)
        self.ql.os.handle_manager.append(handle)
        self.struct[Token.TokenInformationClass.TokenIntegrityLevel] = self.ql.pack(sid_addr)

    def get(self, value):
        res = self.struct[value]
        if res is None:
            raise QlErrorNotImplemented("API not implemented")
        else:
            return res


# typedef struct _SID {
#   BYTE                     Revision;
#   BYTE                     SubAuthorityCount;
#   SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
# #if ...
#   DWORD                    *SubAuthority[];
# #else
#   DWORD                    SubAuthority[ANYSIZE_ARRAY];
# #endif
# } SID, *PISID;
class Sid(WindowsStruct):
    # General Struct
    # https://docs.microsoft.com/it-it/windows/win32/api/winnt/ns-winnt-sid
    # https://en.wikipedia.org/wiki/Security_Identifier

    # Identf Authority
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

    def __init__(self, ql, revision=None, subs_count=None, identifier=None, subs=None):
        # TODO find better documentation
        super().__init__(ql)
        self.revision = [revision, self.BYTE_SIZE, "little", int]
        self.subs_count = [subs_count, self.BYTE_SIZE, "little", int]
        # FIXME: understand if is correct to set them as big
        self.identifier = [identifier, 6, "big", int]
        self.subs = [subs, self.subs_count[0] * self.DWORD_SIZE, "little", bytes]
        self.size = 2 + 6 + self.subs_count[0] * 4

    def write(self, addr):
        super().generic_write(addr, [self.revision, self.subs_count, self.identifier, self.subs])

    def read(self, addr):
        super().generic_read(addr, [self.revision, self.subs_count, self.identifier, self.subs])
        self.size = 2 + 6 + self.subs_count[0] * 4

    def __eq__(self, other):
        # FIXME
        if not isinstance(other, Sid):
            return False
        return self.subs == other.subs and self.identifier[0] == other.identifier[0]


class Mutex:
    def __init__(self, name, type):
        self.name = name
        self.locked = False
        self.type = type

    def lock(self):
        self.locked = True

    def unlock(self):
        self.locked = False

    def isFree(self):
        return not self.locked


class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    _fields_ = (
        ('OriginalFirstThunk', ctypes.c_uint32),
        ('TimeDateStamp', ctypes.c_uint32),
        ('ForwarderChain', ctypes.c_uint32), 
        ('Name', ctypes.c_uint32),
        ('FirstThunk', ctypes.c_uint32)
    )


class CLIENT_ID32(ctypes.Structure):
    _fields_ = (
        ('UniqueProcess', ctypes.c_uint32),
        ('UniqueThread', ctypes.c_uint32)
    )


class CLIENT_ID64(ctypes.Structure):
    _fields_ = (
        ('UniqueProcess', ctypes.c_uint64),
        ('UniqueThread', ctypes.c_uint64)
    )
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


# typedef struct _OSVERSIONINFOEXA {
#   DWORD dwOSVersionInfoSize;
#   DWORD dwMajorVersion;
#   DWORD dwMinorVersion;
#   DWORD dwBuildNumber;
#   DWORD dwPlatformId;
#   CHAR  szCSDVersion[128];
#   WORD  wServicePackMajor;
#   WORD  wServicePackMinor;
#   WORD  wSuiteMask;
#   BYTE  wProductType;
#   BYTE  wReserved;
# } OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;
class OsVersionInfoExA(WindowsStruct):
    def __init__(self, ql, size=None, major=None, minor=None, build=None, platform=None, version=None,
                 service_major=None, service_minor=None, suite=None, product=None):
        super().__init__(ql)
        self.size = [size, self.DWORD_SIZE, "little", int]
        self.major = [major, self.DWORD_SIZE, "little", int]
        self.minor = [minor, self.DWORD_SIZE, "little", int]
        self.build = [build, self.DWORD_SIZE, "little", int]
        self.platform = [platform, self.DWORD_SIZE, "little", int]
        self.version = [version, 128, "little", bytes]
        self.service_major = [service_major, self.WORD_SIZE, "little", int]
        self.service_minor = [service_minor, self.WORD_SIZE, "little", int]
        self.suite = [suite, self.WORD_SIZE, "little", int]
        self.product = [product, self.BYTE_SIZE, "little", int]
        self.reserved = [0, self.BYTE_SIZE, "little", int]

    def write(self, addr):
        super().generic_write(addr, [self.size, self.major, self.minor, self.build, self.platform, self.version,
                                     self.service_major, self.service_minor, self.suite, self.product, self.reserved])

    def read(self, addr):
        super().generic_read(addr, [self.size, self.major, self.minor, self.build, self.platform, self.version,
                                    self.service_major, self.service_minor, self.suite, self.product, self.reserved])


# typedef struct _OSVERSIONINFOW {
#   ULONG dwOSVersionInfoSize;
#   ULONG dwMajorVersion;
#   ULONG dwMinorVersion;
#   ULONG dwBuildNumber;
#   ULONG dwPlatformId;
#   WCHAR szCSDVersion[128];
# }
class OsVersionInfoW(WindowsStruct):
    def __init__(self, ql, size=None, major=None, minor=None, build=None, platform=None, version=None):
        super().__init__(ql)
        self.size = [size, self.ULONG_SIZE, "little", int]
        self.major = [major, self.ULONG_SIZE, "little", int]
        self.minor = [minor, self.ULONG_SIZE, "little", int]
        self.build = [build, self.ULONG_SIZE, "little", int]
        self.platform = [platform, self.ULONG_SIZE, "little", int]
        self.version = [version, 128, "little", bytes]

    def write(self, addr):
        self.generic_write(addr, [self.size, self.major, self.minor, self.build, self.platform, self.version])

    def read(self, addr):
        self.generic_read(addr, [self.size, self.major, self.minor, self.build, self.platform, self.version])


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
class SystemInfo(WindowsStruct):
    def __init__(self, ql, dummy=None, page_size=None, min_address=None, max_address=None, mask=None, processors=None,
                 processor_type=None, allocation=None, processor_level=None, processor_revision=None):
        super().__init__(ql)
        self.dummy = [dummy, self.DWORD_SIZE, "little", int]
        self.page_size = [page_size, self.DWORD_SIZE, "little", int]
        self.min_address = [min_address, self.POINTER_SIZE, "little", int]
        self.max_address = [max_address, self.POINTER_SIZE, "little", int]
        self.mask = [mask, self.POINTER_SIZE, "little", int]
        self.processors = [processors, self.DWORD_SIZE, "little", int]
        self.processor_type = [processor_type, self.DWORD_SIZE, "little", int]
        self.allocation = [allocation, self.DWORD_SIZE, "little", int]
        self.processor_level = [processor_level, self.WORD_SIZE, "little", int]
        self.processor_revision = [processor_revision, self.WORD_SIZE, "little", int]
        self.size = self.DWORD_SIZE * 5 + self.WORD_SIZE * 2 + self.POINTER_SIZE * 3

    def write(self, addr):
        super().generic_write(addr, [self.dummy, self.page_size, self.min_address, self.max_address, self.mask,
                                     self.processors, self.processor_type, self.allocation, self.processor_level,
                                     self.processor_revision])

    def read(self, addr):
        super().generic_read(addr, [self.dummy, self.page_size, self.min_address, self.max_address, self.mask,
                                    self.processors, self.processor_type, self.allocation, self.processor_level,
                                    self.processor_revision])


# typedef struct _SYSTEMTIME {
#   WORD wYear;
#   WORD wMonth;
#   WORD wDayOfWeek;
#   WORD wDay;
#   WORD wHour;
#   WORD wMinute;
#   WORD wSecond;
#   WORD wMilliseconds;
# } SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;


class SystemTime(WindowsStruct):
    def __init__(self, ql, year=None, month=None, day_week=None, day=None, hour=None, minute=None, seconds=None,
                 milliseconds=None):
        super().__init__(ql)
        self.year = [year, self.WORD_SIZE, "little", int]
        self.month = [month, self.WORD_SIZE, "little", int]
        self.day_week = [day_week, self.WORD_SIZE, "little", int]
        self.day = [day, self.WORD_SIZE, "little", int]
        self.hour = [hour, self.WORD_SIZE, "little", int]
        self.minute = [minute, self.WORD_SIZE, "little", int]
        self.seconds = [seconds, self.WORD_SIZE, "little", int]
        self.milliseconds = [milliseconds, self.WORD_SIZE, "little", int]
        self.size = self.WORD_SIZE * 8

    def write(self, addr):
        super().generic_write(addr, [self.year, self.month, self.day_week, self.day, self.hour,
                                     self.minute, self.seconds, self.milliseconds])

    def read(self, addr):
        super().generic_read(addr, [self.year, self.month, self.day_week, self.day, self.hour,
                                    self.minute, self.seconds, self.milliseconds])


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
        self.size = 53 + 3 * self.ql.pointersize
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


# private struct PROCESS_BASIC_INFORMATION
# {
#   public NtStatus ExitStatus;
#   public IntPtr PebBaseAddress;
#   public UIntPtr AffinityMask;
#   public int BasePriority;
#   public UIntPtr UniqueProcessId;
#   public UIntPtr InheritedFromUniqueProcessId;
# }
class ProcessBasicInformation(WindowsStruct):
    def __init__(self, ql, exitStatus=None, pebBaseAddress=None, affinityMask=None, basePriority=None, uniqueId=None,
                 parentPid=None):
        super().__init__(ql)
        self.size = self.DWORD_SIZE + self.POINTER_SIZE * 4 + self.INT_SIZE
        self.exitStatus = [exitStatus, self.DWORD_SIZE, "little", int]
        self.pebBaseAddress = [pebBaseAddress, self.POINTER_SIZE, "little", int]
        self.affinityMask = [affinityMask, self.INT_SIZE, "little", int]
        self.basePriority = [basePriority, self.POINTER_SIZE, "little", int]
        self.pid = [uniqueId, self.POINTER_SIZE, "little", int]
        self.parentPid = [parentPid, self.POINTER_SIZE, "little", int]

    def write(self, addr):
        super().generic_write(addr,
                              [self.exitStatus, self.pebBaseAddress, self.affinityMask, self.basePriority, self.pid,
                               self.parentPid])

    def read(self, addr):
        super().generic_read(addr,
                             [self.exitStatus, self.pebBaseAddress, self.affinityMask, self.basePriority, self.pid,
                              self.parentPid])


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
        if (ql.archtype == 32):
            self.size = self.USHORT_SIZE * 2 + self.POINTER_SIZE
        else:
            self.size = self.USHORT_SIZE * 2 + 4 + self.POINTER_SIZE

        self.length = [length, self.USHORT_SIZE, "little", int, self.USHORT_SIZE]
        self.maxLength = [maxLength, self.USHORT_SIZE, "little", int, self.USHORT_SIZE]
        self.buffer = [buffer, self.POINTER_SIZE, "little", int, self.POINTER_SIZE]


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

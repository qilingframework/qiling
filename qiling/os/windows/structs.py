#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from unicorn.x86_const import *
from qiling.os.windows.utils import *

class TEB:
    def __init__(self, ql, base = 0,
                ExceptionList = 0,
                StackBase = 0,
                StackLimit = 0,
                SubSystemTib = 0,
                FiberData = 0,
                ArbitraryUserPointer = 0,
                Self = 0,
                EnvironmentPointer = 0,
                ClientIdUniqueProcess = 0,
                ClientIdUniqueThread = 0,
                RpcHandle = 0,
                Tls_Storage = 0,
                PEB_Address = 0,
                LastErrorValue = 0,
                LastStatusValue = 0,
                Count_Owned_Locks = 0,
                HardErrorMode = 0):
        self.ql = ql
        self.base = base
        self.ExceptionList = ExceptionList
        self.StackBase = StackBase
        self.StackLimit = StackLimit
        self.SubSystemTib = SubSystemTib
        self.FiberData = FiberData
        self.ArbitraryUserPointer = ArbitraryUserPointer
        self.Self = Self
        self.EnvironmentPointer = EnvironmentPointer
        self.ClientIdUniqueProcess = ClientIdUniqueProcess
        self.ClientIdUniqueThread = ClientIdUniqueThread
        self.RpcHandle = RpcHandle
        self.Tls_Storage = Tls_Storage
        self.PEB_Address = PEB_Address
        self.LastErrorValue = LastErrorValue
        self.LastStatusValue = LastStatusValue
        self.Count_Owned_Locks = Count_Owned_Locks
        self.HardErrorMode = HardErrorMode

    def bytes(self):
        s = b''
        s += self.ql.pack(self.ExceptionList)          # 0x00
        s += self.ql.pack(self.StackBase)              # 0x04
        s += self.ql.pack(self.StackLimit)             # 0x08
        s += self.ql.pack(self.SubSystemTib)           # 0x0c
        s += self.ql.pack(self.FiberData)              # 0x10
        s += self.ql.pack(self.ArbitraryUserPointer)   # 0x14
        s += self.ql.pack(self.Self)                   # 0x18
        s += self.ql.pack(self.EnvironmentPointer)     # 0x1c
        s += self.ql.pack(self.ClientIdUniqueProcess)  # 0x20
        s += self.ql.pack(self.ClientIdUniqueThread)   # 0x24
        s += self.ql.pack(self.RpcHandle)              # 0x28
        s += self.ql.pack(self.Tls_Storage)            # 0x2c
        s += self.ql.pack(self.PEB_Address)            # 0x30
        s += self.ql.pack(self.LastErrorValue)         # 0x34
        s += self.ql.pack(self.LastStatusValue)        # 0x38
        s += self.ql.pack(self.Count_Owned_Locks)      # 0x3c
        s += self.ql.pack(self.HardErrorMode)          # 0x40
        return s


class PEB:
    def __init__(self, ql, base = 0,
                flag = 0,
                Mutant = 0,
                ImageBaseAddress = 0,
                LdrAddress = 0,
                ProcessParameters = 0,
                SubSystemData = 0,
                ProcessHeap = 0,
                FastPebLock = 0,
                AtlThunkSListPtr = 0,
                IFEOKey = 0):
        self.ql = ql
        self.base = base
        self.flag = flag
        self.ImageBaseAddress = ImageBaseAddress
        self.Mutant = Mutant
        self.LdrAddress = LdrAddress
        self.ProcessParameters = ProcessParameters
        self.SubSystemData = SubSystemData
        self.ProcessHeap = ProcessHeap
        self.FastPebLock = FastPebLock
        self.AtlThunkSListPtr = AtlThunkSListPtr
        self.IFEOKey = IFEOKey

    def bytes(self):
        s = b''
        s += self.ql.pack(self.flag)                # 0x0 / 0x0
        s += self.ql.pack(self.Mutant)              # 0x4 / 0x8
        s += self.ql.pack(self.ImageBaseAddress)    # 0x8 / 0x10
        s += self.ql.pack(self.LdrAddress)          # 0xc / 0x18
        s += self.ql.pack(self.ProcessParameters)
        s += self.ql.pack(self.SubSystemData)
        s += self.ql.pack(self.ProcessHeap)
        s += self.ql.pack(self.FastPebLock)
        s += self.ql.pack(self.AtlThunkSListPtr)
        s += self.ql.pack(self.IFEOKey)
        return s


class LDR_DATA:
    def __init__(self, ql, base = 0,
                Length = 0,
                Initialized = 0,
                SsHandle = 0,
                InLoadOrderModuleList = {'Flink' : 0, 'Blink' : 0},
                InMemoryOrderModuleList = {'Flink' : 0, 'Blink' : 0},
                InInitializationOrderModuleList = {'Flink' : 0, 'Blink' : 0},
                EntryInProgress = 0,
                ShutdownInProgress = 0,
                ShutdownThreadId = 0):
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
        s += self.ql.pack32(self.Length)                                   # 0x0
        s += self.ql.pack32(self.Initialized)                              # 0x4
        s += self.ql.pack(self.SsHandle)                                   # 0x8
        s += self.ql.pack(self.InLoadOrderModuleList['Flink'])             # 0x0c
        s += self.ql.pack(self.InLoadOrderModuleList['Blink'])
        s += self.ql.pack(self.InMemoryOrderModuleList['Flink'])           # 0x14
        s += self.ql.pack(self.InMemoryOrderModuleList['Blink'])
        s += self.ql.pack(self.InInitializationOrderModuleList['Flink'])   # 0x1C
        s += self.ql.pack(self.InInitializationOrderModuleList['Blink'])
        s += self.ql.pack(self.EntryInProgress)
        s += self.ql.pack(self.ShutdownInProgress)
        s += self.ql.pack(self.selfShutdownThreadId)
        return s


class LDR_DATA_TABLE_ENTRY:
    def __init__(self, ql, base = 0,
                InLoadOrderLinks = {'Flink' : 0, 'Blink' : 0},
                InMemoryOrderLinks = {'Flink' : 0, 'Blink' : 0},
                InInitializationOrderLinks = {'Flink' : 0, 'Blink' : 0},
                DllBase = 0,
                EntryPoint = 0,
                SizeOfImage = 0,
                FullDllName = '',
                BaseDllName = '',
                Flags = 0,
                LoadCount = 0,
                TlsIndex = 0,
                HashLinks = 0,
                SectionPointer = 0,
                CheckSum = 0,
                TimeDateStamp = 0,
                LoadedImports = 0,
                EntryPointActivationContext = 0,
                PatchInformation = 0,
                ForwarderLinks = 0,
                ServiceTagLinks = 0,
                StaticLinks = 0,
                ContextInformation = 0,
                OriginalBase = 0,
                LoadTime = 0):
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
        self.FullDllName['BufferPtr'] = ql.heap.mem_alloc(self.FullDllName['MaximumLength'])
        ql.uc.mem_write(self.FullDllName['BufferPtr'], FullDllName + b"\x00\x00")

        BaseDllName = BaseDllName.encode("utf-16le")
        self.BaseDllName = {}
        self.BaseDllName['Length'] = len(BaseDllName)
        self.BaseDllName['MaximumLength'] = len(BaseDllName) + 2
        self.BaseDllName['BufferPtr'] = ql.heap.mem_alloc(self.BaseDllName['MaximumLength'])
        ql.uc.mem_write(self.BaseDllName['BufferPtr'], BaseDllName + b"\x00\x00")

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
        return ", ".join("{}={}".format(k, getattr(self, k)) for k in self.__dict__.keys())

    def print(self):
        return "[{}:{}]".format(self.__class__.__name__, self.attrs())

    def bytes(self):
        s = b''
        s += self.ql.pack(self.InLoadOrderLinks['Flink'])             # 0x0
        s += self.ql.pack(self.InLoadOrderLinks['Blink'])
        s += self.ql.pack(self.InMemoryOrderLinks['Flink'])           # 0x8
        s += self.ql.pack(self.InMemoryOrderLinks['Blink'])
        s += self.ql.pack(self.InInitializationOrderLinks['Flink'])   # 0x10
        s += self.ql.pack(self.InInitializationOrderLinks['Blink'])
        s += self.ql.pack(self.DllBase)                               # 0x18
        s += self.ql.pack(self.EntryPoint)                            # 0x1c
        s += self.ql.pack(self.SizeOfImage)                           # 0x20
        s += self.ql.pack16(self.FullDllName['Length'])               # 0x24
        s += self.ql.pack16(self.FullDllName['MaximumLength'])        # 0x26
        if self.ql.arch == QL_X8664:
            s += self.ql.pack32(0)
        s += self.ql.pack(self.FullDllName['BufferPtr'])              # 0x28
        s += self.ql.pack16(self.BaseDllName['Length'])
        s += self.ql.pack16(self.BaseDllName['MaximumLength']) 
        if self.ql.arch == QL_X8664:
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

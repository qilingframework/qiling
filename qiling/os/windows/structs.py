#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.windows.utils import *
from enum import IntEnum
from qiling.os.windows.handle import *


class TEB:
    def __init__(self, ql, base=0,
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
    def __init__(self, ql, base=0,
                 flag=0,
                 mutant=0,
                 image_base_address=0,
                 ldr_address=0,
                 process_parameters=0,
                 sub_system_data=0,
                 process_heap=0,
                 fast_peb_lock=0,
                 alt_thunk_s_list_ptr=0,
                 ifeo_key=0):
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

    def bytes(self):
        s = b''
        s += self.ql.pack(self.flag)  # 0x0 / 0x0
        s += self.ql.pack(self.Mutant)  # 0x4 / 0x8
        s += self.ql.pack(self.ImageBaseAddress)  # 0x8 / 0x10
        s += self.ql.pack(self.LdrAddress)  # 0xc / 0x18
        s += self.ql.pack(self.ProcessParameters)
        s += self.ql.pack(self.SubSystemData)
        s += self.ql.pack(self.ProcessHeap)
        s += self.ql.pack(self.FastPebLock)
        s += self.ql.pack(self.AtlThunkSListPtr)
        s += self.ql.pack(self.IFEOKey)
        return s


class LdrData:
    def __init__(self, ql, base=0,
                 length=0,
                 initialized=0,
                 ss_handle=0,
                 in_load_order_module_list={'Flink': 0, 'Blink': 0},
                 in_memory_order_module_list={'Flink': 0, 'Blink': 0},
                 in_initialization_order_module_list={'Flink': 0, 'Blink': 0},
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
        s += self.ql.pack(self.InInitializationOrderModuleList['Flink'])  # 0x1C
        s += self.ql.pack(self.InInitializationOrderModuleList['Blink'])
        s += self.ql.pack(self.EntryInProgress)
        s += self.ql.pack(self.ShutdownInProgress)
        s += self.ql.pack(self.selfShutdownThreadId)
        return s


class LdrDataTableEntry:
    def __init__(self, ql, base=0,
                 in_load_order_links={'Flink': 0, 'Blink': 0},
                 in_memory_order_links={'Flink': 0, 'Blink': 0},
                 in_initialization_order_links={'Flink': 0, 'Blink': 0},
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
        self.FullDllName = {'Length': len(full_dll_name), 'MaximumLength': len(full_dll_name) + 2}
        self.FullDllName['BufferPtr'] = self.ql.os.heap.alloc(self.FullDllName['MaximumLength'])
        ql.mem.write(self.FullDllName['BufferPtr'], full_dll_name + b"\x00\x00")

        base_dll_name = base_dll_name.encode("utf-16le")
        self.BaseDllName = {'Length': len(base_dll_name), 'MaximumLength': len(base_dll_name) + 2}
        self.BaseDllName['BufferPtr'] = self.ql.os.heap.alloc(self.BaseDllName['MaximumLength'])
        ql.mem.write(self.BaseDllName['BufferPtr'], base_dll_name + b"\x00\x00")

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
        return ", ".join("{}={}".format(k, getattr(self, k)) for k in self.__dict__.keys())

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

    def write(self, addr):
        # I want to force the subclasses to implement it
        raise NotImplementedError

    def read(self, addr):
        # I want to force the subclasses to implement it
        raise NotImplementedError


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
        sid = Sid(self.ql, identifier=1, revision=1, subs_count=1, subs=[sub])
        sid_addr = self.ql.os.heap.alloc(sid.size)
        sid.write(sid_addr)
        handle = Handle(obj=sid, id=sid_addr)
        self.ql.os.handle_manager.append(handle)
        self.struct[Token.TokenInformationClass.TokenIntegrityLevel] = self.ql.pack(sid_addr)

    def get(self, value):
        res = self.struct[value]
        if res is None:
            raise QlErrorNotImplemented("[!] API not implemented")
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
        self.revision: int = revision
        self.subs_count: int = subs_count
        self.identifier: int = identifier
        self.subs: [int] = subs

        if subs_count is not None:
            self.size = 2 + 6 + self.subs_count * 4

    def write(self, addr):
        self.ql.mem.write(addr, self.revision.to_bytes(length=1, byteorder="little"))
        self.ql.mem.write(addr + 1, self.subs_count.to_bytes(length=1, byteorder="little"))
        self.ql.mem.write(addr + 2, self.identifier.to_bytes(length=6, byteorder="big"))
        for i in range(self.subs_count):
            self.ql.mem.write(addr + 2 + 6 + 4 * i, self.subs[i].to_bytes(4, "little"))
        self.addr = addr

    def read(self, addr):
        self.revision = int.from_bytes(self.ql.mem.read(addr, 1), byteorder="little")
        self.subs_count = int.from_bytes(self.ql.mem.read(addr + 1, 1), byteorder="little")
        self.identifier = int.from_bytes(self.ql.mem.read(addr + 2, 6), byteorder="little")
        self.subs = []
        for i in range(self.subs_count):
            sub = int.from_bytes(self.ql.mem.read(addr + 2 + 6 + 4 * i, 4), "little")
            self.subs.append(sub)
        self.addr = addr

    def __eq__(self, other):
        if not isinstance(other, Sid):
            return False
        return self.struct == other.struct


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


# typedef struct tagPOINT {
#   LONG x;
#   LONG y;
# } POINT, *PPOINT;
class Point(WindowsStruct):
    def __init__(self, ql, x=None, y=None):
        super().__init__(ql)
        self.x: int = x
        self.y: int = y
        self.size = 64

    def write(self, addr):
        self.ql.mem.write(addr, self.x.to_bytes(length=32, byteorder="little"))
        self.ql.mem.write(addr + 32, self.y.to_bytes(length=32, byteorder="little"))
        self.addr = addr

    def read(self, addr):
        self.x = int.from_bytes(self.ql.mem.read(addr, 32), byteorder="little")
        self.y = int.from_bytes(self.ql.mem.read(addr + 32, 32), byteorder="little")
        self.addr = addr


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
        self.name = name
        self.aliases = aliases
        self.addr_type = addr_type
        self.length = length
        self.addr_list = addr_list
        self.size = self.ql.pointersize * 3 + 4

    def write(self, addr):
        ip_ptr = self.ql.heap.alloc(self.name)
        ql.uc.mem.write(ip_ptr, self.name.encode())
        ql.mem.write(addr, ip_ptr.to_bytes(length=self.ql.pointersize, byteorder='little'))
        ql.mem.write(addr + self.ql.pointersize, self.aliases.to_bytes(length=self.ql.pointersize, byteorder='little'))
        ql.mem.write(addr + 2 * self.ql.pointersize, self.addr_type.add.to_bytes(length=2, byteorder='little'))
        ql.mem.write(addr + 2 * self.ql.pointersize + 2, self.length.to_bytes(length=2, byteorder='little'))
        ql.mem.write(addr + 2 * self.ql.pointersize + 4, self.addr_list)
        self.addr = addr

    def read(self, addr):
        ip_ptr = int.from_bytes(self.ql.mem.read(addr, self.ql.pointersize), byteorder="little")
        self.name = read_cstring(self.ql, ip_ptr)
        self.aliases = int.from_bytes(self.ql.mem.read(addr + self.ql.pointersize, self.ql.pointersize),
                                      byteorder="little")
        self.addr_type = int.from_bytes(self.ql.mem.read(addr + 2 * self.ql.pointersize, 2), byteorder="little")
        self.length = int.from_bytes(self.ql.mem.read(addr + 2 * self.ql.pointersize + 2, 2), byteorder="little")
        self.addr_list = self.ql.mem.read(addr + 2 * self.ql.pointersize + 4, self.ql.pointersize)
        self.addr = addr


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
        self.size = size
        self.major = major
        self.minor = minor
        self.build = build
        self.platform = platform
        self.version = version
        self.service_major = service_major
        self.service_minor = service_minor
        self.suite = suite
        self.product = product
        self.reserved = 0

    def write(self, addr):
        self.ql.mem.write(addr, self.size.to_bytes(4, "little"))
        self.ql.mem.write(addr + 4, self.major.to_bytes(4, "little"))
        self.ql.mem.write(addr + 8, self.minor.to_bytes(4, "little"))
        self.ql.mem.write(addr + 12, self.build.to_bytes(4, "little"))
        self.ql.mem.write(addr + 16, self.platform.to_bytes(4, "little"))
        self.ql.mem.write(addr + 20, self.version.to_bytes(128, "little"))
        self.ql.mem.write(addr + 148, self.service_major.to_bytes(2, "little"))
        self.ql.mem.write(addr + 150, self.service_minor.to_bytes(2, "little"))
        self.ql.mem.write(addr + 152, self.suite.to_bytes(2, "little"))
        self.ql.mem.write(addr + 154, self.product.to_bytes(1, "little"))
        self.ql.mem.write(addr + 155, self.reserved.to_bytes(1, "little"))
        self.addr = addr

    def read(self, addr):
        self.size = int.from_bytes(self.ql.mem.read(addr, 4), byteorder="little")
        self.major = int.from_bytes(self.ql.mem.read(addr + 4, 4), byteorder="little")
        self.minor = int.from_bytes(self.ql.mem.read(addr + 8, 4), byteorder="little")
        self.build = int.from_bytes(self.ql.mem.read(addr + 12, 4), byteorder="little")
        self.platform = int.from_bytes(self.ql.mem.read(addr + 16, 4), byteorder="little")
        self.version = int.from_bytes(self.ql.mem.read(addr + 20, 128), byteorder="little")
        self.service_major = int.from_bytes(self.ql.mem.read(addr + 20 + 128, 2), byteorder="little")
        self.service_minor = int.from_bytes(self.ql.mem.read(addr + 22 + 128, 2), byteorder="little")
        self.suite = int.from_bytes(self.ql.mem.read(addr + 152, 2), byteorder="little")
        self.product = int.from_bytes(self.ql.mem.read(addr + 154, 1), byteorder="little")
        self.reserved = int.from_bytes(self.ql.mem.read(addr + 155, 1), byteorder="little")
        self.addr = addr


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
        self.size = size
        self.major = major
        self.minor = minor
        self.build = build
        self.platform = platform
        self.version = version

    def write(self, addr):
        self.ql.mem.write(addr, self.size.to_bytes(8, byteorder="little"))
        self.ql.mem.write(addr + 8, self.major.to_bytes(8, byteorder="little"))
        self.ql.mem.write(addr + 16, self.minor.to_bytes(8, byteorder="little"))
        self.ql.mem.write(addr + 24, self.build.to_bytes(8, byteorder="little"))
        self.ql.mem.write(addr + 32, self.platform.to_bytes(8, byteorder="little"))
        self.ql.mem.write(addr + 40, self.version.to_bytes(128, byteorder="little"))
        self.addr = addr

    def read(self, addr):
        self.size = int.from_bytes(self.ql.mem.read(addr, 4), byteorder="little")
        self.major = int.from_bytes(self.ql.mem.read(addr + 8, 8), byteorder="little")
        self.minor = int.from_bytes(self.ql.mem.read(addr + 16, 8), byteorder="little")
        self.build = int.from_bytes(self.ql.mem.read(addr + 24, 8), byteorder="little")
        self.platform = int.from_bytes(self.ql.mem.read(addr + 32, 8), byteorder="little")
        self.version = int.from_bytes(self.ql.mem.read(addr + 40, 128), byteorder="little")
        self.addr = addr


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
        self.dummy = dummy
        self.page_size = page_size
        self.min_address = min_address
        self.max_address = max_address
        self.mask = mask
        self.processors = processors
        self.processor_type = processor_type
        self.allocation = allocation
        self.processor_level = processor_level
        self.processor_revision = processor_revision
        self.size = 26 + 2 * self.ql.pointersize

    def write(self, addr):
        self.ql.mem.write(addr, self.dummy.to_bytes(4, byteorder="little"))
        self.ql.mem.write(addr + 4, self.page_size.to_bytes(4, byteorder="little"))
        self.ql.mem.write(addr + 8, self.min_address.to_bytes(self.ql.pointersize, byteorder="little"))
        self.ql.mem.write(addr + 8 + self.ql.pointersize, self.max_address.to_bytes(self.ql.pointersize,
                                                                                    byteorder="little"))
        self.ql.mem.write(addr + 8 + 2 * self.ql.pointersize, self.mask.to_bytes(4, byteorder="little"))
        self.ql.mem.write(addr + 12 + 2 * self.ql.pointersize, self.processors.to_bytes(4, byteorder="little"))
        self.ql.mem.write(addr + 16 + 2 * self.ql.pointersize, self.processor_type.to_bytes(4, byteorder="little"))
        self.ql.mem.write(addr + 20 + 2 * self.ql.pointersize, self.allocation.to_bytes(4, byteorder="little"))
        self.ql.mem.write(addr + 24 + 2 * self.ql.pointersize, self.processor_level.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 26 + 2 * self.ql.pointersize, self.processor_revision.to_bytes(2, byteorder="little"))
        self.addr = addr

    def read(self, addr):
        self.dummy = int.from_bytes(self.ql.mem.read(addr, 4), byteorder="little")
        self.page_size = int.from_bytes(self.ql.mem.read(addr + 4, 4), byteorder="little")
        self.min_address = int.from_bytes(self.ql.mem.read(addr + 8, self.ql.pointersize), byteorder="little")
        self.max_address = int.from_bytes(self.ql.mem.read(addr + 8 + self.ql.pointersize, self.ql.pointersize),
                                          byteorder="little")
        self.mask = int.from_bytes(self.ql.mem.read(addr + 8 + 2 * self.ql.pointersize, 4),
                                   byteorder="little")
        self.processors = int.from_bytes(self.ql.mem.read(addr + 12 + 2 * self.ql.pointersize, 4), byteorder="little")
        self.processor_type = int.from_bytes(self.ql.mem.read(addr + 16 + 2 * self.ql.pointersize, 4),
                                             byteorder="little")
        self.allocation = int.from_bytes(self.ql.mem.read(aaddr + 20 + 2 * self.ql.pointersize, 4), byteorder="little")
        self.processor_level = int.from_bytes(self.ql.mem.read(addr + 24 + 2 * self.ql.pointersize, 2),
                                              byteorder="little")
        self.processor_revision = int.from_bytes(self.ql.mem.read(addr + 26 + 2 * self.ql.pointersize, 2),
                                                 byteorder="little")
        self.addr = addr


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
        self.year = year
        self.month = month
        self.day_week = day_week
        self.day = day
        self.hour = hour
        self.minute = minute
        self.seconds = seconds
        self.milliseconds = milliseconds

    def write(self, addr):
        self.ql.mem.write(addr, self.year.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 2, self.month.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 4, self.day_week.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 6, self.day.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 8, self.hour.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 10, self.minute.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 12, self.seconds.to_bytes(2, byteorder="little"))
        self.ql.mem.write(addr + 14, self.milliseconds.to_bytes(2, byteorder="little"))
        self.addr = addr

    def read(self, addr):
        self.year = int.from_bytes(self.ql.mem.read(addr, 2), byteorder="little")
        self.month = int.from_bytes(self.ql.mem.read(addr + 2, 2), byteorder="little")
        self.day_week = int.from_bytes(self.ql.mem.read(addr + 4, 2), byteorder="little")
        self.day = int.from_bytes(self.ql.mem.read(addr + 6, 2), byteorder="little")
        self.hour = int.from_bytes(self.ql.mem.read(addr + 8, 2), byteorder="little")
        self.minute = int.from_bytes(self.ql.mem.read(addr + 10, 2), byteorder="little")
        self.seconds = int.from_bytes(self.ql.mem.read(addr + 12, 2), byteorder="little")
        self.milliseconds = int.from_bytes(self.ql.mem.read(addr + 14, 2), byteorder="little")
        self.addr = addr


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
        self.size = 49 + 3 * self.ql.pointersize
        self.reserved = 0
        self.desktop = desktop
        self.title = title
        self.x = x
        self.y = y
        self.x_size = x_size
        self.y_size = y_size
        self.x_chars = x_chars
        self.y_chars = y_chars
        self.fill_attribute = fill_attribute
        self.flags = flags
        self.show = show
        self.reserved2 = 0
        self.reserved3 = 0
        self.input = std_input
        self.output = output
        self.error = error

    def read(self, addr):
        self.size = int.from_bytes(self.ql.mem.read(addr, 4), byteorder="little")
        self.reserved = int.from_bytes(self.ql.mem.read(addr + 4, self.ql.pointersize), byteorder="little")
        self.desktop = int.from_bytes(self.ql.mem.read(addr + 4 + 1 * self.ql.pointersize, self.ql.pointersize),
                                      byteorder="little")
        self.title = int.from_bytes(self.ql.mem.read(addr + 4 + 2 * self.ql.pointersize, self.ql.pointersize),
                                    byteorder="little")
        self.x = int.from_bytes(self.ql.mem.read(addr + 4 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.y = int.from_bytes(self.ql.mem.read(addr + 8 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.x_size = int.from_bytes(self.ql.mem.read(addr + 12 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.y_size = int.from_bytes(self.ql.mem.read(addr + 16 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.x_chars = int.from_bytes(self.ql.mem.read(addr + 20 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.y_chars = int.from_bytes(self.ql.mem.read(addr + 24 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.fill_attribute = int.from_bytes(self.ql.mem.read(addr + 28 + 3 * self.ql.pointersize, 4),
                                             byteorder="little")
        self.flags = int.from_bytes(self.ql.mem.read(addr + 32 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.show = int.from_bytes(self.ql.mem.read(addr + 36 + 3 * self.ql.pointersize, 2), byteorder="little")
        self.reserved2 = int.from_bytes(self.ql.mem.read(addr + 38 + 3 * self.ql.pointersize, 2), byteorder="little")
        self.reserved3 = int.from_bytes(self.ql.mem.read(addr + 40 + 3 * self.ql.pointersize, 1), byteorder="little")
        self.input = int.from_bytes(self.ql.mem.read(addr + 41 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.output = int.from_bytes(self.ql.mem.read(addr + 45 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.error = int.from_bytes(self.ql.mem.read(addr + 49 + 3 * self.ql.pointersize, 4), byteorder="little")
        self.addr = addr

    def write(self, addr):
        self.ql.mem.write(addr, self.size.to_bytes(4, "little"))
        self.ql.mem.write(addr + 4, self.reserved.to_bytes(self.ql.pointersize, "little"))
        self.ql.mem.write(addr + 4 + self.ql.pointersize, self.desktop.to_bytes(self.ql.pointersize, "little"))
        self.ql.mem.write(addr + 4 + 2 * self.ql.pointersize, self.title.to_bytes(self.ql.pointersize, "little"))
        self.ql.mem.write(addr + 4 + 3 * self.ql.pointersize, self.x.to_bytes(4, "little"))
        self.ql.mem.write(addr + 8 + 3 * self.ql.pointersize, self.y.to_bytes(4, "little"))
        self.ql.mem.write(addr + 12 + 3 * self.ql.pointersize, self.x_size.to_bytes(4, "little"))
        self.ql.mem.write(addr + 16 + 3 * self.ql.pointersize, self.y_size.to_bytes(4, "little"))
        self.ql.mem.write(addr + 20 + 3 * self.ql.pointersize, self.x_chars.to_bytes(4, "little"))
        self.ql.mem.write(addr + 24 + 3 * self.ql.pointersize, self.y_chars.to_bytes(4, "little"))
        self.ql.mem.write(addr + 28 + 3 * self.ql.pointersize, self.fill_attribute.to_bytes(4, "little"))
        self.ql.mem.write(addr + 32 + 3 * self.ql.pointersize, self.flags.to_bytes(4, "little"))
        self.ql.mem.write(addr + 36 + 3 * self.ql.pointersize, self.show.to_bytes(2, "little"))
        self.ql.mem.write(addr + 38 + 3 * self.ql.pointersize, self.reserved2.to_bytes(2, "little"))
        self.ql.mem.write(addr + 40 + 3 * self.ql.pointersize, self.reserved3.to_bytes(1, "little"))
        self.ql.mem.write(addr + 41 + 3 * self.ql.pointersize, self.input.to_bytes(4, "little"))
        self.ql.mem.write(addr + 45 + 3 * self.ql.pointersize, self.output.to_bytes(4, "little"))
        self.ql.mem.write(addr + 49 + 3 * self.ql.pointersize, self.error.to_bytes(4, "little"))
        self.addr = addr

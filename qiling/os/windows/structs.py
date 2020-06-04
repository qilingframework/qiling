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
        already_written = 0
        for elem in attributes:
            (val, size, endianness, typ) = elem
            if typ == int:
                value = val.to_bytes(size, endianness)
                self.ql.dprint(D_INFO, "[+] Writing at addr %d value %s" % (addr + already_written, value))
                self.ql.mem.write(addr + already_written, value)
            elif typ == bytes:
                if isinstance(val, bytearray):
                    value = bytes(val)
                else:
                    value = val
            elif issubclass(typ, WindowsStruct):
                val.write(addr)
            else:
                raise QlErrorNotImplemented("[!] API not implemented")

            already_written += size
        self.addr = addr

    def generic_read(self, addr: int, attributes: list):
        already_read = 0
        for elem in attributes:
            (val, size, endianness, type) = elem
            value = self.ql.mem.read(addr + already_read, size)
            if type == int:
                elem[0] = int.from_bytes(value, endianness)
            elif type == bytes:
                elem[0] = value
            elif issubclass(type, WindowsStruct):
                obj = type(self.ql)
                obj.read(addr)
                elem[0] = obj
            else:
                raise QlErrorNotImplemented("[!] API not implemented")
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
        return self.subs == other.subs


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
        self.x = [x, self.LONG_SIZE, "little", int]
        self.y = [y, self.LONG_SIZE, "little", int]
        self.size = self.LONG_SIZE * 2

    def write(self, addr):
        super().generic_write(addr, [self.x, self.y])

    def read(self, addr):
        super().generic_read(addr, [self.x, self.y])


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
class UnicodeString(WindowsStruct):
    def write(self, addr):
        super().generic_write(addr, [self.length, self.maxLength, self.buffer])

    def read(self, addr):
        super().generic_read(addr, [self.length, self.maxLength, self.buffer])

    def __init__(self, ql, length=None, maxLength=None, buffer=None):
        super().__init__(ql)
        self.size = self.USHORT_SIZE * 2 + self.POINTER_SIZE
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

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
        self.FullDllName['BufferPtr'] = ql.heap.mem_alloc(self.FullDllName['MaximumLength'])
        ql.mem.write(self.FullDllName['BufferPtr'], full_dll_name + b"\x00\x00")

        base_dll_name = base_dll_name.encode("utf-16le")
        self.BaseDllName = {'Length': len(base_dll_name), 'MaximumLength': len(base_dll_name) + 2}
        self.BaseDllName['BufferPtr'] = ql.heap.mem_alloc(self.BaseDllName['MaximumLength'])
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
        if self.ql.archtype== QL_X8664:
            s += self.ql.pack32(0)
        s += self.ql.pack(self.FullDllName['BufferPtr'])  # 0x28
        s += self.ql.pack16(self.BaseDllName['Length'])
        s += self.ql.pack16(self.BaseDllName['MaximumLength'])
        if self.ql.archtype== QL_X8664:
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
        self.struct[Token.TokenInformationClass.TokenUIAccess.value] = 0x1.to_bytes(length=4,
                                                                                    byteorder='little')
        # We create a Sid Structure, set its handle and return the value
        sid = Sid(ql)
        handle = Handle(sid=sid)
        ql.handle_manager.append(handle)
        self.struct[Token.TokenInformationClass.TokenIntegrityLevel] = ql.pack(handle.id)

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
class Sid:
    # General Struct
    # https://docs.microsoft.com/it-it/windows/win32/api/winnt/ns-winnt-sid
    # Identf Authority
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
    def __init__(self, ql):
        # TODO find better documentation
        self.struct = {
            "Revision": 0x1.to_bytes(length=1, byteorder="little"),  # ADD
            "SubAuthorityCount": 0x1.to_bytes(length=1, byteorder="little"),
            "IdentifierAuthority": 0x5.to_bytes(length=6, byteorder="little"),
            "SubAuthority": 0x12345678.to_bytes(length=ql.pointersize, byteorder="little")
        }
        values = b"".join(self.struct.values())
        self.addr = ql.heap.mem_alloc(len(values))
        ql.mem.write(self.addr, values)


class Mutex:
    def __init__(self, name, type):
        self.name = name
        self.lock = False
        self.type = type

    def lock(self):
        self.lock = True

    def unlock(self):
        self.lock = False

    def isFree(self):
        return not self.lock
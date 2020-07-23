# -*- coding: utf-8 -*-
#
# TARGET arch is: []
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

# if local wordsize is same as target, keep ctypes pointer function.
# required to access _ctypes
import _ctypes
# Emulate a pointer class using the approriate c_int32/c_int64 type
# The new class should have :
# ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
# but the class should be submitted to a unique instance for each base type
# to that if A == B, POINTER_T(A) == POINTER_T(B)
ctypes._pointer_t_type_cache = {}
def POINTER_T(pointee):
    # a pointer should have the same length as LONG
    fake_ptr_base_type = ctypes.c_uint64 
    # specific case for c_void_p
    if pointee is None: # VOID pointer type. c_void_p.
        pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
        clsname = 'c_void'
    else:
        clsname = pointee.__name__
    if clsname in ctypes._pointer_t_type_cache:
        return ctypes._pointer_t_type_cache[clsname]
    # make template
    _class = type('LP_%d_%s'%(8, clsname), (fake_ptr_base_type,),{}) 
    ctypes._pointer_t_type_cache[clsname] = _class
    return _class



undefined = ctypes.c_ubyte
ImageBaseOffset32 = ctypes.c_uint32
byte = ctypes.c_ubyte
dword = ctypes.c_uint32
longlong = ctypes.c_int64
qword = ctypes.c_uint64
uchar = ctypes.c_ubyte
uint = ctypes.c_uint32
ulong = ctypes.c_uint64
ulonglong = ctypes.c_uint64
undefined1 = ctypes.c_ubyte
undefined4 = ctypes.c_uint32
undefined8 = ctypes.c_uint64
ushort = ctypes.c_uint16
word = ctypes.c_uint16
class struct_DXE_SERVICES(ctypes.Structure):
    pass

class struct_EFI_TABLE_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Signature', ctypes.c_uint64),
    ('Revision', ctypes.c_uint32),
    ('HeaderSize', ctypes.c_uint32),
    ('CRC32', ctypes.c_uint32),
    ('Reserved', ctypes.c_uint32),
     ]


# values for enumeration 'enum_852'
enum_852__enumvalues = {
    7: 'EfiGcdMemoryTypeMaximum',
    3: 'EfiGcdMemoryTypeMemoryMappedIo',
    6: 'EfiGcdMemoryTypeMoreReliable',
    0: 'EfiGcdMemoryTypeNonExistent',
    4: 'EfiGcdMemoryTypePersistent',
    5: 'EfiGcdMemoryTypePersistentMemory',
    1: 'EfiGcdMemoryTypeReserved',
    2: 'EfiGcdMemoryTypeSystemMemory',
}
EfiGcdMemoryTypeMaximum = 7
EfiGcdMemoryTypeMemoryMappedIo = 3
EfiGcdMemoryTypeMoreReliable = 6
EfiGcdMemoryTypeNonExistent = 0
EfiGcdMemoryTypePersistent = 4
EfiGcdMemoryTypePersistentMemory = 5
EfiGcdMemoryTypeReserved = 1
EfiGcdMemoryTypeSystemMemory = 2
enum_852 = ctypes.c_int # enum
class struct_EFI_GCD_IO_SPACE_DESCRIPTOR(ctypes.Structure):
    pass

class struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR(ctypes.Structure):
    pass

class struct_GUID(ctypes.Structure):
    pass


# values for enumeration 'enum_853'
enum_853__enumvalues = {
    2: 'EfiGcdIoTypeIo',
    3: 'EfiGcdIoTypeMaximum',
    0: 'EfiGcdIoTypeNonExistent',
    1: 'EfiGcdIoTypeReserved',
}
EfiGcdIoTypeIo = 2
EfiGcdIoTypeMaximum = 3
EfiGcdIoTypeNonExistent = 0
EfiGcdIoTypeReserved = 1
enum_853 = ctypes.c_int # enum

# values for enumeration 'enum_854'
enum_854__enumvalues = {
    2: 'EfiGcdAllocateAddress',
    0: 'EfiGcdAllocateAnySearchBottomUp',
    3: 'EfiGcdAllocateAnySearchTopDown',
    1: 'EfiGcdAllocateMaxAddressSearchBottomUp',
    4: 'EfiGcdAllocateMaxAddressSearchTopDown',
    5: 'EfiGcdMaxAllocateType',
}
EfiGcdAllocateAddress = 2
EfiGcdAllocateAnySearchBottomUp = 0
EfiGcdAllocateAnySearchTopDown = 3
EfiGcdAllocateMaxAddressSearchBottomUp = 1
EfiGcdAllocateMaxAddressSearchTopDown = 4
EfiGcdMaxAllocateType = 5
enum_854 = ctypes.c_int # enum
struct_DXE_SERVICES._pack_ = True # source:False
struct_DXE_SERVICES._functions_ = []
struct_DXE_SERVICES._fields_ = [
    ('Hdr', struct_EFI_TABLE_HEADER),
    ('AddMemorySpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_852, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('AllocateMemorySpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_854, enum_852, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(None), POINTER_T(None)))),
    ('FreeMemorySpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('RemoveMemorySpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('GetMemorySpaceDescriptor', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR)))),
    ('SetMemorySpaceAttributes', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('GetMemorySpaceMap', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR))))),
    ('AddIoSpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_853, ctypes.c_uint64, ctypes.c_uint64))),
    ('AllocateIoSpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_854, enum_853, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(None), POINTER_T(None)))),
    ('FreeIoSpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('RemoveIoSpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('GetIoSpaceDescriptor', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR)))),
    ('GetIoSpaceMap', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR))))),
    ('Dispatch', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64))),
    ('Schedule', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID)))),
    ('Trust', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID)))),
    ('ProcessFirmwareVolume', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('SetMemorySpaceCapabilities', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
]

struct_DXE_SERVICES._functions_.append(("AddMemorySpace",['ctypes.c_uint64', 'enum_852', 'ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("AllocateMemorySpace",['ctypes.c_uint64', 'enum_854', 'enum_852', 'ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(None)', 'POINTER_T(None)']))
struct_DXE_SERVICES._functions_.append(("FreeMemorySpace",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("RemoveMemorySpace",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("GetMemorySpaceDescriptor",['ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR)']))
struct_DXE_SERVICES._functions_.append(("SetMemorySpaceAttributes",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("GetMemorySpaceMap",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR))']))
struct_DXE_SERVICES._functions_.append(("AddIoSpace",['ctypes.c_uint64', 'enum_853', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("AllocateIoSpace",['ctypes.c_uint64', 'enum_854', 'enum_853', 'ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(None)', 'POINTER_T(None)']))
struct_DXE_SERVICES._functions_.append(("FreeIoSpace",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("RemoveIoSpace",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("GetIoSpaceDescriptor",['ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR)']))
struct_DXE_SERVICES._functions_.append(("GetIoSpaceMap",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR))']))
struct_DXE_SERVICES._functions_.append(("Dispatch",['ctypes.c_uint64']))
struct_DXE_SERVICES._functions_.append(("Schedule",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)']))
struct_DXE_SERVICES._functions_.append(("Trust",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)']))
struct_DXE_SERVICES._functions_.append(("ProcessFirmwareVolume",['ctypes.c_uint64', 'POINTER_T(None)', 'ctypes.c_uint64', 'POINTER_T(POINTER_T(None))']))
struct_DXE_SERVICES._functions_.append(("SetMemorySpaceCapabilities",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
DXE_SERVICES = struct_DXE_SERVICES
PDXE_SERVICES = POINTER_T(struct_DXE_SERVICES)
EFI_DXE_SERVICES = struct_DXE_SERVICES
EFI_TABLE_HEADER = struct_EFI_TABLE_HEADER
PEFI_TABLE_HEADER = POINTER_T(struct_EFI_TABLE_HEADER)
UINT64 = ctypes.c_uint64
UINTN = ctypes.c_uint64
RETURN_STATUS = ctypes.c_uint64
EFI_STATUS = ctypes.c_uint64
EFI_GCD_MEMORY_TYPE = enum_852
EFI_GCD_MEMORY_TYPE__enumvalues = enum_852__enumvalues
EFI_PHYSICAL_ADDRESS = ctypes.c_uint64
EFI_ADD_MEMORY_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_852, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
EFI_GCD_ALLOCATE_TYPE = enum_854
EFI_GCD_ALLOCATE_TYPE__enumvalues = enum_854__enumvalues
EFI_HANDLE = POINTER_T(None)
EFI_ALLOCATE_MEMORY_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_854, enum_852, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(None), POINTER_T(None)))
EFI_FREE_MEMORY_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
EFI_REMOVE_MEMORY_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR._pack_ = True # source:False
struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR._functions_ = []
struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR._fields_ = [
    ('BaseAddress', ctypes.c_uint64),
    ('Length', ctypes.c_uint64),
    ('Capabilities', ctypes.c_uint64),
    ('Attributes', ctypes.c_uint64),
    ('GcdMemoryType', EFI_GCD_MEMORY_TYPE),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ImageHandle', POINTER_T(None)),
    ('DeviceHandle', POINTER_T(None)),
]

EFI_GCD_MEMORY_SPACE_DESCRIPTOR = struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR
PEFI_GCD_MEMORY_SPACE_DESCRIPTOR = POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR)
EFI_GET_MEMORY_SPACE_DESCRIPTOR = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR)))
EFI_SET_MEMORY_SPACE_ATTRIBUTES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
EFI_GET_MEMORY_SPACE_MAP = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR))))
EFI_GCD_IO_TYPE = enum_853
EFI_GCD_IO_TYPE__enumvalues = enum_853__enumvalues
EFI_ADD_IO_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_853, ctypes.c_uint64, ctypes.c_uint64))
EFI_ALLOCATE_IO_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_854, enum_853, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(None), POINTER_T(None)))
EFI_FREE_IO_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
EFI_REMOVE_IO_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
PEFI_GCD_IO_SPACE_DESCRIPTOR = POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR)
struct_EFI_GCD_IO_SPACE_DESCRIPTOR._pack_ = True # source:False
struct_EFI_GCD_IO_SPACE_DESCRIPTOR._functions_ = []
struct_EFI_GCD_IO_SPACE_DESCRIPTOR._fields_ = [
    ('BaseAddress', ctypes.c_uint64),
    ('Length', ctypes.c_uint64),
    ('GcdIoType', EFI_GCD_IO_TYPE),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ImageHandle', POINTER_T(None)),
    ('DeviceHandle', POINTER_T(None)),
]

EFI_GCD_IO_SPACE_DESCRIPTOR = struct_EFI_GCD_IO_SPACE_DESCRIPTOR
EFI_GET_IO_SPACE_DESCRIPTOR = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR)))
EFI_GET_IO_SPACE_MAP = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR))))
EFI_DISPATCH = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64))
struct_GUID._pack_ = True # source:False
struct_GUID._functions_ = []
struct_GUID._fields_ = [
    ('Data1', ctypes.c_uint32),
    ('Data2', ctypes.c_uint16),
    ('Data3', ctypes.c_uint16),
    ('Data4', ctypes.c_ubyte * 8),
]

GUID = struct_GUID
PGUID = POINTER_T(struct_GUID)
EFI_GUID = struct_GUID
EFI_SCHEDULE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID)))
EFI_TRUST = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID)))
EFI_PROCESS_FIRMWARE_VOLUME = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64, POINTER_T(POINTER_T(None))))
EFI_SET_MEMORY_SPACE_CAPABILITIES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
UINT32 = ctypes.c_uint32
UINT16 = ctypes.c_uint16
UINT8 = ctypes.c_ubyte
__all__ = \
    ['DXE_SERVICES', 'EFI_ADD_IO_SPACE', 'EFI_ADD_MEMORY_SPACE',
    'EFI_ALLOCATE_IO_SPACE', 'EFI_ALLOCATE_MEMORY_SPACE',
    'EFI_DISPATCH', 'EFI_DXE_SERVICES', 'EFI_FREE_IO_SPACE',
    'EFI_FREE_MEMORY_SPACE', 'EFI_GCD_ALLOCATE_TYPE',
    'EFI_GCD_ALLOCATE_TYPE__enumvalues',
    'EFI_GCD_IO_SPACE_DESCRIPTOR', 'EFI_GCD_IO_TYPE',
    'EFI_GCD_IO_TYPE__enumvalues', 'EFI_GCD_MEMORY_SPACE_DESCRIPTOR',
    'EFI_GCD_MEMORY_TYPE', 'EFI_GCD_MEMORY_TYPE__enumvalues',
    'EFI_GET_IO_SPACE_DESCRIPTOR', 'EFI_GET_IO_SPACE_MAP',
    'EFI_GET_MEMORY_SPACE_DESCRIPTOR', 'EFI_GET_MEMORY_SPACE_MAP',
    'EFI_GUID', 'EFI_HANDLE', 'EFI_PHYSICAL_ADDRESS',
    'EFI_PROCESS_FIRMWARE_VOLUME', 'EFI_REMOVE_IO_SPACE',
    'EFI_REMOVE_MEMORY_SPACE', 'EFI_SCHEDULE',
    'EFI_SET_MEMORY_SPACE_ATTRIBUTES',
    'EFI_SET_MEMORY_SPACE_CAPABILITIES', 'EFI_STATUS',
    'EFI_TABLE_HEADER', 'EFI_TRUST', 'EfiGcdAllocateAddress',
    'EfiGcdAllocateAnySearchBottomUp',
    'EfiGcdAllocateAnySearchTopDown',
    'EfiGcdAllocateMaxAddressSearchBottomUp',
    'EfiGcdAllocateMaxAddressSearchTopDown', 'EfiGcdIoTypeIo',
    'EfiGcdIoTypeMaximum', 'EfiGcdIoTypeNonExistent',
    'EfiGcdIoTypeReserved', 'EfiGcdMaxAllocateType',
    'EfiGcdMemoryTypeMaximum', 'EfiGcdMemoryTypeMemoryMappedIo',
    'EfiGcdMemoryTypeMoreReliable', 'EfiGcdMemoryTypeNonExistent',
    'EfiGcdMemoryTypePersistent', 'EfiGcdMemoryTypePersistentMemory',
    'EfiGcdMemoryTypeReserved', 'EfiGcdMemoryTypeSystemMemory',
    'GUID', 'ImageBaseOffset32', 'PDXE_SERVICES',
    'PEFI_GCD_IO_SPACE_DESCRIPTOR',
    'PEFI_GCD_MEMORY_SPACE_DESCRIPTOR', 'PEFI_TABLE_HEADER', 'PGUID',
    'RETURN_STATUS', 'UINT16', 'UINT32', 'UINT64', 'UINT8', 'UINTN',
    'byte', 'dword', 'enum_852', 'enum_853', 'enum_854', 'longlong',
    'qword', 'struct_DXE_SERVICES',
    'struct_EFI_GCD_IO_SPACE_DESCRIPTOR',
    'struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR',
    'struct_EFI_TABLE_HEADER', 'struct_GUID', 'uchar', 'uint',
    'ulong', 'ulonglong', 'undefined', 'undefined1', 'undefined4',
    'undefined8', 'ushort', 'word']

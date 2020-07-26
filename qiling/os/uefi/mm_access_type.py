# -*- coding: utf-8 -*-
#
# TARGET arch is: []
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


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
ulonglong = ctypes.c_uint64
undefined1 = ctypes.c_ubyte
undefined2 = ctypes.c_uint16
undefined4 = ctypes.c_uint32
undefined8 = ctypes.c_uint64
ushort = ctypes.c_uint16
word = ctypes.c_uint16
class struct__EFI_MM_ACCESS_PROTOCOL(ctypes.Structure):
    pass

class struct_EFI_MMRAM_DESCRIPTOR(ctypes.Structure):
    pass

struct__EFI_MM_ACCESS_PROTOCOL._pack_ = True # source:False
struct__EFI_MM_ACCESS_PROTOCOL._functions_ = []
struct__EFI_MM_ACCESS_PROTOCOL._fields_ = [
    ('Open', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)))),
    ('Close', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)))),
    ('Lock', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)))),
    ('GetCapabilities', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL), POINTER_T(ctypes.c_uint64), POINTER_T(struct_EFI_MMRAM_DESCRIPTOR)))),
    ('LockState', ctypes.c_ubyte),
    ('OpenState', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 6),
]

struct__EFI_MM_ACCESS_PROTOCOL._functions_.append(("Open",['ctypes.c_uint64', 'POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)']))
struct__EFI_MM_ACCESS_PROTOCOL._functions_.append(("Close",['ctypes.c_uint64', 'POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)']))
struct__EFI_MM_ACCESS_PROTOCOL._functions_.append(("Lock",['ctypes.c_uint64', 'POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)']))
struct__EFI_MM_ACCESS_PROTOCOL._functions_.append(("GetCapabilities",['ctypes.c_uint64', 'POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(struct_EFI_MMRAM_DESCRIPTOR)']))
_EFI_MM_ACCESS_PROTOCOL = struct__EFI_MM_ACCESS_PROTOCOL
P_EFI_MM_ACCESS_PROTOCOL = POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
UINT64 = ctypes.c_uint64
UINTN = ctypes.c_uint64
RETURN_STATUS = ctypes.c_uint64
EFI_STATUS = ctypes.c_uint64
EFI_MM_ACCESS_PROTOCOL = struct__EFI_MM_ACCESS_PROTOCOL
EFI_MM_OPEN = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)))
EFI_MM_CLOSE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)))
EFI_MM_LOCK = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)))
struct_EFI_MMRAM_DESCRIPTOR._pack_ = True # source:False
struct_EFI_MMRAM_DESCRIPTOR._functions_ = []
struct_EFI_MMRAM_DESCRIPTOR._fields_ = [
    ('PhysicalStart', ctypes.c_uint64),
    ('CpuStart', ctypes.c_uint64),
    ('PhysicalSize', ctypes.c_uint64),
    ('RegionState', ctypes.c_uint64),
]

EFI_MMRAM_DESCRIPTOR = struct_EFI_MMRAM_DESCRIPTOR
PEFI_MMRAM_DESCRIPTOR = POINTER_T(struct_EFI_MMRAM_DESCRIPTOR)
EFI_MM_CAPABILITIES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL), POINTER_T(ctypes.c_uint64), POINTER_T(struct_EFI_MMRAM_DESCRIPTOR)))
BOOLEAN = ctypes.c_ubyte
EFI_PHYSICAL_ADDRESS = ctypes.c_uint64
__all__ = \
    ['BOOLEAN', 'EFI_MMRAM_DESCRIPTOR', 'EFI_MM_ACCESS_PROTOCOL',
    'EFI_MM_CAPABILITIES', 'EFI_MM_CLOSE', 'EFI_MM_LOCK',
    'EFI_MM_OPEN', 'EFI_PHYSICAL_ADDRESS', 'EFI_STATUS',
    'ImageBaseOffset32', 'PEFI_MMRAM_DESCRIPTOR',
    'P_EFI_MM_ACCESS_PROTOCOL', 'RETURN_STATUS', 'UINT64', 'UINTN',
    '_EFI_MM_ACCESS_PROTOCOL', 'byte', 'dword', 'longlong', 'qword',
    'struct_EFI_MMRAM_DESCRIPTOR', 'struct__EFI_MM_ACCESS_PROTOCOL',
    'uchar', 'uint', 'ulonglong', 'undefined', 'undefined1',
    'undefined2', 'undefined4', 'undefined8', 'ushort', 'word']

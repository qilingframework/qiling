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
byte = ctypes.c_ubyte
dword = ctypes.c_uint32
qword = ctypes.c_uint64
uchar = ctypes.c_ubyte
uint = ctypes.c_uint32
ulong = ctypes.c_uint64
ulonglong = ctypes.c_uint64
undefined1 = ctypes.c_ubyte
undefined2 = ctypes.c_uint16
undefined4 = ctypes.c_uint32
ushort = ctypes.c_uint16
word = ctypes.c_uint16
class struct__EFI_PCD_PROTOCOL(ctypes.Structure):
    pass

class struct_EFI_GUID(ctypes.Structure):
    pass

struct__EFI_PCD_PROTOCOL._pack_ = True # source:False
struct__EFI_PCD_PROTOCOL._functions_ = []
struct__EFI_PCD_PROTOCOL._fields_ = [
    ('SetSku', POINTER_T(ctypes.CFUNCTYPE(None, ctypes.c_uint64))),
    ('Get8', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_ubyte, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('Get16', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint16, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('Get32', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint32, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('Get64', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('GetPtr', POINTER_T(ctypes.CFUNCTYPE(POINTER_T(None), POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('GetBool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_ubyte, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('GetSize', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))),
    ('Set8', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_ubyte))),
    ('Set16', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_uint16))),
    ('Set32', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_uint32))),
    ('Set64', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_uint64))),
    ('SetPtr', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(None)))),
    ('SetBool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_ubyte))),
    ('CallbackOnSet', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))))),
    ('CancelCallback', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))))),
    ('GetNextToken', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), POINTER_T(ctypes.c_uint64)))),
    ('GetNextTokenSpace', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(struct_EFI_GUID))))),
]

struct__EFI_PCD_PROTOCOL._functions_.append(("SetSku",['None', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Get8",['ctypes.c_ubyte', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Get16",['ctypes.c_uint16', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Get32",['ctypes.c_uint32', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Get64",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("GetPtr",['POINTER_T(None)', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("GetBool",['ctypes.c_ubyte', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("GetSize",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Set8",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'ctypes.c_ubyte']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Set16",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'ctypes.c_uint16']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Set32",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'ctypes.c_uint32']))
struct__EFI_PCD_PROTOCOL._functions_.append(("Set64",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct__EFI_PCD_PROTOCOL._functions_.append(("SetPtr",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(None)']))
struct__EFI_PCD_PROTOCOL._functions_.append(("SetBool",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'ctypes.c_ubyte']))
struct__EFI_PCD_PROTOCOL._functions_.append(("CallbackOnSet",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))']))
struct__EFI_PCD_PROTOCOL._functions_.append(("CancelCallback",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'ctypes.c_uint64', 'POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))']))
struct__EFI_PCD_PROTOCOL._functions_.append(("GetNextToken",['ctypes.c_uint64', 'POINTER_T(struct_EFI_GUID)', 'POINTER_T(ctypes.c_uint64)']))
struct__EFI_PCD_PROTOCOL._functions_.append(("GetNextTokenSpace",['ctypes.c_uint64', 'POINTER_T(POINTER_T(struct_EFI_GUID))']))
_EFI_PCD_PROTOCOL = struct__EFI_PCD_PROTOCOL
P_EFI_PCD_PROTOCOL = POINTER_T(struct__EFI_PCD_PROTOCOL)
UINT64 = ctypes.c_uint64
UINTN = ctypes.c_uint64
EFI_PCD_PROTOCOL_SET_SKU = POINTER_T(ctypes.CFUNCTYPE(None, ctypes.c_uint64))
UINT8 = ctypes.c_ubyte
struct_EFI_GUID._pack_ = True # source:False
struct_EFI_GUID._functions_ = []
struct_EFI_GUID._fields_ = [
    ('Data1', ctypes.c_uint32),
    ('Data2', ctypes.c_uint16),
    ('Data3', ctypes.c_uint16),
    ('Data4', ctypes.c_ubyte * 8),
]

EFI_GUID = struct_EFI_GUID
PEFI_GUID = POINTER_T(struct_EFI_GUID)
EFI_PCD_PROTOCOL_GET_8 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_ubyte, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
UINT16 = ctypes.c_uint16
EFI_PCD_PROTOCOL_GET_16 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint16, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
UINT32 = ctypes.c_uint32
EFI_PCD_PROTOCOL_GET_32 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint32, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
EFI_PCD_PROTOCOL_GET_64 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
EFI_PCD_PROTOCOL_GET_POINTER = POINTER_T(ctypes.CFUNCTYPE(POINTER_T(None), POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
BOOLEAN = ctypes.c_ubyte
EFI_PCD_PROTOCOL_GET_BOOLEAN = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_ubyte, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
EFI_PCD_PROTOCOL_GET_SIZE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64))
RETURN_STATUS = ctypes.c_uint64
EFI_STATUS = ctypes.c_uint64
EFI_PCD_PROTOCOL_SET_8 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_ubyte))
EFI_PCD_PROTOCOL_SET_16 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_uint16))
EFI_PCD_PROTOCOL_SET_32 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_uint32))
EFI_PCD_PROTOCOL_SET_64 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_uint64))
EFI_PCD_PROTOCOL_SET_POINTER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(None)))
EFI_PCD_PROTOCOL_SET_BOOLEAN = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, ctypes.c_ubyte))
EFI_PCD_PROTOCOL_CALLBACK = POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))
EFI_PCD_PROTOCOL_CALLBACK_ON_SET = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))))
EFI_PCD_PROTOCOL_CANCEL_CALLBACK = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(struct_EFI_GUID), ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))))
EFI_PCD_PROTOCOL_GET_NEXT_TOKEN = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_GUID), POINTER_T(ctypes.c_uint64)))
EFI_PCD_PROTOCOL_GET_NEXT_TOKEN_SPACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(struct_EFI_GUID))))
EFI_PCD_PROTOCOL = struct__EFI_PCD_PROTOCOL
__all__ = \
    ['BOOLEAN', 'EFI_GUID', 'EFI_PCD_PROTOCOL',
    'EFI_PCD_PROTOCOL_CALLBACK', 'EFI_PCD_PROTOCOL_CALLBACK_ON_SET',
    'EFI_PCD_PROTOCOL_CANCEL_CALLBACK', 'EFI_PCD_PROTOCOL_GET_16',
    'EFI_PCD_PROTOCOL_GET_32', 'EFI_PCD_PROTOCOL_GET_64',
    'EFI_PCD_PROTOCOL_GET_8', 'EFI_PCD_PROTOCOL_GET_BOOLEAN',
    'EFI_PCD_PROTOCOL_GET_NEXT_TOKEN',
    'EFI_PCD_PROTOCOL_GET_NEXT_TOKEN_SPACE',
    'EFI_PCD_PROTOCOL_GET_POINTER', 'EFI_PCD_PROTOCOL_GET_SIZE',
    'EFI_PCD_PROTOCOL_SET_16', 'EFI_PCD_PROTOCOL_SET_32',
    'EFI_PCD_PROTOCOL_SET_64', 'EFI_PCD_PROTOCOL_SET_8',
    'EFI_PCD_PROTOCOL_SET_BOOLEAN', 'EFI_PCD_PROTOCOL_SET_POINTER',
    'EFI_PCD_PROTOCOL_SET_SKU', 'EFI_STATUS', 'PEFI_GUID',
    'P_EFI_PCD_PROTOCOL', 'RETURN_STATUS', 'UINT16', 'UINT32',
    'UINT64', 'UINT8', 'UINTN', '_EFI_PCD_PROTOCOL', 'byte', 'dword',
    'qword', 'struct_EFI_GUID', 'struct__EFI_PCD_PROTOCOL', 'uchar',
    'uint', 'ulong', 'ulonglong', 'undefined', 'undefined1',
    'undefined2', 'undefined4', 'ushort', 'word']

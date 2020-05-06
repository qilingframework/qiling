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
ulonglong = ctypes.c_uint64
undefined1 = ctypes.c_ubyte
undefined2 = ctypes.c_uint16
undefined4 = ctypes.c_uint32
undefined8 = ctypes.c_uint64
ushort = ctypes.c_uint16
word = ctypes.c_uint16
EFI_EVENT = POINTER_T(None)
class struct_GUID(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Data1', ctypes.c_uint32),
    ('Data2', ctypes.c_uint16),
    ('Data3', ctypes.c_uint16),
    ('Data4', ctypes.c_ubyte * 8),
     ]

GUID = struct_GUID
PGUID = POINTER_T(struct_GUID)
EFI_GUID = struct_GUID
UINT32 = ctypes.c_uint32
UINT16 = ctypes.c_uint16
UINT8 = ctypes.c_ubyte
EFI_HANDLE = POINTER_T(None)
class union_EFI_IP_ADDRESS(ctypes.Union):
    pass

class struct_EFI_IPv4_ADDRESS(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Addr', ctypes.c_ubyte * 4),
     ]

class struct_EFI_IPv6_ADDRESS(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Addr', ctypes.c_ubyte * 16),
     ]

union_EFI_IP_ADDRESS._pack_ = True # source:False
union_EFI_IP_ADDRESS._functions_ = []
union_EFI_IP_ADDRESS._fields_ = [
    ('Addr', ctypes.c_uint32 * 4),
    ('v4', struct_EFI_IPv4_ADDRESS),
    ('v6', struct_EFI_IPv6_ADDRESS),
]

EFI_IP_ADDRESS = union_EFI_IP_ADDRESS
PEFI_IP_ADDRESS = POINTER_T(union_EFI_IP_ADDRESS)
EFI_IPv4_ADDRESS = struct_EFI_IPv4_ADDRESS
PEFI_IPv4_ADDRESS = POINTER_T(struct_EFI_IPv4_ADDRESS)
EFI_IPv6_ADDRESS = struct_EFI_IPv6_ADDRESS
PEFI_IPv6_ADDRESS = POINTER_T(struct_EFI_IPv6_ADDRESS)
UINT64 = ctypes.c_uint64
EFI_LBA = ctypes.c_uint64
class struct_EFI_MAC_ADDRESS(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Addr', ctypes.c_ubyte * 32),
     ]

EFI_MAC_ADDRESS = struct_EFI_MAC_ADDRESS
PEFI_MAC_ADDRESS = POINTER_T(struct_EFI_MAC_ADDRESS)
EFI_PHYSICAL_ADDRESS = ctypes.c_uint64
UINTN = ctypes.c_uint64
RETURN_STATUS = ctypes.c_uint64
EFI_STATUS = ctypes.c_uint64
class struct_EFI_TIME(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Year', ctypes.c_uint16),
    ('Month', ctypes.c_ubyte),
    ('Day', ctypes.c_ubyte),
    ('Hour', ctypes.c_ubyte),
    ('Minute', ctypes.c_ubyte),
    ('Second', ctypes.c_ubyte),
    ('Pad1', ctypes.c_ubyte),
    ('Nanosecond', ctypes.c_uint32),
    ('TimeZone', ctypes.c_int16),
    ('Daylight', ctypes.c_ubyte),
    ('Pad2', ctypes.c_ubyte),
     ]

EFI_TIME = struct_EFI_TIME
PEFI_TIME = POINTER_T(struct_EFI_TIME)
INT16 = ctypes.c_int16
EFI_TPL = ctypes.c_uint64
EFI_VIRTUAL_ADDRESS = ctypes.c_uint64
class struct_EFI_PARTITION_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('PartitionTypeGUID', EFI_GUID),
    ('UniquePartitionGUID', EFI_GUID),
    ('StartingLBA', ctypes.c_uint64),
    ('EndingLBA', ctypes.c_uint64),
    ('Attributes', ctypes.c_uint64),
    ('PartitionName', ctypes.c_uint16 * 36),
     ]

EFI_PARTITION_ENTRY = struct_EFI_PARTITION_ENTRY
PEFI_PARTITION_ENTRY = POINTER_T(struct_EFI_PARTITION_ENTRY)
CHAR16 = ctypes.c_uint16
class struct_EFI_PARTITION_TABLE_HEADER(ctypes.Structure):
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

struct_EFI_PARTITION_TABLE_HEADER._pack_ = True # source:False
struct_EFI_PARTITION_TABLE_HEADER._functions_ = []
struct_EFI_PARTITION_TABLE_HEADER._fields_ = [
    ('Header', struct_EFI_TABLE_HEADER),
    ('MyLBA', ctypes.c_uint64),
    ('AlternateLBA', ctypes.c_uint64),
    ('FirstUsableLBA', ctypes.c_uint64),
    ('LastUsableLBA', ctypes.c_uint64),
    ('DiskGUID', EFI_GUID),
    ('PartitionEntryLBA', ctypes.c_uint64),
    ('NumberOfPartitionEntries', ctypes.c_uint32),
    ('SizeOfPartitionEntry', ctypes.c_uint32),
    ('PartitionEntryArrayCRC32', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

EFI_PARTITION_TABLE_HEADER = struct_EFI_PARTITION_TABLE_HEADER
PEFI_PARTITION_TABLE_HEADER = POINTER_T(struct_EFI_PARTITION_TABLE_HEADER)
EFI_TABLE_HEADER = struct_EFI_TABLE_HEADER
PEFI_TABLE_HEADER = POINTER_T(struct_EFI_TABLE_HEADER)
class struct__EFI_GLYPH_GIBT_END_BLOCK(ctypes.Structure):
    pass

class struct__EFI_HII_GLYPH_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BlockType', ctypes.c_ubyte),
     ]

EFI_HII_GLYPH_BLOCK = struct__EFI_HII_GLYPH_BLOCK
struct__EFI_GLYPH_GIBT_END_BLOCK._pack_ = True # source:False
struct__EFI_GLYPH_GIBT_END_BLOCK._functions_ = []
struct__EFI_GLYPH_GIBT_END_BLOCK._fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
]

_EFI_GLYPH_GIBT_END_BLOCK = struct__EFI_GLYPH_GIBT_END_BLOCK
P_EFI_GLYPH_GIBT_END_BLOCK = POINTER_T(struct__EFI_GLYPH_GIBT_END_BLOCK)
_EFI_HII_GLYPH_BLOCK = struct__EFI_HII_GLYPH_BLOCK
P_EFI_HII_GLYPH_BLOCK = POINTER_T(struct__EFI_HII_GLYPH_BLOCK)
class struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK(ctypes.Structure):
    pass

class struct__EFI_HII_ANIMATION_CELL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('OffsetX', ctypes.c_uint16),
    ('OffsetY', ctypes.c_uint16),
    ('ImageId', ctypes.c_uint16),
    ('Delay', ctypes.c_uint16),
     ]

class struct__EFI_HII_RGB_PIXEL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('b', ctypes.c_ubyte),
    ('g', ctypes.c_ubyte),
    ('r', ctypes.c_ubyte),
     ]

EFI_HII_RGB_PIXEL = struct__EFI_HII_RGB_PIXEL
struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK._pack_ = True # source:False
struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK._functions_ = []
struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK._fields_ = [
    ('DftImageId', ctypes.c_uint16),
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('CellCount', ctypes.c_uint16),
    ('BackgndColor', EFI_HII_RGB_PIXEL),
    ('PADDING_0', ctypes.c_ubyte),
    ('AnimationCell', struct__EFI_HII_ANIMATION_CELL * 1),
]

_EFI_HII_AIBT_CLEAR_IMAGES_BLOCK = struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK
P_EFI_HII_AIBT_CLEAR_IMAGES_BLOCK = POINTER_T(struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK)
EFI_IMAGE_ID = ctypes.c_uint16
_EFI_HII_RGB_PIXEL = struct__EFI_HII_RGB_PIXEL
P_EFI_HII_RGB_PIXEL = POINTER_T(struct__EFI_HII_RGB_PIXEL)
_EFI_HII_ANIMATION_CELL = struct__EFI_HII_ANIMATION_CELL
P_EFI_HII_ANIMATION_CELL = POINTER_T(struct__EFI_HII_ANIMATION_CELL)
EFI_HII_ANIMATION_CELL = struct__EFI_HII_ANIMATION_CELL
class struct__EFI_HII_AIBT_DUPLICATE_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('AnimationId', ctypes.c_uint16),
     ]

_EFI_HII_AIBT_DUPLICATE_BLOCK = struct__EFI_HII_AIBT_DUPLICATE_BLOCK
P_EFI_HII_AIBT_DUPLICATE_BLOCK = POINTER_T(struct__EFI_HII_AIBT_DUPLICATE_BLOCK)
EFI_ANIMATION_ID = ctypes.c_uint16
class struct__EFI_HII_AIBT_EXT1_BLOCK(ctypes.Structure):
    pass

class struct__EFI_HII_ANIMATION_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BlockType', ctypes.c_ubyte),
     ]

EFI_HII_ANIMATION_BLOCK = struct__EFI_HII_ANIMATION_BLOCK
struct__EFI_HII_AIBT_EXT1_BLOCK._pack_ = True # source:False
struct__EFI_HII_AIBT_EXT1_BLOCK._functions_ = []
struct__EFI_HII_AIBT_EXT1_BLOCK._fields_ = [
    ('Header', EFI_HII_ANIMATION_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte),
]

_EFI_HII_AIBT_EXT1_BLOCK = struct__EFI_HII_AIBT_EXT1_BLOCK
P_EFI_HII_AIBT_EXT1_BLOCK = POINTER_T(struct__EFI_HII_AIBT_EXT1_BLOCK)
_EFI_HII_ANIMATION_BLOCK = struct__EFI_HII_ANIMATION_BLOCK
P_EFI_HII_ANIMATION_BLOCK = POINTER_T(struct__EFI_HII_ANIMATION_BLOCK)
class struct__EFI_HII_AIBT_EXT2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_ANIMATION_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_uint16),
     ]

_EFI_HII_AIBT_EXT2_BLOCK = struct__EFI_HII_AIBT_EXT2_BLOCK
P_EFI_HII_AIBT_EXT2_BLOCK = POINTER_T(struct__EFI_HII_AIBT_EXT2_BLOCK)
class struct__EFI_HII_AIBT_EXT4_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_ANIMATION_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Length', ctypes.c_uint32),
     ]

_EFI_HII_AIBT_EXT4_BLOCK = struct__EFI_HII_AIBT_EXT4_BLOCK
P_EFI_HII_AIBT_EXT4_BLOCK = POINTER_T(struct__EFI_HII_AIBT_EXT4_BLOCK)
class struct__EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('DftImageId', ctypes.c_uint16),
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('CellCount', ctypes.c_uint16),
    ('AnimationCell', struct__EFI_HII_ANIMATION_CELL * 1),
     ]

_EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK = struct__EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK
P_EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK = POINTER_T(struct__EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK)
class struct__EFI_HII_AIBT_RESTORE_SCRN_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('DftImageId', ctypes.c_uint16),
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('CellCount', ctypes.c_uint16),
    ('AnimationCell', struct__EFI_HII_ANIMATION_CELL * 1),
     ]

_EFI_HII_AIBT_RESTORE_SCRN_BLOCK = struct__EFI_HII_AIBT_RESTORE_SCRN_BLOCK
P_EFI_HII_AIBT_RESTORE_SCRN_BLOCK = POINTER_T(struct__EFI_HII_AIBT_RESTORE_SCRN_BLOCK)
class struct__EFI_HII_AIBT_SKIP1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('SkipCount', ctypes.c_ubyte),
     ]

_EFI_HII_AIBT_SKIP1_BLOCK = struct__EFI_HII_AIBT_SKIP1_BLOCK
P_EFI_HII_AIBT_SKIP1_BLOCK = POINTER_T(struct__EFI_HII_AIBT_SKIP1_BLOCK)
class struct__EFI_HII_AIBT_SKIP2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('SkipCount', ctypes.c_uint16),
     ]

_EFI_HII_AIBT_SKIP2_BLOCK = struct__EFI_HII_AIBT_SKIP2_BLOCK
P_EFI_HII_AIBT_SKIP2_BLOCK = POINTER_T(struct__EFI_HII_AIBT_SKIP2_BLOCK)
class struct__EFI_HII_ANIMATION_PACKAGE_HDR(ctypes.Structure):
    pass

class struct_EFI_HII_PACKAGE_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Length', ctypes.c_uint32, 24),
    ('Type', ctypes.c_uint32, 8),
     ]

struct__EFI_HII_ANIMATION_PACKAGE_HDR._pack_ = True # source:False
struct__EFI_HII_ANIMATION_PACKAGE_HDR._functions_ = []
struct__EFI_HII_ANIMATION_PACKAGE_HDR._fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('AnimationInfoOffset', ctypes.c_uint32),
]

_EFI_HII_ANIMATION_PACKAGE_HDR = struct__EFI_HII_ANIMATION_PACKAGE_HDR
P_EFI_HII_ANIMATION_PACKAGE_HDR = POINTER_T(struct__EFI_HII_ANIMATION_PACKAGE_HDR)
EFI_HII_PACKAGE_HEADER = struct_EFI_HII_PACKAGE_HEADER
PEFI_HII_PACKAGE_HEADER = POINTER_T(struct_EFI_HII_PACKAGE_HEADER)
class struct__EFI_HII_DEVICE_PATH_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
     ]

_EFI_HII_DEVICE_PATH_PACKAGE_HDR = struct__EFI_HII_DEVICE_PATH_PACKAGE_HDR
P_EFI_HII_DEVICE_PATH_PACKAGE_HDR = POINTER_T(struct__EFI_HII_DEVICE_PATH_PACKAGE_HDR)
class struct__EFI_HII_FONT_PACKAGE_HDR(ctypes.Structure):
    pass

class struct__EFI_HII_GLYPH_INFO(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('OffsetX', ctypes.c_int16),
    ('OffsetY', ctypes.c_int16),
    ('AdvanceX', ctypes.c_int16),
     ]

EFI_HII_GLYPH_INFO = struct__EFI_HII_GLYPH_INFO
struct__EFI_HII_FONT_PACKAGE_HDR._pack_ = True # source:False
struct__EFI_HII_FONT_PACKAGE_HDR._functions_ = []
struct__EFI_HII_FONT_PACKAGE_HDR._fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('HdrSize', ctypes.c_uint32),
    ('GlyphBlockOffset', ctypes.c_uint32),
    ('Cell', EFI_HII_GLYPH_INFO),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('FontStyle', ctypes.c_uint32),
    ('FontFamily', ctypes.c_uint16 * 1),
    ('PADDING_1', ctypes.c_ubyte * 2),
]

_EFI_HII_FONT_PACKAGE_HDR = struct__EFI_HII_FONT_PACKAGE_HDR
P_EFI_HII_FONT_PACKAGE_HDR = POINTER_T(struct__EFI_HII_FONT_PACKAGE_HDR)
_EFI_HII_GLYPH_INFO = struct__EFI_HII_GLYPH_INFO
P_EFI_HII_GLYPH_INFO = POINTER_T(struct__EFI_HII_GLYPH_INFO)
EFI_HII_FONT_STYLE = ctypes.c_uint32
class struct__EFI_HII_FORM_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
     ]

_EFI_HII_FORM_PACKAGE_HDR = struct__EFI_HII_FORM_PACKAGE_HDR
P_EFI_HII_FORM_PACKAGE_HDR = POINTER_T(struct__EFI_HII_FORM_PACKAGE_HDR)
class struct__EFI_HII_GIBT_DEFAULTS_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('Cell', EFI_HII_GLYPH_INFO),
     ]

_EFI_HII_GIBT_DEFAULTS_BLOCK = struct__EFI_HII_GIBT_DEFAULTS_BLOCK
P_EFI_HII_GIBT_DEFAULTS_BLOCK = POINTER_T(struct__EFI_HII_GIBT_DEFAULTS_BLOCK)
class struct__EFI_HII_GIBT_DUPLICATE_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('CharValue', ctypes.c_uint16),
     ]

_EFI_HII_GIBT_DUPLICATE_BLOCK = struct__EFI_HII_GIBT_DUPLICATE_BLOCK
P_EFI_HII_GIBT_DUPLICATE_BLOCK = POINTER_T(struct__EFI_HII_GIBT_DUPLICATE_BLOCK)
class struct__EFI_HII_GIBT_EXT1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte),
     ]

_EFI_HII_GIBT_EXT1_BLOCK = struct__EFI_HII_GIBT_EXT1_BLOCK
P_EFI_HII_GIBT_EXT1_BLOCK = POINTER_T(struct__EFI_HII_GIBT_EXT1_BLOCK)
class struct__EFI_HII_GIBT_EXT2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_uint16),
     ]

_EFI_HII_GIBT_EXT2_BLOCK = struct__EFI_HII_GIBT_EXT2_BLOCK
P_EFI_HII_GIBT_EXT2_BLOCK = POINTER_T(struct__EFI_HII_GIBT_EXT2_BLOCK)
class struct__EFI_HII_GIBT_EXT4_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Length', ctypes.c_uint32),
     ]

_EFI_HII_GIBT_EXT4_BLOCK = struct__EFI_HII_GIBT_EXT4_BLOCK
P_EFI_HII_GIBT_EXT4_BLOCK = POINTER_T(struct__EFI_HII_GIBT_EXT4_BLOCK)
class struct__EFI_HII_GIBT_GLYPH_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('Cell', EFI_HII_GLYPH_INFO),
    ('BitmapData', ctypes.c_ubyte * 1),
    ('PADDING_1', ctypes.c_ubyte),
     ]

_EFI_HII_GIBT_GLYPH_BLOCK = struct__EFI_HII_GIBT_GLYPH_BLOCK
P_EFI_HII_GIBT_GLYPH_BLOCK = POINTER_T(struct__EFI_HII_GIBT_GLYPH_BLOCK)
class struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK(ctypes.Structure):
    pass

P_EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK = POINTER_T(struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK)
struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK._pack_ = True # source:False
struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK._functions_ = []
struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK._fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('BitmapData', ctypes.c_ubyte * 1),
]

_EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK = struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK
class struct__EFI_HII_GIBT_GLYPHS_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('Cell', EFI_HII_GLYPH_INFO),
    ('Count', ctypes.c_uint16),
    ('BitmapData', ctypes.c_ubyte * 1),
    ('PADDING_1', ctypes.c_ubyte),
     ]

_EFI_HII_GIBT_GLYPHS_BLOCK = struct__EFI_HII_GIBT_GLYPHS_BLOCK
P_EFI_HII_GIBT_GLYPHS_BLOCK = POINTER_T(struct__EFI_HII_GIBT_GLYPHS_BLOCK)
class struct__EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('Count', ctypes.c_uint16),
    ('BitmapData', ctypes.c_ubyte * 1),
    ('PADDING_1', ctypes.c_ubyte),
     ]

_EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK = struct__EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK
P_EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK = POINTER_T(struct__EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK)
class struct__EFI_HII_GIBT_SKIP1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('SkipCount', ctypes.c_ubyte),
     ]

_EFI_HII_GIBT_SKIP1_BLOCK = struct__EFI_HII_GIBT_SKIP1_BLOCK
P_EFI_HII_GIBT_SKIP1_BLOCK = POINTER_T(struct__EFI_HII_GIBT_SKIP1_BLOCK)
class struct__EFI_HII_GIBT_SKIP2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_GLYPH_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('SkipCount', ctypes.c_uint16),
     ]

_EFI_HII_GIBT_SKIP2_BLOCK = struct__EFI_HII_GIBT_SKIP2_BLOCK
P_EFI_HII_GIBT_SKIP2_BLOCK = POINTER_T(struct__EFI_HII_GIBT_SKIP2_BLOCK)
class struct__EFI_HII_GUID_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('Guid', EFI_GUID),
     ]

_EFI_HII_GUID_PACKAGE_HDR = struct__EFI_HII_GUID_PACKAGE_HDR
P_EFI_HII_GUID_PACKAGE_HDR = POINTER_T(struct__EFI_HII_GUID_PACKAGE_HDR)
class struct__EFI_HII_IIBT_DUPLICATE_BLOCK(ctypes.Structure):
    pass

class struct__EFI_HII_IMAGE_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BlockType', ctypes.c_ubyte),
     ]

EFI_HII_IMAGE_BLOCK = struct__EFI_HII_IMAGE_BLOCK
struct__EFI_HII_IIBT_DUPLICATE_BLOCK._pack_ = True # source:False
struct__EFI_HII_IIBT_DUPLICATE_BLOCK._functions_ = []
struct__EFI_HII_IIBT_DUPLICATE_BLOCK._fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('ImageId', ctypes.c_uint16),
]

_EFI_HII_IIBT_DUPLICATE_BLOCK = struct__EFI_HII_IIBT_DUPLICATE_BLOCK
P_EFI_HII_IIBT_DUPLICATE_BLOCK = POINTER_T(struct__EFI_HII_IIBT_DUPLICATE_BLOCK)
_EFI_HII_IMAGE_BLOCK = struct__EFI_HII_IMAGE_BLOCK
P_EFI_HII_IMAGE_BLOCK = POINTER_T(struct__EFI_HII_IMAGE_BLOCK)
class struct__EFI_HII_IIBT_END_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
     ]

_EFI_HII_IIBT_END_BLOCK = struct__EFI_HII_IIBT_END_BLOCK
P_EFI_HII_IIBT_END_BLOCK = POINTER_T(struct__EFI_HII_IIBT_END_BLOCK)
class struct__EFI_HII_IIBT_EXT1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte),
     ]

_EFI_HII_IIBT_EXT1_BLOCK = struct__EFI_HII_IIBT_EXT1_BLOCK
P_EFI_HII_IIBT_EXT1_BLOCK = POINTER_T(struct__EFI_HII_IIBT_EXT1_BLOCK)
class struct__EFI_HII_IIBT_EXT2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_uint16),
     ]

_EFI_HII_IIBT_EXT2_BLOCK = struct__EFI_HII_IIBT_EXT2_BLOCK
P_EFI_HII_IIBT_EXT2_BLOCK = POINTER_T(struct__EFI_HII_IIBT_EXT2_BLOCK)
class struct__EFI_HII_IIBT_EXT4_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Length', ctypes.c_uint32),
     ]

_EFI_HII_IIBT_EXT4_BLOCK = struct__EFI_HII_IIBT_EXT4_BLOCK
P_EFI_HII_IIBT_EXT4_BLOCK = POINTER_T(struct__EFI_HII_IIBT_EXT4_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_1BIT_BASE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('Data', ctypes.c_ubyte * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_IIBT_IMAGE_1BIT_BASE = struct__EFI_HII_IIBT_IMAGE_1BIT_BASE
P_EFI_HII_IIBT_IMAGE_1BIT_BASE = POINTER_T(struct__EFI_HII_IIBT_IMAGE_1BIT_BASE)
class struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK(ctypes.Structure):
    pass

EFI_HII_IIBT_IMAGE_1BIT_BASE = struct__EFI_HII_IIBT_IMAGE_1BIT_BASE
struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK._pack_ = True # source:False
struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK._functions_ = []
struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK._fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PaletteIndex', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_1BIT_BASE),
]

_EFI_HII_IIBT_IMAGE_1BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK
P_EFI_HII_IIBT_IMAGE_1BIT_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PaletteIndex', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_1BIT_BASE),
     ]

_EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK
P_EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_24BIT_BASE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('Bitmap', struct__EFI_HII_RGB_PIXEL * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_IIBT_IMAGE_24BIT_BASE = struct__EFI_HII_IIBT_IMAGE_24BIT_BASE
P_EFI_HII_IIBT_IMAGE_24BIT_BASE = POINTER_T(struct__EFI_HII_IIBT_IMAGE_24BIT_BASE)
class struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK(ctypes.Structure):
    pass

EFI_HII_IIBT_IMAGE_24BIT_BASE = struct__EFI_HII_IIBT_IMAGE_24BIT_BASE
struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK._pack_ = True # source:False
struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK._functions_ = []
struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK._fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_24BIT_BASE),
]

_EFI_HII_IIBT_IMAGE_24BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK
P_EFI_HII_IIBT_IMAGE_24BIT_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_24BIT_BASE),
     ]

_EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK
P_EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_4BIT_BASE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('Data', ctypes.c_ubyte * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_IIBT_IMAGE_4BIT_BASE = struct__EFI_HII_IIBT_IMAGE_4BIT_BASE
P_EFI_HII_IIBT_IMAGE_4BIT_BASE = POINTER_T(struct__EFI_HII_IIBT_IMAGE_4BIT_BASE)
class struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK(ctypes.Structure):
    pass

EFI_HII_IIBT_IMAGE_4BIT_BASE = struct__EFI_HII_IIBT_IMAGE_4BIT_BASE
struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK._pack_ = True # source:False
struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK._functions_ = []
struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK._fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PaletteIndex', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_4BIT_BASE),
]

_EFI_HII_IIBT_IMAGE_4BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK
P_EFI_HII_IIBT_IMAGE_4BIT_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PaletteIndex', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_4BIT_BASE),
     ]

_EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK
P_EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_8BIT_BASE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Width', ctypes.c_uint16),
    ('Height', ctypes.c_uint16),
    ('Data', ctypes.c_ubyte * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_IIBT_IMAGE_8BIT_BASE = struct__EFI_HII_IIBT_IMAGE_8BIT_BASE
P_EFI_HII_IIBT_IMAGE_8BIT_BASE = POINTER_T(struct__EFI_HII_IIBT_IMAGE_8BIT_BASE)
class struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK(ctypes.Structure):
    pass

EFI_HII_IIBT_IMAGE_8BIT_BASE = struct__EFI_HII_IIBT_IMAGE_8BIT_BASE
struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK._pack_ = True # source:False
struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK._functions_ = []
struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK._fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PaletteIndex', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_8BIT_BASE),
]

_EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK = struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK
P_EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK)
class struct__EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PaletteIndex', ctypes.c_ubyte),
    ('Bitmap', EFI_HII_IIBT_IMAGE_8BIT_BASE),
     ]

_EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK
P_EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK = POINTER_T(struct__EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK)
class struct__EFI_HII_IIBT_JPEG_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('Size', ctypes.c_uint32),
    ('Data', ctypes.c_ubyte * 1),
    ('PADDING_1', ctypes.c_ubyte * 3),
     ]

_EFI_HII_IIBT_JPEG_BLOCK = struct__EFI_HII_IIBT_JPEG_BLOCK
P_EFI_HII_IIBT_JPEG_BLOCK = POINTER_T(struct__EFI_HII_IIBT_JPEG_BLOCK)
class struct__EFI_HII_IIBT_SKIP1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('SkipCount', ctypes.c_ubyte),
     ]

_EFI_HII_IIBT_SKIP1_BLOCK = struct__EFI_HII_IIBT_SKIP1_BLOCK
P_EFI_HII_IIBT_SKIP1_BLOCK = POINTER_T(struct__EFI_HII_IIBT_SKIP1_BLOCK)
class struct__EFI_HII_IIBT_SKIP2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_HII_IMAGE_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('SkipCount', ctypes.c_uint16),
     ]

_EFI_HII_IIBT_SKIP2_BLOCK = struct__EFI_HII_IIBT_SKIP2_BLOCK
P_EFI_HII_IIBT_SKIP2_BLOCK = POINTER_T(struct__EFI_HII_IIBT_SKIP2_BLOCK)
class struct__EFI_HII_IMAGE_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('ImageInfoOffset', ctypes.c_uint32),
    ('PaletteInfoOffset', ctypes.c_uint32),
     ]

_EFI_HII_IMAGE_PACKAGE_HDR = struct__EFI_HII_IMAGE_PACKAGE_HDR
P_EFI_HII_IMAGE_PACKAGE_HDR = POINTER_T(struct__EFI_HII_IMAGE_PACKAGE_HDR)
class struct__EFI_HII_IMAGE_PALETTE_INFO(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('PaletteSize', ctypes.c_uint16),
    ('PaletteValue', struct__EFI_HII_RGB_PIXEL * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_IMAGE_PALETTE_INFO = struct__EFI_HII_IMAGE_PALETTE_INFO
P_EFI_HII_IMAGE_PALETTE_INFO = POINTER_T(struct__EFI_HII_IMAGE_PALETTE_INFO)
class struct__EFI_HII_IMAGE_PALETTE_INFO_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('PaletteCount', ctypes.c_uint16),
     ]

_EFI_HII_IMAGE_PALETTE_INFO_HEADER = struct__EFI_HII_IMAGE_PALETTE_INFO_HEADER
P_EFI_HII_IMAGE_PALETTE_INFO_HEADER = POINTER_T(struct__EFI_HII_IMAGE_PALETTE_INFO_HEADER)
class struct__EFI_HII_SIBT_DUPLICATE_BLOCK(ctypes.Structure):
    pass

class struct_EFI_HII_STRING_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BlockType', ctypes.c_ubyte),
     ]

struct__EFI_HII_SIBT_DUPLICATE_BLOCK._pack_ = True # source:False
struct__EFI_HII_SIBT_DUPLICATE_BLOCK._functions_ = []
struct__EFI_HII_SIBT_DUPLICATE_BLOCK._fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('StringId', ctypes.c_uint16),
]

_EFI_HII_SIBT_DUPLICATE_BLOCK = struct__EFI_HII_SIBT_DUPLICATE_BLOCK
P_EFI_HII_SIBT_DUPLICATE_BLOCK = POINTER_T(struct__EFI_HII_SIBT_DUPLICATE_BLOCK)
EFI_HII_STRING_BLOCK = struct_EFI_HII_STRING_BLOCK
PEFI_HII_STRING_BLOCK = POINTER_T(struct_EFI_HII_STRING_BLOCK)
EFI_STRING_ID = ctypes.c_uint16
class struct__EFI_HII_SIBT_END_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
     ]

_EFI_HII_SIBT_END_BLOCK = struct__EFI_HII_SIBT_END_BLOCK
P_EFI_HII_SIBT_END_BLOCK = POINTER_T(struct__EFI_HII_SIBT_END_BLOCK)
class struct__EFI_HII_SIBT_EXT1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte),
     ]

_EFI_HII_SIBT_EXT1_BLOCK = struct__EFI_HII_SIBT_EXT1_BLOCK
P_EFI_HII_SIBT_EXT1_BLOCK = POINTER_T(struct__EFI_HII_SIBT_EXT1_BLOCK)
class struct__EFI_HII_SIBT_EXT2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('Length', ctypes.c_uint16),
     ]

_EFI_HII_SIBT_EXT2_BLOCK = struct__EFI_HII_SIBT_EXT2_BLOCK
P_EFI_HII_SIBT_EXT2_BLOCK = POINTER_T(struct__EFI_HII_SIBT_EXT2_BLOCK)
class struct__EFI_HII_SIBT_EXT4_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('BlockType2', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Length', ctypes.c_uint32),
     ]

_EFI_HII_SIBT_EXT4_BLOCK = struct__EFI_HII_SIBT_EXT4_BLOCK
P_EFI_HII_SIBT_EXT4_BLOCK = POINTER_T(struct__EFI_HII_SIBT_EXT4_BLOCK)
class struct__EFI_HII_SIBT_FONT_BLOCK(ctypes.Structure):
    pass

EFI_HII_SIBT_EXT2_BLOCK = struct__EFI_HII_SIBT_EXT2_BLOCK
struct__EFI_HII_SIBT_FONT_BLOCK._pack_ = True # source:False
struct__EFI_HII_SIBT_FONT_BLOCK._functions_ = []
struct__EFI_HII_SIBT_FONT_BLOCK._fields_ = [
    ('Header', EFI_HII_SIBT_EXT2_BLOCK),
    ('FontId', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
    ('FontSize', ctypes.c_uint16),
    ('FontStyle', ctypes.c_uint32),
    ('FontName', ctypes.c_uint16 * 1),
    ('PADDING_1', ctypes.c_ubyte * 2),
]

_EFI_HII_SIBT_FONT_BLOCK = struct__EFI_HII_SIBT_FONT_BLOCK
P_EFI_HII_SIBT_FONT_BLOCK = POINTER_T(struct__EFI_HII_SIBT_FONT_BLOCK)
class struct__EFI_HII_SIBT_SKIP1_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('SkipCount', ctypes.c_ubyte),
     ]

_EFI_HII_SIBT_SKIP1_BLOCK = struct__EFI_HII_SIBT_SKIP1_BLOCK
P_EFI_HII_SIBT_SKIP1_BLOCK = POINTER_T(struct__EFI_HII_SIBT_SKIP1_BLOCK)
class struct__EFI_HII_SIBT_SKIP2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('SkipCount', ctypes.c_uint16),
     ]

_EFI_HII_SIBT_SKIP2_BLOCK = struct__EFI_HII_SIBT_SKIP2_BLOCK
P_EFI_HII_SIBT_SKIP2_BLOCK = POINTER_T(struct__EFI_HII_SIBT_SKIP2_BLOCK)
class struct__EFI_HII_SIBT_STRING_SCSU_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('StringText', ctypes.c_ubyte * 1),
     ]

_EFI_HII_SIBT_STRING_SCSU_BLOCK = struct__EFI_HII_SIBT_STRING_SCSU_BLOCK
P_EFI_HII_SIBT_STRING_SCSU_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRING_SCSU_BLOCK)
class struct__EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('FontIdentifier', ctypes.c_ubyte),
    ('StringText', ctypes.c_ubyte * 1),
     ]

_EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK = struct__EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK
P_EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK)
class struct__EFI_HII_SIBT_STRING_UCS2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('StringText', ctypes.c_uint16 * 1),
     ]

_EFI_HII_SIBT_STRING_UCS2_BLOCK = struct__EFI_HII_SIBT_STRING_UCS2_BLOCK
P_EFI_HII_SIBT_STRING_UCS2_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRING_UCS2_BLOCK)
class struct__EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('FontIdentifier', ctypes.c_ubyte),
    ('StringText', ctypes.c_uint16 * 1),
     ]

_EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK = struct__EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK
P_EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK)
class struct__EFI_HII_SIBT_STRINGS_SCSU_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('StringCount', ctypes.c_uint16),
    ('StringText', ctypes.c_ubyte * 1),
    ('PADDING_1', ctypes.c_ubyte),
     ]

_EFI_HII_SIBT_STRINGS_SCSU_BLOCK = struct__EFI_HII_SIBT_STRINGS_SCSU_BLOCK
P_EFI_HII_SIBT_STRINGS_SCSU_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRINGS_SCSU_BLOCK)
class struct__EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('FontIdentifier', ctypes.c_ubyte),
    ('StringCount', ctypes.c_uint16),
    ('StringText', ctypes.c_ubyte * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK = struct__EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK
P_EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK)
class struct__EFI_HII_SIBT_STRINGS_UCS2_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('PADDING_0', ctypes.c_ubyte),
    ('StringCount', ctypes.c_uint16),
    ('StringText', ctypes.c_uint16 * 1),
     ]

_EFI_HII_SIBT_STRINGS_UCS2_BLOCK = struct__EFI_HII_SIBT_STRINGS_UCS2_BLOCK
P_EFI_HII_SIBT_STRINGS_UCS2_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRINGS_UCS2_BLOCK)
class struct__EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_STRING_BLOCK),
    ('FontIdentifier', ctypes.c_ubyte),
    ('StringCount', ctypes.c_uint16),
    ('StringText', ctypes.c_uint16 * 1),
     ]

_EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK = struct__EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK
P_EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK = POINTER_T(struct__EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK)
class struct__EFI_HII_SIMPLE_FONT_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('NumberOfNarrowGlyphs', ctypes.c_uint16),
    ('NumberOfWideGlyphs', ctypes.c_uint16),
     ]

_EFI_HII_SIMPLE_FONT_PACKAGE_HDR = struct__EFI_HII_SIMPLE_FONT_PACKAGE_HDR
P_EFI_HII_SIMPLE_FONT_PACKAGE_HDR = POINTER_T(struct__EFI_HII_SIMPLE_FONT_PACKAGE_HDR)
class struct__EFI_HII_STRING_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('HdrSize', ctypes.c_uint32),
    ('StringInfoOffset', ctypes.c_uint32),
    ('LanguageWindow', ctypes.c_uint16 * 16),
    ('LanguageName', ctypes.c_uint16),
    ('Language', ctypes.c_char * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_HII_STRING_PACKAGE_HDR = struct__EFI_HII_STRING_PACKAGE_HDR
P_EFI_HII_STRING_PACKAGE_HDR = POINTER_T(struct__EFI_HII_STRING_PACKAGE_HDR)
CHAR8 = ctypes.c_char
class struct__EFI_IFR_ACTION(ctypes.Structure):
    pass

class struct__EFI_IFR_QUESTION_HEADER(ctypes.Structure):
    pass

class struct__EFI_IFR_STATEMENT_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Prompt', ctypes.c_uint16),
    ('Help', ctypes.c_uint16),
     ]

EFI_IFR_STATEMENT_HEADER = struct__EFI_IFR_STATEMENT_HEADER
class union__union_202(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('VarName', ctypes.c_uint16),
    ('VarOffset', ctypes.c_uint16),
     ]

struct__EFI_IFR_QUESTION_HEADER._pack_ = True # source:False
struct__EFI_IFR_QUESTION_HEADER._functions_ = []
struct__EFI_IFR_QUESTION_HEADER._fields_ = [
    ('Header', EFI_IFR_STATEMENT_HEADER),
    ('QuestionId', ctypes.c_uint16),
    ('VarStoreId', ctypes.c_uint16),
    ('VarStoreInfo', union__union_202),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
]

EFI_IFR_QUESTION_HEADER = struct__EFI_IFR_QUESTION_HEADER
class struct__EFI_IFR_OP_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('OpCode', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte, 7),
    ('Scope', ctypes.c_ubyte, 1),
     ]

EFI_IFR_OP_HEADER = struct__EFI_IFR_OP_HEADER
struct__EFI_IFR_ACTION._pack_ = True # source:False
struct__EFI_IFR_ACTION._functions_ = []
struct__EFI_IFR_ACTION._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('QuestionConfig', ctypes.c_uint16),
]

_EFI_IFR_ACTION = struct__EFI_IFR_ACTION
P_EFI_IFR_ACTION = POINTER_T(struct__EFI_IFR_ACTION)
_EFI_IFR_OP_HEADER = struct__EFI_IFR_OP_HEADER
P_EFI_IFR_OP_HEADER = POINTER_T(struct__EFI_IFR_OP_HEADER)
_EFI_IFR_QUESTION_HEADER = struct__EFI_IFR_QUESTION_HEADER
P_EFI_IFR_QUESTION_HEADER = POINTER_T(struct__EFI_IFR_QUESTION_HEADER)
_EFI_IFR_STATEMENT_HEADER = struct__EFI_IFR_STATEMENT_HEADER
P_EFI_IFR_STATEMENT_HEADER = POINTER_T(struct__EFI_IFR_STATEMENT_HEADER)
EFI_QUESTION_ID = ctypes.c_uint16
EFI_VARSTORE_ID = ctypes.c_uint16
_union_202 = union__union_202
P_union_202 = POINTER_T(union__union_202)
class struct__EFI_IFR_ACTION_1(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
     ]

_EFI_IFR_ACTION_1 = struct__EFI_IFR_ACTION_1
P_EFI_IFR_ACTION_1 = POINTER_T(struct__EFI_IFR_ACTION_1)
class struct__EFI_IFR_ADD(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_ADD = struct__EFI_IFR_ADD
P_EFI_IFR_ADD = POINTER_T(struct__EFI_IFR_ADD)
class struct__EFI_IFR_AND(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_AND = struct__EFI_IFR_AND
P_EFI_IFR_AND = POINTER_T(struct__EFI_IFR_AND)
class struct__EFI_IFR_ANIMATION(ctypes.Structure):
    pass

P_EFI_IFR_ANIMATION = POINTER_T(struct__EFI_IFR_ANIMATION)
struct__EFI_IFR_ANIMATION._pack_ = True # source:False
struct__EFI_IFR_ANIMATION._functions_ = []
struct__EFI_IFR_ANIMATION._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Id', ctypes.c_uint16),
]

_EFI_IFR_ANIMATION = struct__EFI_IFR_ANIMATION
class struct__EFI_IFR_BITWISE_AND(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_BITWISE_AND = struct__EFI_IFR_BITWISE_AND
P_EFI_IFR_BITWISE_AND = POINTER_T(struct__EFI_IFR_BITWISE_AND)
class struct__EFI_IFR_BITWISE_NOT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_BITWISE_NOT = struct__EFI_IFR_BITWISE_NOT
P_EFI_IFR_BITWISE_NOT = POINTER_T(struct__EFI_IFR_BITWISE_NOT)
class struct__EFI_IFR_BITWISE_OR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_BITWISE_OR = struct__EFI_IFR_BITWISE_OR
P_EFI_IFR_BITWISE_OR = POINTER_T(struct__EFI_IFR_BITWISE_OR)
class struct__EFI_IFR_CATENATE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_CATENATE = struct__EFI_IFR_CATENATE
P_EFI_IFR_CATENATE = POINTER_T(struct__EFI_IFR_CATENATE)
class struct__EFI_IFR_CHECKBOX(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_CHECKBOX = struct__EFI_IFR_CHECKBOX
P_EFI_IFR_CHECKBOX = POINTER_T(struct__EFI_IFR_CHECKBOX)
class struct__EFI_IFR_CONDITIONAL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_CONDITIONAL = struct__EFI_IFR_CONDITIONAL
P_EFI_IFR_CONDITIONAL = POINTER_T(struct__EFI_IFR_CONDITIONAL)
class struct__EFI_IFR_DATE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_DATE = struct__EFI_IFR_DATE
P_EFI_IFR_DATE = POINTER_T(struct__EFI_IFR_DATE)
class struct__EFI_IFR_DEFAULT(ctypes.Structure):
    pass

class union_EFI_IFR_TYPE_VALUE(ctypes.Union):
    pass

class struct_EFI_HII_DATE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Year', ctypes.c_uint16),
    ('Month', ctypes.c_ubyte),
    ('Day', ctypes.c_ubyte),
     ]

class struct_EFI_HII_TIME(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Hour', ctypes.c_ubyte),
    ('Minute', ctypes.c_ubyte),
    ('Second', ctypes.c_ubyte),
     ]

class struct_EFI_HII_REF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('QuestionId', ctypes.c_uint16),
    ('FormId', ctypes.c_uint16),
    ('FormSetGuid', EFI_GUID),
    ('DevicePath', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
     ]

union_EFI_IFR_TYPE_VALUE._pack_ = True # source:False
union_EFI_IFR_TYPE_VALUE._functions_ = []
union_EFI_IFR_TYPE_VALUE._fields_ = [
    ('u8', ctypes.c_ubyte),
    ('u16', ctypes.c_uint16),
    ('u32', ctypes.c_uint32),
    ('u64', ctypes.c_uint64),
    ('b', ctypes.c_ubyte),
    ('time', struct_EFI_HII_TIME),
    ('date', struct_EFI_HII_DATE),
    ('string', ctypes.c_uint16),
    ('ref', struct_EFI_HII_REF),
]

struct__EFI_IFR_DEFAULT._pack_ = True # source:False
struct__EFI_IFR_DEFAULT._functions_ = []
struct__EFI_IFR_DEFAULT._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('DefaultId', ctypes.c_uint16),
    ('Type', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('Value', union_EFI_IFR_TYPE_VALUE),
]

_EFI_IFR_DEFAULT = struct__EFI_IFR_DEFAULT
P_EFI_IFR_DEFAULT = POINTER_T(struct__EFI_IFR_DEFAULT)
EFI_IFR_TYPE_VALUE = union_EFI_IFR_TYPE_VALUE
PEFI_IFR_TYPE_VALUE = POINTER_T(union_EFI_IFR_TYPE_VALUE)
BOOLEAN = ctypes.c_ubyte
EFI_HII_TIME = struct_EFI_HII_TIME
PEFI_HII_TIME = POINTER_T(struct_EFI_HII_TIME)
PEFI_HII_DATE = POINTER_T(struct_EFI_HII_DATE)
EFI_HII_DATE = struct_EFI_HII_DATE
EFI_HII_REF = struct_EFI_HII_REF
PEFI_HII_REF = POINTER_T(struct_EFI_HII_REF)
EFI_FORM_ID = ctypes.c_uint16
class struct__EFI_IFR_DEFAULT_2(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('DefaultId', ctypes.c_uint16),
    ('Type', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_DEFAULT_2 = struct__EFI_IFR_DEFAULT_2
P_EFI_IFR_DEFAULT_2 = POINTER_T(struct__EFI_IFR_DEFAULT_2)
class struct__EFI_IFR_DEFAULTSTORE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('DefaultName', ctypes.c_uint16),
    ('DefaultId', ctypes.c_uint16),
     ]

_EFI_IFR_DEFAULTSTORE = struct__EFI_IFR_DEFAULTSTORE
P_EFI_IFR_DEFAULTSTORE = POINTER_T(struct__EFI_IFR_DEFAULTSTORE)
class struct__EFI_IFR_DISABLE_IF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_DISABLE_IF = struct__EFI_IFR_DISABLE_IF
P_EFI_IFR_DISABLE_IF = POINTER_T(struct__EFI_IFR_DISABLE_IF)
class struct__EFI_IFR_DIVIDE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_DIVIDE = struct__EFI_IFR_DIVIDE
P_EFI_IFR_DIVIDE = POINTER_T(struct__EFI_IFR_DIVIDE)
class struct__EFI_IFR_DUP(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_DUP = struct__EFI_IFR_DUP
P_EFI_IFR_DUP = POINTER_T(struct__EFI_IFR_DUP)
class struct__EFI_IFR_END(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_END = struct__EFI_IFR_END
P_EFI_IFR_END = POINTER_T(struct__EFI_IFR_END)
class struct__EFI_IFR_EQ_ID_ID(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('QuestionId1', ctypes.c_uint16),
    ('QuestionId2', ctypes.c_uint16),
     ]

_EFI_IFR_EQ_ID_ID = struct__EFI_IFR_EQ_ID_ID
P_EFI_IFR_EQ_ID_ID = POINTER_T(struct__EFI_IFR_EQ_ID_ID)
class struct__EFI_IFR_EQ_ID_VAL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('QuestionId', ctypes.c_uint16),
    ('Value', ctypes.c_uint16),
     ]

_EFI_IFR_EQ_ID_VAL = struct__EFI_IFR_EQ_ID_VAL
P_EFI_IFR_EQ_ID_VAL = POINTER_T(struct__EFI_IFR_EQ_ID_VAL)
class struct__EFI_IFR_EQ_ID_VAL_LIST(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('QuestionId', ctypes.c_uint16),
    ('ListLength', ctypes.c_uint16),
    ('ValueList', ctypes.c_uint16 * 1),
     ]

_EFI_IFR_EQ_ID_VAL_LIST = struct__EFI_IFR_EQ_ID_VAL_LIST
P_EFI_IFR_EQ_ID_VAL_LIST = POINTER_T(struct__EFI_IFR_EQ_ID_VAL_LIST)
class struct__EFI_IFR_EQUAL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_EQUAL = struct__EFI_IFR_EQUAL
P_EFI_IFR_EQUAL = POINTER_T(struct__EFI_IFR_EQUAL)
class struct__EFI_IFR_FALSE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_FALSE = struct__EFI_IFR_FALSE
P_EFI_IFR_FALSE = POINTER_T(struct__EFI_IFR_FALSE)
class struct__EFI_IFR_FIND(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Format', ctypes.c_ubyte),
     ]

_EFI_IFR_FIND = struct__EFI_IFR_FIND
P_EFI_IFR_FIND = POINTER_T(struct__EFI_IFR_FIND)
class struct__EFI_IFR_FORM(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('FormId', ctypes.c_uint16),
    ('FormTitle', ctypes.c_uint16),
     ]

_EFI_IFR_FORM = struct__EFI_IFR_FORM
P_EFI_IFR_FORM = POINTER_T(struct__EFI_IFR_FORM)
class struct__EFI_IFR_FORM_MAP(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('FormId', ctypes.c_uint16),
     ]

_EFI_IFR_FORM_MAP = struct__EFI_IFR_FORM_MAP
P_EFI_IFR_FORM_MAP = POINTER_T(struct__EFI_IFR_FORM_MAP)
class struct__EFI_IFR_FORM_MAP_METHOD(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MethodTitle', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('MethodIdentifier', EFI_GUID),
     ]

_EFI_IFR_FORM_MAP_METHOD = struct__EFI_IFR_FORM_MAP_METHOD
P_EFI_IFR_FORM_MAP_METHOD = POINTER_T(struct__EFI_IFR_FORM_MAP_METHOD)
class struct__EFI_IFR_FORM_SET(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Guid', EFI_GUID),
    ('FormSetTitle', ctypes.c_uint16),
    ('Help', ctypes.c_uint16),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_1', ctypes.c_ubyte * 3),
     ]

_EFI_IFR_FORM_SET = struct__EFI_IFR_FORM_SET
P_EFI_IFR_FORM_SET = POINTER_T(struct__EFI_IFR_FORM_SET)
class struct__EFI_IFR_GET(ctypes.Structure):
    pass

class union__union_313(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('VarName', ctypes.c_uint16),
    ('VarOffset', ctypes.c_uint16),
     ]

struct__EFI_IFR_GET._pack_ = True # source:False
struct__EFI_IFR_GET._functions_ = []
struct__EFI_IFR_GET._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('VarStoreId', ctypes.c_uint16),
    ('VarStoreInfo', union__union_313),
    ('VarStoreType', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
]

_EFI_IFR_GET = struct__EFI_IFR_GET
P_EFI_IFR_GET = POINTER_T(struct__EFI_IFR_GET)
_union_313 = union__union_313
P_union_313 = POINTER_T(union__union_313)
class struct__EFI_IFR_GRAY_OUT_IF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_GRAY_OUT_IF = struct__EFI_IFR_GRAY_OUT_IF
P_EFI_IFR_GRAY_OUT_IF = POINTER_T(struct__EFI_IFR_GRAY_OUT_IF)
class struct__EFI_IFR_GREATER_EQUAL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_GREATER_EQUAL = struct__EFI_IFR_GREATER_EQUAL
P_EFI_IFR_GREATER_EQUAL = POINTER_T(struct__EFI_IFR_GREATER_EQUAL)
class struct__EFI_IFR_GREATER_THAN(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_GREATER_THAN = struct__EFI_IFR_GREATER_THAN
P_EFI_IFR_GREATER_THAN = POINTER_T(struct__EFI_IFR_GREATER_THAN)
class struct__EFI_IFR_GUID(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Guid', EFI_GUID),
     ]

_EFI_IFR_GUID = struct__EFI_IFR_GUID
P_EFI_IFR_GUID = POINTER_T(struct__EFI_IFR_GUID)
class struct__EFI_IFR_IMAGE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Id', ctypes.c_uint16),
     ]

_EFI_IFR_IMAGE = struct__EFI_IFR_IMAGE
P_EFI_IFR_IMAGE = POINTER_T(struct__EFI_IFR_IMAGE)
class struct__EFI_IFR_INCONSISTENT_IF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Error', ctypes.c_uint16),
     ]

_EFI_IFR_INCONSISTENT_IF = struct__EFI_IFR_INCONSISTENT_IF
P_EFI_IFR_INCONSISTENT_IF = POINTER_T(struct__EFI_IFR_INCONSISTENT_IF)
class struct__EFI_IFR_LENGTH(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_LENGTH = struct__EFI_IFR_LENGTH
P_EFI_IFR_LENGTH = POINTER_T(struct__EFI_IFR_LENGTH)
class struct__EFI_IFR_LESS_EQUAL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_LESS_EQUAL = struct__EFI_IFR_LESS_EQUAL
P_EFI_IFR_LESS_EQUAL = POINTER_T(struct__EFI_IFR_LESS_EQUAL)
class struct__EFI_IFR_LESS_THAN(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_LESS_THAN = struct__EFI_IFR_LESS_THAN
P_EFI_IFR_LESS_THAN = POINTER_T(struct__EFI_IFR_LESS_THAN)
class struct__EFI_IFR_LOCKED(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_LOCKED = struct__EFI_IFR_LOCKED
P_EFI_IFR_LOCKED = POINTER_T(struct__EFI_IFR_LOCKED)
class struct__EFI_IFR_MAP(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_MAP = struct__EFI_IFR_MAP
P_EFI_IFR_MAP = POINTER_T(struct__EFI_IFR_MAP)
class struct__EFI_IFR_MATCH(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_MATCH = struct__EFI_IFR_MATCH
P_EFI_IFR_MATCH = POINTER_T(struct__EFI_IFR_MATCH)
class struct__EFI_IFR_MID(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_MID = struct__EFI_IFR_MID
P_EFI_IFR_MID = POINTER_T(struct__EFI_IFR_MID)
class struct__EFI_IFR_MODAL_TAG(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_MODAL_TAG = struct__EFI_IFR_MODAL_TAG
P_EFI_IFR_MODAL_TAG = POINTER_T(struct__EFI_IFR_MODAL_TAG)
class struct__EFI_IFR_MODULO(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_MODULO = struct__EFI_IFR_MODULO
P_EFI_IFR_MODULO = POINTER_T(struct__EFI_IFR_MODULO)
class struct__EFI_IFR_MULTIPLY(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_MULTIPLY = struct__EFI_IFR_MULTIPLY
P_EFI_IFR_MULTIPLY = POINTER_T(struct__EFI_IFR_MULTIPLY)
class struct__EFI_IFR_NO_SUBMIT_IF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Error', ctypes.c_uint16),
     ]

_EFI_IFR_NO_SUBMIT_IF = struct__EFI_IFR_NO_SUBMIT_IF
P_EFI_IFR_NO_SUBMIT_IF = POINTER_T(struct__EFI_IFR_NO_SUBMIT_IF)
class struct__EFI_IFR_NOT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_NOT = struct__EFI_IFR_NOT
P_EFI_IFR_NOT = POINTER_T(struct__EFI_IFR_NOT)
class struct__EFI_IFR_NOT_EQUAL(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_NOT_EQUAL = struct__EFI_IFR_NOT_EQUAL
P_EFI_IFR_NOT_EQUAL = POINTER_T(struct__EFI_IFR_NOT_EQUAL)
class struct__EFI_IFR_NUMERIC(ctypes.Structure):
    pass

class union_MINMAXSTEP_DATA(ctypes.Union):
    pass

class struct__struct_231(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MinValue', ctypes.c_uint16),
    ('MaxValue', ctypes.c_uint16),
    ('Step', ctypes.c_uint16),
     ]

class struct__struct_230(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MinValue', ctypes.c_ubyte),
    ('MaxValue', ctypes.c_ubyte),
    ('Step', ctypes.c_ubyte),
     ]

class struct__struct_233(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MinValue', ctypes.c_uint64),
    ('MaxValue', ctypes.c_uint64),
    ('Step', ctypes.c_uint64),
     ]

class struct__struct_232(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MinValue', ctypes.c_uint32),
    ('MaxValue', ctypes.c_uint32),
    ('Step', ctypes.c_uint32),
     ]

union_MINMAXSTEP_DATA._pack_ = True # source:False
union_MINMAXSTEP_DATA._functions_ = []
union_MINMAXSTEP_DATA._fields_ = [
    ('u8', struct__struct_230),
    ('u16', struct__struct_231),
    ('u32', struct__struct_232),
    ('u64', struct__struct_233),
]

struct__EFI_IFR_NUMERIC._pack_ = True # source:False
struct__EFI_IFR_NUMERIC._functions_ = []
struct__EFI_IFR_NUMERIC._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
    ('data', union_MINMAXSTEP_DATA),
]

_EFI_IFR_NUMERIC = struct__EFI_IFR_NUMERIC
P_EFI_IFR_NUMERIC = POINTER_T(struct__EFI_IFR_NUMERIC)
MINMAXSTEP_DATA = union_MINMAXSTEP_DATA
PMINMAXSTEP_DATA = POINTER_T(union_MINMAXSTEP_DATA)
_struct_230 = struct__struct_230
P_struct_230 = POINTER_T(struct__struct_230)
_struct_231 = struct__struct_231
P_struct_231 = POINTER_T(struct__struct_231)
_struct_232 = struct__struct_232
P_struct_232 = POINTER_T(struct__struct_232)
_struct_233 = struct__struct_233
P_struct_233 = POINTER_T(struct__struct_233)
class struct__EFI_IFR_ONE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_ONE = struct__EFI_IFR_ONE
P_EFI_IFR_ONE = POINTER_T(struct__EFI_IFR_ONE)
class struct__EFI_IFR_ONE_OF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
    ('data', union_MINMAXSTEP_DATA),
     ]

_EFI_IFR_ONE_OF = struct__EFI_IFR_ONE_OF
P_EFI_IFR_ONE_OF = POINTER_T(struct__EFI_IFR_ONE_OF)
class struct__EFI_IFR_ONE_OF_OPTION(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Option', ctypes.c_uint16),
    ('Flags', ctypes.c_ubyte),
    ('Type', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Value', union_EFI_IFR_TYPE_VALUE),
     ]

_EFI_IFR_ONE_OF_OPTION = struct__EFI_IFR_ONE_OF_OPTION
P_EFI_IFR_ONE_OF_OPTION = POINTER_T(struct__EFI_IFR_ONE_OF_OPTION)
class struct__EFI_IFR_ONES(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_ONES = struct__EFI_IFR_ONES
P_EFI_IFR_ONES = POINTER_T(struct__EFI_IFR_ONES)
class struct__EFI_IFR_OR(ctypes.Structure):
    pass

P_EFI_IFR_OR = POINTER_T(struct__EFI_IFR_OR)
struct__EFI_IFR_OR._pack_ = True # source:False
struct__EFI_IFR_OR._functions_ = []
struct__EFI_IFR_OR._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
]

_EFI_IFR_OR = struct__EFI_IFR_OR
class struct__EFI_IFR_ORDERED_LIST(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('MaxContainers', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
     ]

_EFI_IFR_ORDERED_LIST = struct__EFI_IFR_ORDERED_LIST
P_EFI_IFR_ORDERED_LIST = POINTER_T(struct__EFI_IFR_ORDERED_LIST)
class struct__EFI_IFR_PASSWORD(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('MinSize', ctypes.c_uint16),
    ('MaxSize', ctypes.c_uint16),
     ]

_EFI_IFR_PASSWORD = struct__EFI_IFR_PASSWORD
P_EFI_IFR_PASSWORD = POINTER_T(struct__EFI_IFR_PASSWORD)
class struct__EFI_IFR_QUESTION_REF1(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('QuestionId', ctypes.c_uint16),
     ]

_EFI_IFR_QUESTION_REF1 = struct__EFI_IFR_QUESTION_REF1
P_EFI_IFR_QUESTION_REF1 = POINTER_T(struct__EFI_IFR_QUESTION_REF1)
class struct__EFI_IFR_QUESTION_REF2(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_QUESTION_REF2 = struct__EFI_IFR_QUESTION_REF2
P_EFI_IFR_QUESTION_REF2 = POINTER_T(struct__EFI_IFR_QUESTION_REF2)
class struct__EFI_IFR_QUESTION_REF3(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_QUESTION_REF3 = struct__EFI_IFR_QUESTION_REF3
P_EFI_IFR_QUESTION_REF3 = POINTER_T(struct__EFI_IFR_QUESTION_REF3)
class struct__EFI_IFR_QUESTION_REF3_2(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('DevicePath', ctypes.c_uint16),
     ]

_EFI_IFR_QUESTION_REF3_2 = struct__EFI_IFR_QUESTION_REF3_2
P_EFI_IFR_QUESTION_REF3_2 = POINTER_T(struct__EFI_IFR_QUESTION_REF3_2)
class struct__EFI_IFR_QUESTION_REF3_3(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('DevicePath', ctypes.c_uint16),
    ('Guid', EFI_GUID),
     ]

_EFI_IFR_QUESTION_REF3_3 = struct__EFI_IFR_QUESTION_REF3_3
P_EFI_IFR_QUESTION_REF3_3 = POINTER_T(struct__EFI_IFR_QUESTION_REF3_3)
class struct__EFI_IFR_READ(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_READ = struct__EFI_IFR_READ
P_EFI_IFR_READ = POINTER_T(struct__EFI_IFR_READ)
class struct__EFI_IFR_REF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('FormId', ctypes.c_uint16),
     ]

_EFI_IFR_REF = struct__EFI_IFR_REF
P_EFI_IFR_REF = POINTER_T(struct__EFI_IFR_REF)
class struct__EFI_IFR_REF2(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('FormId', ctypes.c_uint16),
    ('QuestionId', ctypes.c_uint16),
     ]

_EFI_IFR_REF2 = struct__EFI_IFR_REF2
P_EFI_IFR_REF2 = POINTER_T(struct__EFI_IFR_REF2)
class struct__EFI_IFR_REF3(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('FormId', ctypes.c_uint16),
    ('QuestionId', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('FormSetId', EFI_GUID),
     ]

_EFI_IFR_REF3 = struct__EFI_IFR_REF3
P_EFI_IFR_REF3 = POINTER_T(struct__EFI_IFR_REF3)
class struct__EFI_IFR_REF4(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('FormId', ctypes.c_uint16),
    ('QuestionId', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('FormSetId', EFI_GUID),
    ('DevicePath', ctypes.c_uint16),
    ('PADDING_1', ctypes.c_ubyte * 2),
     ]

_EFI_IFR_REF4 = struct__EFI_IFR_REF4
P_EFI_IFR_REF4 = POINTER_T(struct__EFI_IFR_REF4)
class struct__EFI_IFR_REF5(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
     ]

_EFI_IFR_REF5 = struct__EFI_IFR_REF5
P_EFI_IFR_REF5 = POINTER_T(struct__EFI_IFR_REF5)
class struct__EFI_IFR_REFRESH(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('RefreshInterval', ctypes.c_ubyte),
     ]

_EFI_IFR_REFRESH = struct__EFI_IFR_REFRESH
P_EFI_IFR_REFRESH = POINTER_T(struct__EFI_IFR_REFRESH)
class struct__EFI_IFR_REFRESH_ID(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('RefreshEventGroupId', EFI_GUID),
     ]

_EFI_IFR_REFRESH_ID = struct__EFI_IFR_REFRESH_ID
P_EFI_IFR_REFRESH_ID = POINTER_T(struct__EFI_IFR_REFRESH_ID)
class struct__EFI_IFR_RESET_BUTTON(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Statement', EFI_IFR_STATEMENT_HEADER),
    ('DefaultId', ctypes.c_uint16),
     ]

_EFI_IFR_RESET_BUTTON = struct__EFI_IFR_RESET_BUTTON
P_EFI_IFR_RESET_BUTTON = POINTER_T(struct__EFI_IFR_RESET_BUTTON)
EFI_DEFAULT_ID = ctypes.c_uint16
class struct__EFI_IFR_RULE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('RuleId', ctypes.c_ubyte),
     ]

_EFI_IFR_RULE = struct__EFI_IFR_RULE
P_EFI_IFR_RULE = POINTER_T(struct__EFI_IFR_RULE)
class struct__EFI_IFR_RULE_REF(ctypes.Structure):
    pass

P_EFI_IFR_RULE_REF = POINTER_T(struct__EFI_IFR_RULE_REF)
struct__EFI_IFR_RULE_REF._pack_ = True # source:False
struct__EFI_IFR_RULE_REF._functions_ = []
struct__EFI_IFR_RULE_REF._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('RuleId', ctypes.c_ubyte),
]

_EFI_IFR_RULE_REF = struct__EFI_IFR_RULE_REF
class struct__EFI_IFR_SECURITY(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Permissions', EFI_GUID),
     ]

_EFI_IFR_SECURITY = struct__EFI_IFR_SECURITY
P_EFI_IFR_SECURITY = POINTER_T(struct__EFI_IFR_SECURITY)
class struct__EFI_IFR_SET(ctypes.Structure):
    pass

class union__union_311(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('VarName', ctypes.c_uint16),
    ('VarOffset', ctypes.c_uint16),
     ]

struct__EFI_IFR_SET._pack_ = True # source:False
struct__EFI_IFR_SET._functions_ = []
struct__EFI_IFR_SET._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('VarStoreId', ctypes.c_uint16),
    ('VarStoreInfo', union__union_311),
    ('VarStoreType', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
]

_EFI_IFR_SET = struct__EFI_IFR_SET
P_EFI_IFR_SET = POINTER_T(struct__EFI_IFR_SET)
_union_311 = union__union_311
P_union_311 = POINTER_T(union__union_311)
class struct__EFI_IFR_SHIFT_LEFT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_SHIFT_LEFT = struct__EFI_IFR_SHIFT_LEFT
P_EFI_IFR_SHIFT_LEFT = POINTER_T(struct__EFI_IFR_SHIFT_LEFT)
class struct__EFI_IFR_SHIFT_RIGHT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_SHIFT_RIGHT = struct__EFI_IFR_SHIFT_RIGHT
P_EFI_IFR_SHIFT_RIGHT = POINTER_T(struct__EFI_IFR_SHIFT_RIGHT)
class struct__EFI_IFR_SPAN(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Flags', ctypes.c_ubyte),
     ]

_EFI_IFR_SPAN = struct__EFI_IFR_SPAN
P_EFI_IFR_SPAN = POINTER_T(struct__EFI_IFR_SPAN)
class struct__EFI_IFR_STRING(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('MinSize', ctypes.c_ubyte),
    ('MaxSize', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_STRING = struct__EFI_IFR_STRING
P_EFI_IFR_STRING = POINTER_T(struct__EFI_IFR_STRING)
class struct__EFI_IFR_STRING_REF1(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('StringId', ctypes.c_uint16),
     ]

_EFI_IFR_STRING_REF1 = struct__EFI_IFR_STRING_REF1
P_EFI_IFR_STRING_REF1 = POINTER_T(struct__EFI_IFR_STRING_REF1)
class struct__EFI_IFR_STRING_REF2(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_STRING_REF2 = struct__EFI_IFR_STRING_REF2
P_EFI_IFR_STRING_REF2 = POINTER_T(struct__EFI_IFR_STRING_REF2)
class struct__EFI_IFR_SUBTITLE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Statement', EFI_IFR_STATEMENT_HEADER),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_SUBTITLE = struct__EFI_IFR_SUBTITLE
P_EFI_IFR_SUBTITLE = POINTER_T(struct__EFI_IFR_SUBTITLE)
class struct__EFI_IFR_SUBTRACT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_SUBTRACT = struct__EFI_IFR_SUBTRACT
P_EFI_IFR_SUBTRACT = POINTER_T(struct__EFI_IFR_SUBTRACT)
class struct__EFI_IFR_SUPPRESS_IF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_SUPPRESS_IF = struct__EFI_IFR_SUPPRESS_IF
P_EFI_IFR_SUPPRESS_IF = POINTER_T(struct__EFI_IFR_SUPPRESS_IF)
class struct__EFI_IFR_TEXT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Statement', EFI_IFR_STATEMENT_HEADER),
    ('TextTwo', ctypes.c_uint16),
     ]

_EFI_IFR_TEXT = struct__EFI_IFR_TEXT
P_EFI_IFR_TEXT = POINTER_T(struct__EFI_IFR_TEXT)
class struct__EFI_IFR_THIS(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_THIS = struct__EFI_IFR_THIS
P_EFI_IFR_THIS = POINTER_T(struct__EFI_IFR_THIS)
class struct__EFI_IFR_TIME(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Question', EFI_IFR_QUESTION_HEADER),
    ('Flags', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_TIME = struct__EFI_IFR_TIME
P_EFI_IFR_TIME = POINTER_T(struct__EFI_IFR_TIME)
class struct__EFI_IFR_TO_BOOLEAN(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_TO_BOOLEAN = struct__EFI_IFR_TO_BOOLEAN
P_EFI_IFR_TO_BOOLEAN = POINTER_T(struct__EFI_IFR_TO_BOOLEAN)
class struct__EFI_IFR_TO_LOWER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_TO_LOWER = struct__EFI_IFR_TO_LOWER
P_EFI_IFR_TO_LOWER = POINTER_T(struct__EFI_IFR_TO_LOWER)
class struct__EFI_IFR_TO_STRING(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Format', ctypes.c_ubyte),
     ]

_EFI_IFR_TO_STRING = struct__EFI_IFR_TO_STRING
P_EFI_IFR_TO_STRING = POINTER_T(struct__EFI_IFR_TO_STRING)
class struct__EFI_IFR_TO_UINT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_TO_UINT = struct__EFI_IFR_TO_UINT
P_EFI_IFR_TO_UINT = POINTER_T(struct__EFI_IFR_TO_UINT)
class struct__EFI_IFR_TO_UPPER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_TO_UPPER = struct__EFI_IFR_TO_UPPER
P_EFI_IFR_TO_UPPER = POINTER_T(struct__EFI_IFR_TO_UPPER)
class struct__EFI_IFR_TOKEN(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_TOKEN = struct__EFI_IFR_TOKEN
P_EFI_IFR_TOKEN = POINTER_T(struct__EFI_IFR_TOKEN)
class struct__EFI_IFR_TRUE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_TRUE = struct__EFI_IFR_TRUE
P_EFI_IFR_TRUE = POINTER_T(struct__EFI_IFR_TRUE)
class struct__EFI_IFR_UINT16(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Value', ctypes.c_uint16),
     ]

_EFI_IFR_UINT16 = struct__EFI_IFR_UINT16
P_EFI_IFR_UINT16 = POINTER_T(struct__EFI_IFR_UINT16)
class struct__EFI_IFR_UINT32(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Value', ctypes.c_uint32),
     ]

_EFI_IFR_UINT32 = struct__EFI_IFR_UINT32
P_EFI_IFR_UINT32 = POINTER_T(struct__EFI_IFR_UINT32)
class struct__EFI_IFR_UINT64(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 6),
    ('Value', ctypes.c_uint64),
     ]

_EFI_IFR_UINT64 = struct__EFI_IFR_UINT64
P_EFI_IFR_UINT64 = POINTER_T(struct__EFI_IFR_UINT64)
class struct__EFI_IFR_UINT8(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Value', ctypes.c_ubyte),
     ]

_EFI_IFR_UINT8 = struct__EFI_IFR_UINT8
P_EFI_IFR_UINT8 = POINTER_T(struct__EFI_IFR_UINT8)
class struct__EFI_IFR_UNDEFINED(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_UNDEFINED = struct__EFI_IFR_UNDEFINED
P_EFI_IFR_UNDEFINED = POINTER_T(struct__EFI_IFR_UNDEFINED)
class struct__EFI_IFR_VALUE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_VALUE = struct__EFI_IFR_VALUE
P_EFI_IFR_VALUE = POINTER_T(struct__EFI_IFR_VALUE)
class struct__EFI_IFR_VARSTORE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Guid', EFI_GUID),
    ('VarStoreId', ctypes.c_uint16),
    ('Size', ctypes.c_uint16),
    ('Name', ctypes.c_ubyte * 1),
    ('PADDING_1', ctypes.c_ubyte * 3),
     ]

_EFI_IFR_VARSTORE = struct__EFI_IFR_VARSTORE
P_EFI_IFR_VARSTORE = POINTER_T(struct__EFI_IFR_VARSTORE)
class struct__EFI_IFR_VARSTORE_DEVICE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('DevicePath', ctypes.c_uint16),
     ]

_EFI_IFR_VARSTORE_DEVICE = struct__EFI_IFR_VARSTORE_DEVICE
P_EFI_IFR_VARSTORE_DEVICE = POINTER_T(struct__EFI_IFR_VARSTORE_DEVICE)
class struct__EFI_IFR_VARSTORE_EFI(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('VarStoreId', ctypes.c_uint16),
    ('Guid', EFI_GUID),
    ('Attributes', ctypes.c_uint32),
    ('Size', ctypes.c_uint16),
    ('Name', ctypes.c_ubyte * 1),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_VARSTORE_EFI = struct__EFI_IFR_VARSTORE_EFI
P_EFI_IFR_VARSTORE_EFI = POINTER_T(struct__EFI_IFR_VARSTORE_EFI)
class struct__EFI_IFR_VARSTORE_NAME_VALUE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('VarStoreId', ctypes.c_uint16),
    ('Guid', EFI_GUID),
     ]

_EFI_IFR_VARSTORE_NAME_VALUE = struct__EFI_IFR_VARSTORE_NAME_VALUE
P_EFI_IFR_VARSTORE_NAME_VALUE = POINTER_T(struct__EFI_IFR_VARSTORE_NAME_VALUE)
class struct__EFI_IFR_VERSION(ctypes.Structure):
    pass

P_EFI_IFR_VERSION = POINTER_T(struct__EFI_IFR_VERSION)
struct__EFI_IFR_VERSION._pack_ = True # source:False
struct__EFI_IFR_VERSION._functions_ = []
struct__EFI_IFR_VERSION._fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
]

_EFI_IFR_VERSION = struct__EFI_IFR_VERSION
class struct__EFI_IFR_WARNING_IF(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
    ('Warning', ctypes.c_uint16),
    ('TimeOut', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

_EFI_IFR_WARNING_IF = struct__EFI_IFR_WARNING_IF
P_EFI_IFR_WARNING_IF = POINTER_T(struct__EFI_IFR_WARNING_IF)
class struct__EFI_IFR_WRITE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_WRITE = struct__EFI_IFR_WRITE
P_EFI_IFR_WRITE = POINTER_T(struct__EFI_IFR_WRITE)
class struct__EFI_IFR_ZERO(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', EFI_IFR_OP_HEADER),
     ]

_EFI_IFR_ZERO = struct__EFI_IFR_ZERO
P_EFI_IFR_ZERO = POINTER_T(struct__EFI_IFR_ZERO)
EFI_GLYPH_GIBT_END_BLOCK = struct__EFI_GLYPH_GIBT_END_BLOCK
EFI_HII_AIBT_CLEAR_IMAGES_BLOCK = struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK
EFI_HII_AIBT_CLEAR_IMAGES_LOOP_BLOCK = struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK
EFI_HII_AIBT_DUPLICATE_BLOCK = struct__EFI_HII_AIBT_DUPLICATE_BLOCK
EFI_HII_AIBT_EXT1_BLOCK = struct__EFI_HII_AIBT_EXT1_BLOCK
EFI_HII_AIBT_EXT2_BLOCK = struct__EFI_HII_AIBT_EXT2_BLOCK
EFI_HII_AIBT_EXT4_BLOCK = struct__EFI_HII_AIBT_EXT4_BLOCK
EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK = struct__EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK
EFI_HII_AIBT_OVERLAY_IMAGES_LOOP_BLOCK = struct__EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK
EFI_HII_AIBT_RESTORE_SCRN_BLOCK = struct__EFI_HII_AIBT_RESTORE_SCRN_BLOCK
EFI_HII_AIBT_RESTORE_SCRN_LOOP_BLOCK = struct__EFI_HII_AIBT_RESTORE_SCRN_BLOCK
EFI_HII_AIBT_SKIP1_BLOCK = struct__EFI_HII_AIBT_SKIP1_BLOCK
EFI_HII_AIBT_SKIP2_BLOCK = struct__EFI_HII_AIBT_SKIP2_BLOCK
EFI_HII_ANIMATION_PACKAGE_HDR = struct__EFI_HII_ANIMATION_PACKAGE_HDR
EFI_HII_DEVICE_PATH_PACKAGE_HDR = struct__EFI_HII_DEVICE_PATH_PACKAGE_HDR
EFI_HII_FONT_PACKAGE_HDR = struct__EFI_HII_FONT_PACKAGE_HDR
EFI_HII_FORM_PACKAGE_HDR = struct__EFI_HII_FORM_PACKAGE_HDR
EFI_HII_GIBT_DEFAULTS_BLOCK = struct__EFI_HII_GIBT_DEFAULTS_BLOCK
EFI_HII_GIBT_DUPLICATE_BLOCK = struct__EFI_HII_GIBT_DUPLICATE_BLOCK
EFI_HII_GIBT_EXT1_BLOCK = struct__EFI_HII_GIBT_EXT1_BLOCK
EFI_HII_GIBT_EXT2_BLOCK = struct__EFI_HII_GIBT_EXT2_BLOCK
EFI_HII_GIBT_EXT4_BLOCK = struct__EFI_HII_GIBT_EXT4_BLOCK
EFI_HII_GIBT_GLYPH_BLOCK = struct__EFI_HII_GIBT_GLYPH_BLOCK
EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK = struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK
EFI_HII_GIBT_GLYPHS_BLOCK = struct__EFI_HII_GIBT_GLYPHS_BLOCK
EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK = struct__EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK
EFI_HII_GIBT_SKIP1_BLOCK = struct__EFI_HII_GIBT_SKIP1_BLOCK
EFI_HII_GIBT_SKIP2_BLOCK = struct__EFI_HII_GIBT_SKIP2_BLOCK
EFI_HII_GUID_PACKAGE_HDR = struct__EFI_HII_GUID_PACKAGE_HDR
EFI_HII_HANDLE = POINTER_T(None)
EFI_HII_IIBT_DUPLICATE_BLOCK = struct__EFI_HII_IIBT_DUPLICATE_BLOCK
EFI_HII_IIBT_END_BLOCK = struct__EFI_HII_IIBT_END_BLOCK
EFI_HII_IIBT_EXT1_BLOCK = struct__EFI_HII_IIBT_EXT1_BLOCK
EFI_HII_IIBT_EXT2_BLOCK = struct__EFI_HII_IIBT_EXT2_BLOCK
EFI_HII_IIBT_EXT4_BLOCK = struct__EFI_HII_IIBT_EXT4_BLOCK
EFI_HII_IIBT_IMAGE_1BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK
EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK
EFI_HII_IIBT_IMAGE_24BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK
EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK
EFI_HII_IIBT_IMAGE_4BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK
EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK = struct__EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK
EFI_HII_IIBT_IMAGE_8BIT_BLOCK = struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK
EFI_HII_IIBT_IMAGE_8BIT_TRAN_BLOCK = struct__EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK
EFI_HII_IIBT_JPEG_BLOCK = struct__EFI_HII_IIBT_JPEG_BLOCK
EFI_HII_IIBT_SKIP1_BLOCK = struct__EFI_HII_IIBT_SKIP1_BLOCK
EFI_HII_IIBT_SKIP2_BLOCK = struct__EFI_HII_IIBT_SKIP2_BLOCK
EFI_HII_IMAGE_PACKAGE_HDR = struct__EFI_HII_IMAGE_PACKAGE_HDR
EFI_HII_IMAGE_PALETTE_INFO = struct__EFI_HII_IMAGE_PALETTE_INFO
EFI_HII_IMAGE_PALETTE_INFO_HEADER = struct__EFI_HII_IMAGE_PALETTE_INFO_HEADER
class struct_EFI_HII_KEYBOARD_LAYOUT(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('LayoutLength', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('Guid', EFI_GUID),
    ('LayoutDescriptorStringOffset', ctypes.c_uint32),
    ('DescriptorCount', ctypes.c_ubyte),
    ('PADDING_1', ctypes.c_ubyte * 3),
     ]

EFI_HII_KEYBOARD_LAYOUT = struct_EFI_HII_KEYBOARD_LAYOUT
PEFI_HII_KEYBOARD_LAYOUT = POINTER_T(struct_EFI_HII_KEYBOARD_LAYOUT)
class struct_EFI_HII_KEYBOARD_PACKAGE_HDR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Header', struct_EFI_HII_PACKAGE_HEADER),
    ('LayoutCount', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
     ]

EFI_HII_KEYBOARD_PACKAGE_HDR = struct_EFI_HII_KEYBOARD_PACKAGE_HDR
PEFI_HII_KEYBOARD_PACKAGE_HDR = POINTER_T(struct_EFI_HII_KEYBOARD_PACKAGE_HDR)
class struct_EFI_HII_PACKAGE_LIST_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('PackageListGuid', EFI_GUID),
    ('PackageLength', ctypes.c_uint32),
     ]

EFI_HII_PACKAGE_LIST_HEADER = struct_EFI_HII_PACKAGE_LIST_HEADER
PEFI_HII_PACKAGE_LIST_HEADER = POINTER_T(struct_EFI_HII_PACKAGE_LIST_HEADER)
EFI_HII_SIBT_DUPLICATE_BLOCK = struct__EFI_HII_SIBT_DUPLICATE_BLOCK
EFI_HII_SIBT_END_BLOCK = struct__EFI_HII_SIBT_END_BLOCK
EFI_HII_SIBT_EXT1_BLOCK = struct__EFI_HII_SIBT_EXT1_BLOCK
EFI_HII_SIBT_EXT4_BLOCK = struct__EFI_HII_SIBT_EXT4_BLOCK
EFI_HII_SIBT_FONT_BLOCK = struct__EFI_HII_SIBT_FONT_BLOCK
EFI_HII_SIBT_SKIP1_BLOCK = struct__EFI_HII_SIBT_SKIP1_BLOCK
EFI_HII_SIBT_SKIP2_BLOCK = struct__EFI_HII_SIBT_SKIP2_BLOCK
EFI_HII_SIBT_STRING_SCSU_BLOCK = struct__EFI_HII_SIBT_STRING_SCSU_BLOCK
EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK = struct__EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK
EFI_HII_SIBT_STRING_UCS2_BLOCK = struct__EFI_HII_SIBT_STRING_UCS2_BLOCK
EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK = struct__EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK
EFI_HII_SIBT_STRINGS_SCSU_BLOCK = struct__EFI_HII_SIBT_STRINGS_SCSU_BLOCK
EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK = struct__EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK
EFI_HII_SIBT_STRINGS_UCS2_BLOCK = struct__EFI_HII_SIBT_STRINGS_UCS2_BLOCK
EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK = struct__EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK
EFI_HII_SIMPLE_FONT_PACKAGE_HDR = struct__EFI_HII_SIMPLE_FONT_PACKAGE_HDR
EFI_HII_STRING_PACKAGE_HDR = struct__EFI_HII_STRING_PACKAGE_HDR
EFI_IFR_ACTION = struct__EFI_IFR_ACTION
EFI_IFR_ACTION_1 = struct__EFI_IFR_ACTION_1
EFI_IFR_ADD = struct__EFI_IFR_ADD
EFI_IFR_AND = struct__EFI_IFR_AND
EFI_IFR_ANIMATION = struct__EFI_IFR_ANIMATION
EFI_IFR_BITWISE_AND = struct__EFI_IFR_BITWISE_AND
EFI_IFR_BITWISE_NOT = struct__EFI_IFR_BITWISE_NOT
EFI_IFR_BITWISE_OR = struct__EFI_IFR_BITWISE_OR
EFI_IFR_CATENATE = struct__EFI_IFR_CATENATE
EFI_IFR_CHECKBOX = struct__EFI_IFR_CHECKBOX
EFI_IFR_CONDITIONAL = struct__EFI_IFR_CONDITIONAL
EFI_IFR_DATE = struct__EFI_IFR_DATE
EFI_IFR_DEFAULT = struct__EFI_IFR_DEFAULT
EFI_IFR_DEFAULT_2 = struct__EFI_IFR_DEFAULT_2
EFI_IFR_DEFAULTSTORE = struct__EFI_IFR_DEFAULTSTORE
EFI_IFR_DISABLE_IF = struct__EFI_IFR_DISABLE_IF
EFI_IFR_DIVIDE = struct__EFI_IFR_DIVIDE
EFI_IFR_DUP = struct__EFI_IFR_DUP
EFI_IFR_END = struct__EFI_IFR_END
EFI_IFR_EQ_ID_ID = struct__EFI_IFR_EQ_ID_ID
EFI_IFR_EQ_ID_VAL = struct__EFI_IFR_EQ_ID_VAL
EFI_IFR_EQ_ID_VAL_LIST = struct__EFI_IFR_EQ_ID_VAL_LIST
EFI_IFR_EQUAL = struct__EFI_IFR_EQUAL
EFI_IFR_FALSE = struct__EFI_IFR_FALSE
EFI_IFR_FIND = struct__EFI_IFR_FIND
EFI_IFR_FORM = struct__EFI_IFR_FORM
EFI_IFR_FORM_MAP = struct__EFI_IFR_FORM_MAP
EFI_IFR_FORM_MAP_METHOD = struct__EFI_IFR_FORM_MAP_METHOD
EFI_IFR_FORM_SET = struct__EFI_IFR_FORM_SET
EFI_IFR_GET = struct__EFI_IFR_GET
EFI_IFR_GRAY_OUT_IF = struct__EFI_IFR_GRAY_OUT_IF
EFI_IFR_GREATER_EQUAL = struct__EFI_IFR_GREATER_EQUAL
EFI_IFR_GREATER_THAN = struct__EFI_IFR_GREATER_THAN
EFI_IFR_GUID = struct__EFI_IFR_GUID
EFI_IFR_IMAGE = struct__EFI_IFR_IMAGE
EFI_IFR_INCONSISTENT_IF = struct__EFI_IFR_INCONSISTENT_IF
EFI_IFR_LENGTH = struct__EFI_IFR_LENGTH
EFI_IFR_LESS_EQUAL = struct__EFI_IFR_LESS_EQUAL
EFI_IFR_LESS_THAN = struct__EFI_IFR_LESS_THAN
EFI_IFR_LOCKED = struct__EFI_IFR_LOCKED
EFI_IFR_MAP = struct__EFI_IFR_MAP
EFI_IFR_MATCH = struct__EFI_IFR_MATCH
EFI_IFR_MID = struct__EFI_IFR_MID
EFI_IFR_MODAL_TAG = struct__EFI_IFR_MODAL_TAG
EFI_IFR_MODULO = struct__EFI_IFR_MODULO
EFI_IFR_MULTIPLY = struct__EFI_IFR_MULTIPLY
EFI_IFR_NO_SUBMIT_IF = struct__EFI_IFR_NO_SUBMIT_IF
EFI_IFR_NOT = struct__EFI_IFR_NOT
EFI_IFR_NOT_EQUAL = struct__EFI_IFR_NOT_EQUAL
EFI_IFR_NUMERIC = struct__EFI_IFR_NUMERIC
EFI_IFR_ONE = struct__EFI_IFR_ONE
EFI_IFR_ONE_OF = struct__EFI_IFR_ONE_OF
EFI_IFR_ONE_OF_OPTION = struct__EFI_IFR_ONE_OF_OPTION
EFI_IFR_ONES = struct__EFI_IFR_ONES
EFI_IFR_OR = struct__EFI_IFR_OR
EFI_IFR_ORDERED_LIST = struct__EFI_IFR_ORDERED_LIST
EFI_IFR_PASSWORD = struct__EFI_IFR_PASSWORD
EFI_IFR_QUESTION_REF1 = struct__EFI_IFR_QUESTION_REF1
EFI_IFR_QUESTION_REF2 = struct__EFI_IFR_QUESTION_REF2
EFI_IFR_QUESTION_REF3 = struct__EFI_IFR_QUESTION_REF3
EFI_IFR_QUESTION_REF3_2 = struct__EFI_IFR_QUESTION_REF3_2
EFI_IFR_QUESTION_REF3_3 = struct__EFI_IFR_QUESTION_REF3_3
EFI_IFR_READ = struct__EFI_IFR_READ
EFI_IFR_REF = struct__EFI_IFR_REF
EFI_IFR_REF2 = struct__EFI_IFR_REF2
EFI_IFR_REF3 = struct__EFI_IFR_REF3
EFI_IFR_REF4 = struct__EFI_IFR_REF4
EFI_IFR_REF5 = struct__EFI_IFR_REF5
EFI_IFR_REFRESH = struct__EFI_IFR_REFRESH
EFI_IFR_REFRESH_ID = struct__EFI_IFR_REFRESH_ID
EFI_IFR_RESET_BUTTON = struct__EFI_IFR_RESET_BUTTON
EFI_IFR_RULE = struct__EFI_IFR_RULE
EFI_IFR_RULE_REF = struct__EFI_IFR_RULE_REF
EFI_IFR_SECURITY = struct__EFI_IFR_SECURITY
EFI_IFR_SET = struct__EFI_IFR_SET
EFI_IFR_SHIFT_LEFT = struct__EFI_IFR_SHIFT_LEFT
EFI_IFR_SHIFT_RIGHT = struct__EFI_IFR_SHIFT_RIGHT
EFI_IFR_SPAN = struct__EFI_IFR_SPAN
EFI_IFR_STRING = struct__EFI_IFR_STRING
EFI_IFR_STRING_REF1 = struct__EFI_IFR_STRING_REF1
EFI_IFR_STRING_REF2 = struct__EFI_IFR_STRING_REF2
EFI_IFR_SUBTITLE = struct__EFI_IFR_SUBTITLE
EFI_IFR_SUBTRACT = struct__EFI_IFR_SUBTRACT
EFI_IFR_SUPPRESS_IF = struct__EFI_IFR_SUPPRESS_IF
EFI_IFR_TEXT = struct__EFI_IFR_TEXT
EFI_IFR_THIS = struct__EFI_IFR_THIS
EFI_IFR_TIME = struct__EFI_IFR_TIME
EFI_IFR_TO_BOOLEAN = struct__EFI_IFR_TO_BOOLEAN
EFI_IFR_TO_LOWER = struct__EFI_IFR_TO_LOWER
EFI_IFR_TO_STRING = struct__EFI_IFR_TO_STRING
EFI_IFR_TO_UINT = struct__EFI_IFR_TO_UINT
EFI_IFR_TO_UPPER = struct__EFI_IFR_TO_UPPER
EFI_IFR_TOKEN = struct__EFI_IFR_TOKEN
EFI_IFR_TRUE = struct__EFI_IFR_TRUE
EFI_IFR_UINT16 = struct__EFI_IFR_UINT16
EFI_IFR_UINT32 = struct__EFI_IFR_UINT32
EFI_IFR_UINT64 = struct__EFI_IFR_UINT64
EFI_IFR_UINT8 = struct__EFI_IFR_UINT8
EFI_IFR_UNDEFINED = struct__EFI_IFR_UNDEFINED
EFI_IFR_VALUE = struct__EFI_IFR_VALUE
EFI_IFR_VARSTORE = struct__EFI_IFR_VARSTORE
EFI_IFR_VARSTORE_DEVICE = struct__EFI_IFR_VARSTORE_DEVICE
EFI_IFR_VARSTORE_EFI = struct__EFI_IFR_VARSTORE_EFI
EFI_IFR_VARSTORE_NAME_VALUE = struct__EFI_IFR_VARSTORE_NAME_VALUE
EFI_IFR_VERSION = struct__EFI_IFR_VERSION
EFI_IFR_WARNING_IF = struct__EFI_IFR_WARNING_IF
EFI_IFR_WRITE = struct__EFI_IFR_WRITE
EFI_IFR_ZERO = struct__EFI_IFR_ZERO

# values for enumeration 'enum_317'
enum_317__enumvalues = {
    1: 'EfiKeyA0',
    4: 'EfiKeyA2',
    5: 'EfiKeyA3',
    6: 'EfiKeyA4',
    87: 'EfiKeyAsterisk',
    15: 'EfiKeyB0',
    16: 'EfiKeyB1',
    25: 'EfiKeyB10',
    17: 'EfiKeyB2',
    18: 'EfiKeyB3',
    19: 'EfiKeyB4',
    20: 'EfiKeyB5',
    21: 'EfiKeyB6',
    22: 'EfiKeyB7',
    23: 'EfiKeyB8',
    24: 'EfiKeyB9',
    81: 'EfiKeyBackSpace',
    32: 'EfiKeyC1',
    41: 'EfiKeyC10',
    42: 'EfiKeyC11',
    43: 'EfiKeyC12',
    33: 'EfiKeyC2',
    34: 'EfiKeyC3',
    35: 'EfiKeyC4',
    36: 'EfiKeyC5',
    37: 'EfiKeyC6',
    38: 'EfiKeyC7',
    39: 'EfiKeyC8',
    40: 'EfiKeyC9',
    31: 'EfiKeyCapsLock',
    49: 'EfiKeyD1',
    58: 'EfiKeyD10',
    59: 'EfiKeyD11',
    60: 'EfiKeyD12',
    61: 'EfiKeyD13',
    50: 'EfiKeyD2',
    51: 'EfiKeyD3',
    52: 'EfiKeyD4',
    53: 'EfiKeyD5',
    54: 'EfiKeyD6',
    55: 'EfiKeyD7',
    56: 'EfiKeyD8',
    57: 'EfiKeyD9',
    62: 'EfiKeyDel',
    9: 'EfiKeyDownArrow',
    68: 'EfiKeyE0',
    69: 'EfiKeyE1',
    78: 'EfiKeyE10',
    79: 'EfiKeyE11',
    80: 'EfiKeyE12',
    70: 'EfiKeyE2',
    71: 'EfiKeyE3',
    72: 'EfiKeyE4',
    73: 'EfiKeyE5',
    74: 'EfiKeyE6',
    75: 'EfiKeyE7',
    76: 'EfiKeyE8',
    77: 'EfiKeyE9',
    66: 'EfiKeyEight',
    63: 'EfiKeyEnd',
    13: 'EfiKeyEnter',
    89: 'EfiKeyEsc',
    90: 'EfiKeyF1',
    99: 'EfiKeyF10',
    100: 'EfiKeyF11',
    101: 'EfiKeyF12',
    91: 'EfiKeyF2',
    92: 'EfiKeyF3',
    93: 'EfiKeyF4',
    94: 'EfiKeyF5',
    95: 'EfiKeyF6',
    96: 'EfiKeyF7',
    97: 'EfiKeyF8',
    98: 'EfiKeyF9',
    45: 'EfiKeyFive',
    44: 'EfiKeyFour',
    83: 'EfiKeyHome',
    82: 'EfiKeyIns',
    2: 'EfiKeyLAlt',
    0: 'EfiKeyLCtrl',
    14: 'EfiKeyLShift',
    8: 'EfiKeyLeftArrow',
    88: 'EfiKeyMinus',
    85: 'EfiKeyNLck',
    67: 'EfiKeyNine',
    28: 'EfiKeyOne',
    104: 'EfiKeyPause',
    12: 'EfiKeyPeriod',
    64: 'EfiKeyPgDn',
    84: 'EfiKeyPgUp',
    47: 'EfiKeyPlus',
    102: 'EfiKeyPrint',
    7: 'EfiKeyRCtrl',
    26: 'EfiKeyRShift',
    10: 'EfiKeyRightArrow',
    103: 'EfiKeySLck',
    65: 'EfiKeySeven',
    46: 'EfiKeySix',
    86: 'EfiKeySlash',
    3: 'EfiKeySpaceBar',
    48: 'EfiKeyTab',
    30: 'EfiKeyThree',
    29: 'EfiKeyTwo',
    27: 'EfiKeyUpArrow',
    11: 'EfiKeyZero',
}
EfiKeyA0 = 1
EfiKeyA2 = 4
EfiKeyA3 = 5
EfiKeyA4 = 6
EfiKeyAsterisk = 87
EfiKeyB0 = 15
EfiKeyB1 = 16
EfiKeyB10 = 25
EfiKeyB2 = 17
EfiKeyB3 = 18
EfiKeyB4 = 19
EfiKeyB5 = 20
EfiKeyB6 = 21
EfiKeyB7 = 22
EfiKeyB8 = 23
EfiKeyB9 = 24
EfiKeyBackSpace = 81
EfiKeyC1 = 32
EfiKeyC10 = 41
EfiKeyC11 = 42
EfiKeyC12 = 43
EfiKeyC2 = 33
EfiKeyC3 = 34
EfiKeyC4 = 35
EfiKeyC5 = 36
EfiKeyC6 = 37
EfiKeyC7 = 38
EfiKeyC8 = 39
EfiKeyC9 = 40
EfiKeyCapsLock = 31
EfiKeyD1 = 49
EfiKeyD10 = 58
EfiKeyD11 = 59
EfiKeyD12 = 60
EfiKeyD13 = 61
EfiKeyD2 = 50
EfiKeyD3 = 51
EfiKeyD4 = 52
EfiKeyD5 = 53
EfiKeyD6 = 54
EfiKeyD7 = 55
EfiKeyD8 = 56
EfiKeyD9 = 57
EfiKeyDel = 62
EfiKeyDownArrow = 9
EfiKeyE0 = 68
EfiKeyE1 = 69
EfiKeyE10 = 78
EfiKeyE11 = 79
EfiKeyE12 = 80
EfiKeyE2 = 70
EfiKeyE3 = 71
EfiKeyE4 = 72
EfiKeyE5 = 73
EfiKeyE6 = 74
EfiKeyE7 = 75
EfiKeyE8 = 76
EfiKeyE9 = 77
EfiKeyEight = 66
EfiKeyEnd = 63
EfiKeyEnter = 13
EfiKeyEsc = 89
EfiKeyF1 = 90
EfiKeyF10 = 99
EfiKeyF11 = 100
EfiKeyF12 = 101
EfiKeyF2 = 91
EfiKeyF3 = 92
EfiKeyF4 = 93
EfiKeyF5 = 94
EfiKeyF6 = 95
EfiKeyF7 = 96
EfiKeyF8 = 97
EfiKeyF9 = 98
EfiKeyFive = 45
EfiKeyFour = 44
EfiKeyHome = 83
EfiKeyIns = 82
EfiKeyLAlt = 2
EfiKeyLCtrl = 0
EfiKeyLShift = 14
EfiKeyLeftArrow = 8
EfiKeyMinus = 88
EfiKeyNLck = 85
EfiKeyNine = 67
EfiKeyOne = 28
EfiKeyPause = 104
EfiKeyPeriod = 12
EfiKeyPgDn = 64
EfiKeyPgUp = 84
EfiKeyPlus = 47
EfiKeyPrint = 102
EfiKeyRCtrl = 7
EfiKeyRShift = 26
EfiKeyRightArrow = 10
EfiKeySLck = 103
EfiKeySeven = 65
EfiKeySix = 46
EfiKeySlash = 86
EfiKeySpaceBar = 3
EfiKeyTab = 48
EfiKeyThree = 30
EfiKeyTwo = 29
EfiKeyUpArrow = 27
EfiKeyZero = 11
enum_317 = ctypes.c_int # enum
EFI_KEY = enum_317
EFI_KEY__enumvalues = enum_317__enumvalues
class struct_EFI_KEY_DESCRIPTOR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Key', EFI_KEY),
    ('Unicode', ctypes.c_uint16),
    ('ShiftedUnicode', ctypes.c_uint16),
    ('AltGrUnicode', ctypes.c_uint16),
    ('ShiftedAltGrUnicode', ctypes.c_uint16),
    ('Modifier', ctypes.c_uint16),
    ('AffectedAttribute', ctypes.c_uint16),
     ]

EFI_KEY_DESCRIPTOR = struct_EFI_KEY_DESCRIPTOR
PEFI_KEY_DESCRIPTOR = POINTER_T(struct_EFI_KEY_DESCRIPTOR)
class struct_EFI_NARROW_GLYPH(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('UnicodeWeight', ctypes.c_uint16),
    ('Attributes', ctypes.c_ubyte),
    ('GlyphCol1', ctypes.c_ubyte * 19),
     ]

EFI_NARROW_GLYPH = struct_EFI_NARROW_GLYPH
PEFI_NARROW_GLYPH = POINTER_T(struct_EFI_NARROW_GLYPH)
EFI_STRING = POINTER_T(ctypes.c_uint16)
class struct_EFI_WIDE_GLYPH(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('UnicodeWeight', ctypes.c_uint16),
    ('Attributes', ctypes.c_ubyte),
    ('GlyphCol1', ctypes.c_ubyte * 19),
    ('GlyphCol2', ctypes.c_ubyte * 19),
    ('Pad', ctypes.c_ubyte * 3),
     ]

EFI_WIDE_GLYPH = struct_EFI_WIDE_GLYPH
PEFI_WIDE_GLYPH = POINTER_T(struct_EFI_WIDE_GLYPH)

# values for enumeration 'enum_13'
enum_13__enumvalues = {
    10: 'EfiACPIMemoryNVS',
    9: 'EfiACPIReclaimMemory',
    3: 'EfiBootServicesCode',
    4: 'EfiBootServicesData',
    7: 'EfiConventionalMemory',
    1: 'EfiLoaderCode',
    2: 'EfiLoaderData',
    14: 'EfiMaxMemoryType',
    11: 'EfiMemoryMappedIO',
    12: 'EfiMemoryMappedIOPortSpace',
    13: 'EfiPalCode',
    0: 'EfiReservedMemoryType',
    5: 'EfiRuntimeServicesCode',
    6: 'EfiRuntimeServicesData',
    8: 'EfiUnusableMemory',
}
EfiACPIMemoryNVS = 10
EfiACPIReclaimMemory = 9
EfiBootServicesCode = 3
EfiBootServicesData = 4
EfiConventionalMemory = 7
EfiLoaderCode = 1
EfiLoaderData = 2
EfiMaxMemoryType = 14
EfiMemoryMappedIO = 11
EfiMemoryMappedIOPortSpace = 12
EfiPalCode = 13
EfiReservedMemoryType = 0
EfiRuntimeServicesCode = 5
EfiRuntimeServicesData = 6
EfiUnusableMemory = 8
enum_13 = ctypes.c_int # enum
EFI_MEMORY_TYPE = enum_13
EFI_MEMORY_TYPE__enumvalues = enum_13__enumvalues
class struct_EFI_VARIABLE_AUTHENTICATION(ctypes.Structure):
    pass

class struct_WIN_CERTIFICATE_UEFI_GUID(ctypes.Structure):
    pass

class struct_WIN_CERTIFICATE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('dwLength', ctypes.c_uint32),
    ('wRevision', ctypes.c_uint16),
    ('wCertificateType', ctypes.c_uint16),
     ]

struct_WIN_CERTIFICATE_UEFI_GUID._pack_ = True # source:False
struct_WIN_CERTIFICATE_UEFI_GUID._functions_ = []
struct_WIN_CERTIFICATE_UEFI_GUID._fields_ = [
    ('Hdr', struct_WIN_CERTIFICATE),
    ('CertType', EFI_GUID),
    ('CertData', ctypes.c_ubyte * 1),
    ('PADDING_0', ctypes.c_ubyte * 3),
]

struct_EFI_VARIABLE_AUTHENTICATION._pack_ = True # source:False
struct_EFI_VARIABLE_AUTHENTICATION._functions_ = []
struct_EFI_VARIABLE_AUTHENTICATION._fields_ = [
    ('MonotonicCount', ctypes.c_uint64),
    ('AuthInfo', struct_WIN_CERTIFICATE_UEFI_GUID),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

EFI_VARIABLE_AUTHENTICATION = struct_EFI_VARIABLE_AUTHENTICATION
PEFI_VARIABLE_AUTHENTICATION = POINTER_T(struct_EFI_VARIABLE_AUTHENTICATION)
WIN_CERTIFICATE_UEFI_GUID = struct_WIN_CERTIFICATE_UEFI_GUID
PWIN_CERTIFICATE_UEFI_GUID = POINTER_T(struct_WIN_CERTIFICATE_UEFI_GUID)
WIN_CERTIFICATE = struct_WIN_CERTIFICATE
PWIN_CERTIFICATE = POINTER_T(struct_WIN_CERTIFICATE)
class struct_EFI_VARIABLE_AUTHENTICATION_2(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('TimeStamp', struct_EFI_TIME),
    ('AuthInfo', struct_WIN_CERTIFICATE_UEFI_GUID),
     ]

EFI_VARIABLE_AUTHENTICATION_2 = struct_EFI_VARIABLE_AUTHENTICATION_2
PEFI_VARIABLE_AUTHENTICATION_2 = POINTER_T(struct_EFI_VARIABLE_AUTHENTICATION_2)
class struct__struct_113(ctypes.Structure):
    pass

class union__union_114(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Byte', ctypes.c_ubyte),
    ('Word', ctypes.c_uint16),
    ('Dword', ctypes.c_uint32),
     ]

struct__struct_113._pack_ = True # source:False
struct__struct_113._functions_ = []
struct__struct_113._fields_ = [
    ('Addr', ctypes.c_uint32),
    ('Data', union__union_114),
]

_struct_113 = struct__struct_113
P_struct_113 = POINTER_T(struct__struct_113)
PXE_UINT32 = ctypes.c_uint32
_union_114 = union__union_114
P_union_114 = POINTER_T(union__union_114)
PXE_UINT8 = ctypes.c_ubyte
PXE_UINT16 = ctypes.c_uint16
class struct__struct_121(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('FragAddr', ctypes.c_uint64),
    ('FragLen', ctypes.c_uint32),
    ('reserved', ctypes.c_uint32),
     ]

_struct_121 = struct__struct_121
P_struct_121 = POINTER_T(struct__struct_121)
PXE_UINT64 = ctypes.c_uint64
class struct__struct_124(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('FragAddr', ctypes.c_uint64),
    ('FragLen', ctypes.c_uint32),
    ('reserved', ctypes.c_uint32),
     ]

_struct_124 = struct__struct_124
P_struct_124 = POINTER_T(struct__struct_124)
class struct__struct_94(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BusType', ctypes.c_uint32),
    ('Bus', ctypes.c_uint16),
    ('Device', ctypes.c_ubyte),
    ('Function', ctypes.c_ubyte),
     ]

_struct_94 = struct__struct_94
P_struct_94 = POINTER_T(struct__struct_94)
class union__union_101(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Byte', ctypes.c_ubyte * 256),
    ('Word', ctypes.c_uint16 * 128),
    ('Dword', ctypes.c_uint32 * 64),
     ]

_union_101 = union__union_101
P_union_101 = POINTER_T(union__union_101)
class union__union_117(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Byte', ctypes.c_ubyte * 512),
    ('Word', ctypes.c_uint16 * 256),
    ('Dword', ctypes.c_uint32 * 128),
     ]

_union_117 = union__union_117
P_union_117 = POINTER_T(union__union_117)
class union__union_99(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Byte', ctypes.c_ubyte * 256),
    ('Word', ctypes.c_uint16 * 128),
    ('Dword', ctypes.c_uint32 * 64),
     ]

_union_99 = union__union_99
P_union_99 = POINTER_T(union__union_99)
PXE_BOOL = ctypes.c_ubyte
class struct_s_pxe_cdb(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('OpCode', ctypes.c_uint16),
    ('OpFlags', ctypes.c_uint16),
    ('CPBsize', ctypes.c_uint16),
    ('DBsize', ctypes.c_uint16),
    ('CPBaddr', ctypes.c_uint64),
    ('DBaddr', ctypes.c_uint64),
    ('StatCode', ctypes.c_uint16),
    ('StatFlags', ctypes.c_uint16),
    ('IFnum', ctypes.c_uint16),
    ('Control', ctypes.c_uint16),
     ]

s_pxe_cdb = struct_s_pxe_cdb
Ps_pxe_cdb = POINTER_T(struct_s_pxe_cdb)
PXE_CDB = struct_s_pxe_cdb
PXE_OPCODE = ctypes.c_uint16
PXE_OPFLAGS = ctypes.c_uint16
PXE_STATCODE = ctypes.c_uint16
PXE_STATFLAGS = ctypes.c_uint16
PXE_CONTROL = ctypes.c_uint16
class struct_s_pxe_cpb_fill_header(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('SrcAddr', ctypes.c_ubyte * 32),
    ('DestAddr', ctypes.c_ubyte * 32),
    ('MediaHeader', ctypes.c_uint64),
    ('PacketLen', ctypes.c_uint32),
    ('Protocol', ctypes.c_uint16),
    ('MediaHeaderLen', ctypes.c_uint16),
     ]

s_pxe_cpb_fill_header = struct_s_pxe_cpb_fill_header
Ps_pxe_cpb_fill_header = POINTER_T(struct_s_pxe_cpb_fill_header)
PXE_CPB_FILL_HEADER = struct_s_pxe_cpb_fill_header
PXE_MAC_ADDR = ctypes.c_ubyte * 32
class struct_s_pxe_cpb_fill_header_fragmented(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('SrcAddr', ctypes.c_ubyte * 32),
    ('DestAddr', ctypes.c_ubyte * 32),
    ('PacketLen', ctypes.c_uint32),
    ('Protocol', ctypes.c_uint16),
    ('MediaHeaderLen', ctypes.c_uint16),
    ('FragCnt', ctypes.c_uint16),
    ('reserved', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('FragDesc', struct__struct_121 * 16),
     ]

s_pxe_cpb_fill_header_fragmented = struct_s_pxe_cpb_fill_header_fragmented
Ps_pxe_cpb_fill_header_fragmented = POINTER_T(struct_s_pxe_cpb_fill_header_fragmented)
PXE_CPB_FILL_HEADER_FRAGMENTED = struct_s_pxe_cpb_fill_header_fragmented
PXE_MEDIA_PROTOCOL = ctypes.c_uint16
class struct_s_pxe_cpb_initialize(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MemoryAddr', ctypes.c_uint64),
    ('MemoryLength', ctypes.c_uint32),
    ('LinkSpeed', ctypes.c_uint32),
    ('TxBufCnt', ctypes.c_uint16),
    ('TxBufSize', ctypes.c_uint16),
    ('RxBufCnt', ctypes.c_uint16),
    ('RxBufSize', ctypes.c_uint16),
    ('DuplexMode', ctypes.c_ubyte),
    ('LoopBackMode', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 6),
     ]

s_pxe_cpb_initialize = struct_s_pxe_cpb_initialize
Ps_pxe_cpb_initialize = POINTER_T(struct_s_pxe_cpb_initialize)
PXE_CPB_INITIALIZE = struct_s_pxe_cpb_initialize
class struct_s_pxe_cpb_mcast_ip_to_mac(ctypes.Structure):
    pass

class union_u_pxe_ip_addr(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('IPv6', ctypes.c_uint32 * 4),
    ('IPv4', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 12),
     ]

PXE_IP_ADDR = union_u_pxe_ip_addr
struct_s_pxe_cpb_mcast_ip_to_mac._pack_ = True # source:False
struct_s_pxe_cpb_mcast_ip_to_mac._functions_ = []
struct_s_pxe_cpb_mcast_ip_to_mac._fields_ = [
    ('IP', PXE_IP_ADDR),
]

s_pxe_cpb_mcast_ip_to_mac = struct_s_pxe_cpb_mcast_ip_to_mac
Ps_pxe_cpb_mcast_ip_to_mac = POINTER_T(struct_s_pxe_cpb_mcast_ip_to_mac)
PXE_CPB_MCAST_IP_TO_MAC = struct_s_pxe_cpb_mcast_ip_to_mac
u_pxe_ip_addr = union_u_pxe_ip_addr
Pu_pxe_ip_addr = POINTER_T(union_u_pxe_ip_addr)
PXE_IPV6 = ctypes.c_uint32 * 4
PXE_IPV4 = ctypes.c_uint32
class union_u_pxe_cpb_nvdata_bulk(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Byte', ctypes.c_ubyte * 512),
    ('Word', ctypes.c_uint16 * 256),
    ('Dword', ctypes.c_uint32 * 128),
     ]

u_pxe_cpb_nvdata_bulk = union_u_pxe_cpb_nvdata_bulk
Pu_pxe_cpb_nvdata_bulk = POINTER_T(union_u_pxe_cpb_nvdata_bulk)
PXE_CPB_NVDATA_BULK = union_u_pxe_cpb_nvdata_bulk
class struct_s_pxe_cpb_nvdata_sparse(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Item', struct__struct_113 * 128),
     ]

s_pxe_cpb_nvdata_sparse = struct_s_pxe_cpb_nvdata_sparse
Ps_pxe_cpb_nvdata_sparse = POINTER_T(struct_s_pxe_cpb_nvdata_sparse)
PXE_CPB_NVDATA_SPARSE = struct_s_pxe_cpb_nvdata_sparse
class struct_s_pxe_cpb_receive(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BufferAddr', ctypes.c_uint64),
    ('BufferLen', ctypes.c_uint32),
    ('reserved', ctypes.c_uint32),
     ]

s_pxe_cpb_receive = struct_s_pxe_cpb_receive
Ps_pxe_cpb_receive = POINTER_T(struct_s_pxe_cpb_receive)
PXE_CPB_RECEIVE = struct_s_pxe_cpb_receive
class struct_s_pxe_cpb_receive_filters(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MCastList', ctypes.c_ubyte * 32 * 8),
     ]

s_pxe_cpb_receive_filters = struct_s_pxe_cpb_receive_filters
Ps_pxe_cpb_receive_filters = POINTER_T(struct_s_pxe_cpb_receive_filters)
PXE_CPB_RECEIVE_FILTERS = struct_s_pxe_cpb_receive_filters
class struct_s_pxe_cpb_start_30(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Delay', ctypes.c_uint64),
    ('Block', ctypes.c_uint64),
    ('Virt2Phys', ctypes.c_uint64),
    ('Mem_IO', ctypes.c_uint64),
     ]

s_pxe_cpb_start_30 = struct_s_pxe_cpb_start_30
Ps_pxe_cpb_start_30 = POINTER_T(struct_s_pxe_cpb_start_30)
PXE_CPB_START_30 = struct_s_pxe_cpb_start_30
class struct_s_pxe_cpb_start_31(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Delay', ctypes.c_uint64),
    ('Block', ctypes.c_uint64),
    ('Virt2Phys', ctypes.c_uint64),
    ('Mem_IO', ctypes.c_uint64),
    ('Map_Mem', ctypes.c_uint64),
    ('UnMap_Mem', ctypes.c_uint64),
    ('Sync_Mem', ctypes.c_uint64),
    ('Unique_ID', ctypes.c_uint64),
     ]

s_pxe_cpb_start_31 = struct_s_pxe_cpb_start_31
Ps_pxe_cpb_start_31 = POINTER_T(struct_s_pxe_cpb_start_31)
PXE_CPB_START_31 = struct_s_pxe_cpb_start_31
class struct_s_pxe_cpb_station_address(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('StationAddr', ctypes.c_ubyte * 32),
     ]

s_pxe_cpb_station_address = struct_s_pxe_cpb_station_address
Ps_pxe_cpb_station_address = POINTER_T(struct_s_pxe_cpb_station_address)
PXE_CPB_STATION_ADDRESS = struct_s_pxe_cpb_station_address
class struct_s_pxe_cpb_transmit(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('FrameAddr', ctypes.c_uint64),
    ('DataLen', ctypes.c_uint32),
    ('MediaheaderLen', ctypes.c_uint16),
    ('reserved', ctypes.c_uint16),
     ]

s_pxe_cpb_transmit = struct_s_pxe_cpb_transmit
Ps_pxe_cpb_transmit = POINTER_T(struct_s_pxe_cpb_transmit)
PXE_CPB_TRANSMIT = struct_s_pxe_cpb_transmit
class struct_s_pxe_cpb_transmit_fragments(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('FrameLen', ctypes.c_uint32),
    ('MediaheaderLen', ctypes.c_uint16),
    ('FragCnt', ctypes.c_uint16),
    ('FragDesc', struct__struct_124 * 16),
     ]

s_pxe_cpb_transmit_fragments = struct_s_pxe_cpb_transmit_fragments
Ps_pxe_cpb_transmit_fragments = POINTER_T(struct_s_pxe_cpb_transmit_fragments)
PXE_CPB_TRANSMIT_FRAGMENTS = struct_s_pxe_cpb_transmit_fragments
class union_u_pxe_db_get_config_info(ctypes.Union):
    pass

class struct_s_pxe_pcc_config_info(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BusType', ctypes.c_uint32),
    ('Bus', ctypes.c_uint16),
    ('Device', ctypes.c_ubyte),
    ('Function', ctypes.c_ubyte),
    ('Config', union__union_101),
     ]

PXE_PCC_CONFIG_INFO = struct_s_pxe_pcc_config_info
class struct_s_pxe_pci_config_info(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('BusType', ctypes.c_uint32),
    ('Bus', ctypes.c_uint16),
    ('Device', ctypes.c_ubyte),
    ('Function', ctypes.c_ubyte),
    ('Config', union__union_99),
     ]

PXE_PCI_CONFIG_INFO = struct_s_pxe_pci_config_info
union_u_pxe_db_get_config_info._pack_ = True # source:False
union_u_pxe_db_get_config_info._functions_ = []
union_u_pxe_db_get_config_info._fields_ = [
    ('pci', PXE_PCI_CONFIG_INFO),
    ('pcc', PXE_PCC_CONFIG_INFO),
]

u_pxe_db_get_config_info = union_u_pxe_db_get_config_info
Pu_pxe_db_get_config_info = POINTER_T(union_u_pxe_db_get_config_info)
PXE_DB_GET_CONFIG_INFO = union_u_pxe_db_get_config_info
s_pxe_pci_config_info = struct_s_pxe_pci_config_info
Ps_pxe_pci_config_info = POINTER_T(struct_s_pxe_pci_config_info)
s_pxe_pcc_config_info = struct_s_pxe_pcc_config_info
Ps_pxe_pcc_config_info = POINTER_T(struct_s_pxe_pcc_config_info)
class struct_s_pxe_db_get_init_info(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MemoryRequired', ctypes.c_uint32),
    ('FrameDataLen', ctypes.c_uint32),
    ('LinkSpeeds', ctypes.c_uint32 * 4),
    ('NvCount', ctypes.c_uint32),
    ('NvWidth', ctypes.c_uint16),
    ('MediaHeaderLen', ctypes.c_uint16),
    ('HWaddrLen', ctypes.c_uint16),
    ('MCastFilterCnt', ctypes.c_uint16),
    ('TxBufCnt', ctypes.c_uint16),
    ('TxBufSize', ctypes.c_uint16),
    ('RxBufCnt', ctypes.c_uint16),
    ('RxBufSize', ctypes.c_uint16),
    ('IFtype', ctypes.c_ubyte),
    ('SupportedDuplexModes', ctypes.c_ubyte),
    ('SupportedLoopBackModes', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
     ]

s_pxe_db_get_init_info = struct_s_pxe_db_get_init_info
Ps_pxe_db_get_init_info = POINTER_T(struct_s_pxe_db_get_init_info)
PXE_DB_GET_INIT_INFO = struct_s_pxe_db_get_init_info
class struct_s_pxe_db_get_status(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('RxFrameLen', ctypes.c_uint32),
    ('reserved', ctypes.c_uint32),
    ('TxBuffer', ctypes.c_uint64 * 32),
     ]

s_pxe_db_get_status = struct_s_pxe_db_get_status
Ps_pxe_db_get_status = POINTER_T(struct_s_pxe_db_get_status)
PXE_DB_GET_STATUS = struct_s_pxe_db_get_status
class struct_s_pxe_db_initialize(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MemoryUsed', ctypes.c_uint32),
    ('TxBufCnt', ctypes.c_uint16),
    ('TxBufSize', ctypes.c_uint16),
    ('RxBufCnt', ctypes.c_uint16),
    ('RxBufSize', ctypes.c_uint16),
     ]

s_pxe_db_initialize = struct_s_pxe_db_initialize
Ps_pxe_db_initialize = POINTER_T(struct_s_pxe_db_initialize)
PXE_DB_INITIALIZE = struct_s_pxe_db_initialize
class struct_s_pxe_db_mcast_ip_to_mac(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MAC', ctypes.c_ubyte * 32),
     ]

s_pxe_db_mcast_ip_to_mac = struct_s_pxe_db_mcast_ip_to_mac
Ps_pxe_db_mcast_ip_to_mac = POINTER_T(struct_s_pxe_db_mcast_ip_to_mac)
PXE_DB_MCAST_IP_TO_MAC = struct_s_pxe_db_mcast_ip_to_mac
class struct_s_pxe_db_nvdata(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Data', union__union_117),
     ]

s_pxe_db_nvdata = struct_s_pxe_db_nvdata
Ps_pxe_db_nvdata = POINTER_T(struct_s_pxe_db_nvdata)
PXE_DB_NVDATA = struct_s_pxe_db_nvdata
class struct_s_pxe_db_receive(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('SrcAddr', ctypes.c_ubyte * 32),
    ('DestAddr', ctypes.c_ubyte * 32),
    ('FrameLen', ctypes.c_uint32),
    ('Protocol', ctypes.c_uint16),
    ('MediaHeaderLen', ctypes.c_uint16),
    ('Type', ctypes.c_ubyte),
    ('reserved', ctypes.c_ubyte * 7),
     ]

s_pxe_db_receive = struct_s_pxe_db_receive
Ps_pxe_db_receive = POINTER_T(struct_s_pxe_db_receive)
PXE_DB_RECEIVE = struct_s_pxe_db_receive
PXE_FRAME_TYPE = ctypes.c_ubyte
class struct_s_pxe_db_receive_filters(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MCastList', ctypes.c_ubyte * 32 * 8),
     ]

s_pxe_db_receive_filters = struct_s_pxe_db_receive_filters
Ps_pxe_db_receive_filters = POINTER_T(struct_s_pxe_db_receive_filters)
PXE_DB_RECEIVE_FILTERS = struct_s_pxe_db_receive_filters
class struct_s_pxe_dpb_station_address(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('StationAddr', ctypes.c_ubyte * 32),
    ('BroadcastAddr', ctypes.c_ubyte * 32),
    ('PermanentAddr', ctypes.c_ubyte * 32),
     ]

s_pxe_dpb_station_address = struct_s_pxe_dpb_station_address
Ps_pxe_dpb_station_address = POINTER_T(struct_s_pxe_dpb_station_address)
PXE_DB_STATION_ADDRESS = struct_s_pxe_dpb_station_address
class struct_s_pxe_db_statistics(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Supported', ctypes.c_uint64),
    ('Data', ctypes.c_uint64 * 64),
     ]

s_pxe_db_statistics = struct_s_pxe_db_statistics
Ps_pxe_db_statistics = POINTER_T(struct_s_pxe_db_statistics)
PXE_DB_STATISTICS = struct_s_pxe_db_statistics
class union_pxe_device(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('PCI', struct__struct_94),
    ('PCC', struct__struct_94),
     ]

pxe_device = union_pxe_device
Ppxe_device = POINTER_T(union_pxe_device)
PXE_DEVICE = union_pxe_device
class struct_s_pxe_hw_undi(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Signature', ctypes.c_uint32),
    ('Len', ctypes.c_ubyte),
    ('Fudge', ctypes.c_ubyte),
    ('Rev', ctypes.c_ubyte),
    ('IFcnt', ctypes.c_ubyte),
    ('MajorVer', ctypes.c_ubyte),
    ('MinorVer', ctypes.c_ubyte),
    ('IFcntExt', ctypes.c_ubyte),
    ('reserved', ctypes.c_ubyte),
    ('Implementation', ctypes.c_uint32),
     ]

s_pxe_hw_undi = struct_s_pxe_hw_undi
Ps_pxe_hw_undi = POINTER_T(struct_s_pxe_hw_undi)
PXE_HW_UNDI = struct_s_pxe_hw_undi
PXE_IFNUM = ctypes.c_uint16
PXE_IFTYPE = ctypes.c_ubyte
class struct_s_pxe_sw_undi(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Signature', ctypes.c_uint32),
    ('Len', ctypes.c_ubyte),
    ('Fudge', ctypes.c_ubyte),
    ('Rev', ctypes.c_ubyte),
    ('IFcnt', ctypes.c_ubyte),
    ('MajorVer', ctypes.c_ubyte),
    ('MinorVer', ctypes.c_ubyte),
    ('IFcntExt', ctypes.c_ubyte),
    ('reserved1', ctypes.c_ubyte),
    ('Implementation', ctypes.c_uint32),
    ('EntryPoint', ctypes.c_uint64),
    ('reserved2', ctypes.c_ubyte * 3),
    ('BusCnt', ctypes.c_ubyte),
    ('BusType', ctypes.c_uint32 * 1),
     ]

s_pxe_sw_undi = struct_s_pxe_sw_undi
Ps_pxe_sw_undi = POINTER_T(struct_s_pxe_sw_undi)
PXE_SW_UNDI = struct_s_pxe_sw_undi
PXE_UINTN = ctypes.c_uint64
class union_u_pxe_undi(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('hw', PXE_HW_UNDI),
    ('sw', PXE_SW_UNDI),
     ]

u_pxe_undi = union_u_pxe_undi
Pu_pxe_undi = POINTER_T(union_u_pxe_undi)
PXE_UNDI = union_u_pxe_undi
PXE_VOID = None
class struct__struct_86(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Revision', ctypes.c_uint32, 8),
    ('ShiftPressed', ctypes.c_uint32, 1),
    ('ControlPressed', ctypes.c_uint32, 1),
    ('AltPressed', ctypes.c_uint32, 1),
    ('LogoPressed', ctypes.c_uint32, 1),
    ('MenuPressed', ctypes.c_uint32, 1),
    ('SysReqPressed', ctypes.c_uint32, 1),
    ('Reserved', ctypes.c_uint32, 16),
    ('InputKeyCount', ctypes.c_uint32, 2),
     ]

_struct_86 = struct__struct_86
P_struct_86 = POINTER_T(struct__struct_86)
class union__union_78(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('DataBlock', ctypes.c_uint64),
    ('ContinuationPointer', ctypes.c_uint64),
     ]

_union_78 = union__union_78
P_union_78 = POINTER_T(union__union_78)

# values for enumeration 'enum_69'
enum_69__enumvalues = {
    2: 'AllocateAddress',
    0: 'AllocateAnyPages',
    1: 'AllocateMaxAddress',
    3: 'MaxAllocateType',
}
AllocateAddress = 2
AllocateAnyPages = 0
AllocateMaxAddress = 1
MaxAllocateType = 3
enum_69 = ctypes.c_int # enum
EFI_ALLOCATE_TYPE = enum_69
EFI_ALLOCATE_TYPE__enumvalues = enum_69__enumvalues
EFI_ALLOCATE_PAGES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_69, enum_13, ctypes.c_uint64, POINTER_T(ctypes.c_uint64)))
EFI_ALLOCATE_POOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_13, ctypes.c_uint64, POINTER_T(POINTER_T(None))))
class union_EFI_BOOT_KEY_DATA(ctypes.Union):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Options', struct__struct_86),
    ('PackedValue', ctypes.c_uint32),
     ]

EFI_BOOT_KEY_DATA = union_EFI_BOOT_KEY_DATA
PEFI_BOOT_KEY_DATA = POINTER_T(union_EFI_BOOT_KEY_DATA)
class struct_EFI_BOOT_SERVICES(ctypes.Structure):
    pass

class struct_EFI_DEVICE_PATH_PROTOCOL(ctypes.Structure):
    pass


# values for enumeration 'enum_74'
enum_74__enumvalues = {
    0: 'EFI_NATIVE_INTERFACE',
}
EFI_NATIVE_INTERFACE = 0
enum_74 = ctypes.c_int # enum

# values for enumeration 'enum_76'
enum_76__enumvalues = {
    0: 'AllHandles',
    2: 'ByProtocol',
    1: 'ByRegisterNotify',
}
AllHandles = 0
ByProtocol = 2
ByRegisterNotify = 1
enum_76 = ctypes.c_int # enum

# values for enumeration 'enum_71'
enum_71__enumvalues = {
    0: 'TimerCancel',
    1: 'TimerPeriodic',
    2: 'TimerRelative',
}
TimerCancel = 0
TimerPeriodic = 1
TimerRelative = 2
enum_71 = ctypes.c_int # enum
class struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY(ctypes.Structure):
    pass

class struct_EFI_MEMORY_DESCRIPTOR(ctypes.Structure):
    pass

struct_EFI_BOOT_SERVICES._pack_ = True # source:False
struct_EFI_BOOT_SERVICES._functions_ = []
struct_EFI_BOOT_SERVICES._fields_ = [
    ('Hdr', struct_EFI_TABLE_HEADER),
    ('RaiseTPL', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64))),
    ('RestoreTPL', POINTER_T(ctypes.CFUNCTYPE(None, ctypes.c_uint64))),
    ('AllocatePages', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_69, enum_13, ctypes.c_uint64, POINTER_T(ctypes.c_uint64)))),
    ('FreePages', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('GetMemoryMap', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(struct_EFI_MEMORY_DESCRIPTOR), POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint32)))),
    ('AllocatePool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_13, ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('FreePool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('CreateEvent', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None))), POINTER_T(None), POINTER_T(POINTER_T(None))))),
    ('SetTimer', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), enum_71, ctypes.c_uint64))),
    ('WaitForEvent', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(POINTER_T(None)), POINTER_T(ctypes.c_uint64)))),
    ('SignalEvent', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('CloseEvent', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('CheckEvent', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('InstallProtocolInterface', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(None)), POINTER_T(struct_GUID), enum_74, POINTER_T(None)))),
    ('ReinstallProtocolInterface', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(None)))),
    ('UninstallProtocolInterface', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(None)))),
    ('HandleProtocol', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(None))))),
    ('Reserved', POINTER_T(None)),
    ('RegisterProtocolNotify', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(POINTER_T(None))))),
    ('LocateHandle', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_76, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(None))))),
    ('LocateDevicePath', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)), POINTER_T(POINTER_T(None))))),
    ('InstallConfigurationTable', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(None)))),
    ('LoadImage', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_ubyte, POINTER_T(None), POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL), POINTER_T(None), ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('StartImage', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(ctypes.c_uint16))))),
    ('Exit', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint16)))),
    ('UnloadImage', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('ExitBootServices', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))),
    ('GetNextMonotonicCount', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64)))),
    ('Stall', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64))),
    ('SetWatchdogTimer', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint16)))),
    ('ConnectController', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(POINTER_T(None)), POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL), ctypes.c_ubyte))),
    ('DisconnectController', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None)))),
    ('OpenProtocol', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(None)), POINTER_T(None), POINTER_T(None), ctypes.c_uint32))),
    ('CloseProtocol', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(None)))),
    ('OpenProtocolInformation', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY)), POINTER_T(ctypes.c_uint64)))),
    ('ProtocolsPerHandle', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(POINTER_T(POINTER_T(struct_GUID))), POINTER_T(ctypes.c_uint64)))),
    ('LocateHandleBuffer', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_76, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(POINTER_T(None)))))),
    ('LocateProtocol', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(POINTER_T(None))))),
    ('InstallMultipleProtocolInterfaces', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('UninstallMultipleProtocolInterfaces', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('CalculateCrc32', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64, POINTER_T(ctypes.c_uint32)))),
    ('CopyMem', POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None), ctypes.c_uint64))),
    ('SetMem', POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), ctypes.c_uint64, ctypes.c_ubyte))),
    ('CreateEventEx', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None))), POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(None))))),
]

struct_EFI_BOOT_SERVICES._functions_.append(("RaiseTPL",['ctypes.c_uint64', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("RestoreTPL",['None', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("AllocatePages",['ctypes.c_uint64', 'enum_69', 'enum_13', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)']))
struct_EFI_BOOT_SERVICES._functions_.append(("FreePages",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("GetMemoryMap",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(ctypes.c_uint32)']))
struct_EFI_BOOT_SERVICES._functions_.append(("AllocatePool",['ctypes.c_uint64', 'enum_13', 'ctypes.c_uint64', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("FreePool",['ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("CreateEvent",['ctypes.c_uint64', 'ctypes.c_uint32', 'ctypes.c_uint64', 'POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None)))', 'POINTER_T(None)', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("SetTimer",['ctypes.c_uint64', 'POINTER_T(None)', 'enum_71', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("WaitForEvent",['ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(POINTER_T(None))', 'POINTER_T(ctypes.c_uint64)']))
struct_EFI_BOOT_SERVICES._functions_.append(("SignalEvent",['ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("CloseEvent",['ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("CheckEvent",['ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("InstallProtocolInterface",['ctypes.c_uint64', 'POINTER_T(POINTER_T(None))', 'POINTER_T(struct_GUID)', 'enum_74', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("ReinstallProtocolInterface",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(None)', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("UninstallProtocolInterface",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("HandleProtocol",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("RegisterProtocolNotify",['ctypes.c_uint64', 'POINTER_T(struct_GUID)', 'POINTER_T(None)', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("LocateHandle",['ctypes.c_uint64', 'enum_76', 'POINTER_T(struct_GUID)', 'POINTER_T(None)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("LocateDevicePath",['ctypes.c_uint64', 'POINTER_T(struct_GUID)', 'POINTER_T(POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL))', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("InstallConfigurationTable",['ctypes.c_uint64', 'POINTER_T(struct_GUID)', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("LoadImage",['ctypes.c_uint64', 'ctypes.c_ubyte', 'POINTER_T(None)', 'POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)', 'POINTER_T(None)', 'ctypes.c_uint64', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("StartImage",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(POINTER_T(ctypes.c_uint16))']))
struct_EFI_BOOT_SERVICES._functions_.append(("Exit",['ctypes.c_uint64', 'POINTER_T(None)', 'ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint16)']))
struct_EFI_BOOT_SERVICES._functions_.append(("UnloadImage",['ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("ExitBootServices",['ctypes.c_uint64', 'POINTER_T(None)', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("GetNextMonotonicCount",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)']))
struct_EFI_BOOT_SERVICES._functions_.append(("Stall",['ctypes.c_uint64', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("SetWatchdogTimer",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint16)']))
struct_EFI_BOOT_SERVICES._functions_.append(("ConnectController",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(POINTER_T(None))', 'POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)', 'ctypes.c_ubyte']))
struct_EFI_BOOT_SERVICES._functions_.append(("DisconnectController",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(None)', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("OpenProtocol",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(POINTER_T(None))', 'POINTER_T(None)', 'POINTER_T(None)', 'ctypes.c_uint32']))
struct_EFI_BOOT_SERVICES._functions_.append(("CloseProtocol",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(None)', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("OpenProtocolInformation",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY))', 'POINTER_T(ctypes.c_uint64)']))
struct_EFI_BOOT_SERVICES._functions_.append(("ProtocolsPerHandle",['ctypes.c_uint64', 'POINTER_T(None)', 'POINTER_T(POINTER_T(POINTER_T(struct_GUID)))', 'POINTER_T(ctypes.c_uint64)']))
struct_EFI_BOOT_SERVICES._functions_.append(("LocateHandleBuffer",['ctypes.c_uint64', 'enum_76', 'POINTER_T(struct_GUID)', 'POINTER_T(None)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(POINTER_T(POINTER_T(None)))']))
struct_EFI_BOOT_SERVICES._functions_.append(("LocateProtocol",['ctypes.c_uint64', 'POINTER_T(struct_GUID)', 'POINTER_T(None)', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("InstallMultipleProtocolInterfaces",['ctypes.c_uint64', 'POINTER_T(POINTER_T(None))']))
struct_EFI_BOOT_SERVICES._functions_.append(("UninstallMultipleProtocolInterfaces",['ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_BOOT_SERVICES._functions_.append(("CalculateCrc32",['ctypes.c_uint64', 'POINTER_T(None)', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint32)']))
struct_EFI_BOOT_SERVICES._functions_.append(("CopyMem",['None', 'POINTER_T(None)', 'POINTER_T(None)', 'ctypes.c_uint64']))
struct_EFI_BOOT_SERVICES._functions_.append(("SetMem",['None', 'POINTER_T(None)', 'ctypes.c_uint64', 'ctypes.c_ubyte']))
struct_EFI_BOOT_SERVICES._functions_.append(("CreateEventEx",['ctypes.c_uint64', 'ctypes.c_uint32', 'ctypes.c_uint64', 'POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None)))', 'POINTER_T(None)', 'POINTER_T(struct_GUID)', 'POINTER_T(POINTER_T(None))']))
EFI_BOOT_SERVICES = struct_EFI_BOOT_SERVICES
PEFI_BOOT_SERVICES = POINTER_T(struct_EFI_BOOT_SERVICES)
EFI_RAISE_TPL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64))
EFI_RESTORE_TPL = POINTER_T(ctypes.CFUNCTYPE(None, ctypes.c_uint64))
EFI_FREE_PAGES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))
struct_EFI_MEMORY_DESCRIPTOR._pack_ = True # source:False
struct_EFI_MEMORY_DESCRIPTOR._functions_ = []
struct_EFI_MEMORY_DESCRIPTOR._fields_ = [
    ('Type', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('PhysicalStart', ctypes.c_uint64),
    ('VirtualStart', ctypes.c_uint64),
    ('NumberOfPages', ctypes.c_uint64),
    ('Attribute', ctypes.c_uint64),
]

EFI_MEMORY_DESCRIPTOR = struct_EFI_MEMORY_DESCRIPTOR
PEFI_MEMORY_DESCRIPTOR = POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)
EFI_GET_MEMORY_MAP = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(struct_EFI_MEMORY_DESCRIPTOR), POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint32)))
EFI_FREE_POOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))
EFI_EVENT_NOTIFY = POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None)))
EFI_CREATE_EVENT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None))), POINTER_T(None), POINTER_T(POINTER_T(None))))
EFI_TIMER_DELAY = enum_71
EFI_TIMER_DELAY__enumvalues = enum_71__enumvalues
EFI_SET_TIMER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), enum_71, ctypes.c_uint64))
EFI_WAIT_FOR_EVENT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(POINTER_T(None)), POINTER_T(ctypes.c_uint64)))
EFI_SIGNAL_EVENT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))
EFI_CLOSE_EVENT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))
EFI_CHECK_EVENT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))
EFI_INTERFACE_TYPE = enum_74
EFI_INTERFACE_TYPE__enumvalues = enum_74__enumvalues
EFI_INSTALL_PROTOCOL_INTERFACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(None)), POINTER_T(struct_GUID), enum_74, POINTER_T(None)))
EFI_REINSTALL_PROTOCOL_INTERFACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(None)))
EFI_UNINSTALL_PROTOCOL_INTERFACE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(None)))
EFI_HANDLE_PROTOCOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(None))))
EFI_REGISTER_PROTOCOL_NOTIFY = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(POINTER_T(None))))
EFI_LOCATE_SEARCH_TYPE = enum_76
EFI_LOCATE_SEARCH_TYPE__enumvalues = enum_76__enumvalues
EFI_LOCATE_HANDLE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_76, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(None))))
struct_EFI_DEVICE_PATH_PROTOCOL._pack_ = True # source:False
struct_EFI_DEVICE_PATH_PROTOCOL._functions_ = []
struct_EFI_DEVICE_PATH_PROTOCOL._fields_ = [
    ('Type', ctypes.c_ubyte),
    ('SubType', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte * 2),
]

EFI_DEVICE_PATH_PROTOCOL = struct_EFI_DEVICE_PATH_PROTOCOL
PEFI_DEVICE_PATH_PROTOCOL = POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
EFI_LOCATE_DEVICE_PATH = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)), POINTER_T(POINTER_T(None))))
EFI_INSTALL_CONFIGURATION_TABLE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(None)))
EFI_IMAGE_LOAD = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_ubyte, POINTER_T(None), POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL), POINTER_T(None), ctypes.c_uint64, POINTER_T(POINTER_T(None))))
EFI_IMAGE_START = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(ctypes.c_uint16))))
EFI_EXIT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint16)))
EFI_IMAGE_UNLOAD = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))
EFI_EXIT_BOOT_SERVICES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64))
EFI_GET_NEXT_MONOTONIC_COUNT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64)))
EFI_STALL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64))
EFI_SET_WATCHDOG_TIMER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint16)))
EFI_CONNECT_CONTROLLER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(POINTER_T(None)), POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL), ctypes.c_ubyte))
EFI_DISCONNECT_CONTROLLER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None)))
EFI_OPEN_PROTOCOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(None)), POINTER_T(None), POINTER_T(None), ctypes.c_uint32))
EFI_CLOSE_PROTOCOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(None)))
struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY._pack_ = True # source:False
struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY._functions_ = []
struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY._fields_ = [
    ('AgentHandle', POINTER_T(None)),
    ('ControllerHandle', POINTER_T(None)),
    ('Attributes', ctypes.c_uint32),
    ('OpenCount', ctypes.c_uint32),
]

EFI_OPEN_PROTOCOL_INFORMATION_ENTRY = struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY
PEFI_OPEN_PROTOCOL_INFORMATION_ENTRY = POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY)
EFI_OPEN_PROTOCOL_INFORMATION = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY)), POINTER_T(ctypes.c_uint64)))
EFI_PROTOCOLS_PER_HANDLE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(POINTER_T(POINTER_T(struct_GUID))), POINTER_T(ctypes.c_uint64)))
EFI_LOCATE_HANDLE_BUFFER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_76, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(ctypes.c_uint64), POINTER_T(POINTER_T(POINTER_T(None)))))
EFI_LOCATE_PROTOCOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_GUID), POINTER_T(None), POINTER_T(POINTER_T(None))))
EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(None))))
EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))
EFI_CALCULATE_CRC32 = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), ctypes.c_uint64, POINTER_T(ctypes.c_uint32)))
EFI_COPY_MEM = POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None), ctypes.c_uint64))
EFI_SET_MEM = POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), ctypes.c_uint64, ctypes.c_ubyte))
EFI_CREATE_EVENT_EX = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None))), POINTER_T(None), POINTER_T(struct_GUID), POINTER_T(POINTER_T(None))))
class struct_EFI_CAPSULE_BLOCK_DESCRIPTOR(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Length', ctypes.c_uint64),
    ('Union', union__union_78),
     ]

EFI_CAPSULE_BLOCK_DESCRIPTOR = struct_EFI_CAPSULE_BLOCK_DESCRIPTOR
PEFI_CAPSULE_BLOCK_DESCRIPTOR = POINTER_T(struct_EFI_CAPSULE_BLOCK_DESCRIPTOR)
class struct_EFI_CAPSULE_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('CapsuleGuid', EFI_GUID),
    ('HeaderSize', ctypes.c_uint32),
    ('Flags', ctypes.c_uint32),
    ('CapsuleImageSize', ctypes.c_uint32),
     ]

EFI_CAPSULE_HEADER = struct_EFI_CAPSULE_HEADER
PEFI_CAPSULE_HEADER = POINTER_T(struct_EFI_CAPSULE_HEADER)
class struct_EFI_CAPSULE_TABLE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('CapsuleArrayNumber', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('CapsulePtr', POINTER_T(None) * 1),
     ]

EFI_CAPSULE_TABLE = struct_EFI_CAPSULE_TABLE
PEFI_CAPSULE_TABLE = POINTER_T(struct_EFI_CAPSULE_TABLE)
class struct_EFI_CONFIGURATION_TABLE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('VendorGuid', EFI_GUID),
    ('VendorTable', POINTER_T(None)),
     ]

EFI_CONFIGURATION_TABLE = struct_EFI_CONFIGURATION_TABLE
PEFI_CONFIGURATION_TABLE = POINTER_T(struct_EFI_CONFIGURATION_TABLE)
EFI_CONVERT_POINTER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(POINTER_T(None))))
EFI_GET_NEXT_HIGH_MONO_COUNT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint32)))
EFI_GET_NEXT_VARIABLE_NAME = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint16), POINTER_T(struct_GUID)))
class struct_EFI_TIME_CAPABILITIES(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('Resolution', ctypes.c_uint32),
    ('Accuracy', ctypes.c_uint32),
    ('SetsToZero', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
     ]

EFI_TIME_CAPABILITIES = struct_EFI_TIME_CAPABILITIES
PEFI_TIME_CAPABILITIES = POINTER_T(struct_EFI_TIME_CAPABILITIES)
EFI_GET_TIME = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_TIME), POINTER_T(struct_EFI_TIME_CAPABILITIES)))
EFI_GET_VARIABLE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint16), POINTER_T(struct_GUID), POINTER_T(ctypes.c_uint32), POINTER_T(ctypes.c_uint64), POINTER_T(None)))
EFI_GET_WAKEUP_TIME = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_ubyte), POINTER_T(ctypes.c_ubyte), POINTER_T(struct_EFI_TIME)))
class struct_EFI_SYSTEM_TABLE(ctypes.Structure):
    pass

class struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL(ctypes.Structure):
    pass

class struct_EFI_SIMPLE_TEXT_OUTPUT_MODE(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('MaxMode', ctypes.c_int32),
    ('Mode', ctypes.c_int32),
    ('Attribute', ctypes.c_int32),
    ('CursorColumn', ctypes.c_int32),
    ('CursorRow', ctypes.c_int32),
    ('CursorVisible', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 3),
     ]

struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._pack_ = True # source:False
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_ = []
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._fields_ = [
    ('Reset', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_ubyte))),
    ('OutputString', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), POINTER_T(ctypes.c_uint16)))),
    ('TestString', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), POINTER_T(ctypes.c_uint16)))),
    ('QueryMode', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64)))),
    ('SetMode', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64))),
    ('SetAttribute', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64))),
    ('ClearScreen', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)))),
    ('SetCursorPosition', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64, ctypes.c_uint64))),
    ('EnableCursor', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_ubyte))),
    ('Mode', POINTER_T(struct_EFI_SIMPLE_TEXT_OUTPUT_MODE)),
]

struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("Reset",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'ctypes.c_ubyte']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("OutputString",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'POINTER_T(ctypes.c_uint16)']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("TestString",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'POINTER_T(ctypes.c_uint16)']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("QueryMode",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(ctypes.c_uint64)']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("SetMode",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'ctypes.c_uint64']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("SetAttribute",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'ctypes.c_uint64']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("ClearScreen",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("SetCursorPosition",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL._functions_.append(("EnableCursor",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)', 'ctypes.c_ubyte']))
class struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL(ctypes.Structure):
    pass

class struct_EFI_INPUT_KEY(ctypes.Structure):
    pass

struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL._pack_ = True # source:False
struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL._functions_ = []
struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL._fields_ = [
    ('Reset', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL), ctypes.c_ubyte))),
    ('ReadKeyStroke', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL), POINTER_T(struct_EFI_INPUT_KEY)))),
    ('WaitForKey', POINTER_T(None)),
]

struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL._functions_.append(("Reset",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL)', 'ctypes.c_ubyte']))
struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL._functions_.append(("ReadKeyStroke",['ctypes.c_uint64', 'POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL)', 'POINTER_T(struct_EFI_INPUT_KEY)']))
class struct_EFI_RUNTIME_SERVICES(ctypes.Structure):
    pass


# values for enumeration 'enum_73'
enum_73__enumvalues = {
    0: 'EfiResetCold',
    3: 'EfiResetPlatformSpecific',
    2: 'EfiResetShutdown',
    1: 'EfiResetWarm',
}
EfiResetCold = 0
EfiResetPlatformSpecific = 3
EfiResetShutdown = 2
EfiResetWarm = 1
enum_73 = ctypes.c_int # enum
struct_EFI_RUNTIME_SERVICES._pack_ = True # source:False
struct_EFI_RUNTIME_SERVICES._functions_ = []
struct_EFI_RUNTIME_SERVICES._fields_ = [
    ('Hdr', struct_EFI_TABLE_HEADER),
    ('GetTime', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_TIME), POINTER_T(struct_EFI_TIME_CAPABILITIES)))),
    ('SetTime', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_TIME)))),
    ('GetWakeupTime', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_ubyte), POINTER_T(ctypes.c_ubyte), POINTER_T(struct_EFI_TIME)))),
    ('SetWakeupTime', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_ubyte, POINTER_T(struct_EFI_TIME)))),
    ('SetVirtualAddressMap', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)))),
    ('ConvertPointer', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('GetVariable', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint16), POINTER_T(struct_GUID), POINTER_T(ctypes.c_uint32), POINTER_T(ctypes.c_uint64), POINTER_T(None)))),
    ('GetNextVariableName', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint16), POINTER_T(struct_GUID)))),
    ('SetVariable', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint16), POINTER_T(struct_GUID), ctypes.c_uint32, ctypes.c_uint64, POINTER_T(None)))),
    ('GetNextHighMonotonicCount', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint32)))),
    ('ResetSystem', POINTER_T(ctypes.CFUNCTYPE(None, enum_73, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(None)))),
    ('UpdateCapsule', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER)), ctypes.c_uint64, ctypes.c_uint64))),
    ('QueryCapsuleCapabilities', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER)), ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(enum_73)))),
    ('QueryVariableInfo', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint32, POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64)))),
]

struct_EFI_RUNTIME_SERVICES._functions_.append(("GetTime",['ctypes.c_uint64', 'POINTER_T(struct_EFI_TIME)', 'POINTER_T(struct_EFI_TIME_CAPABILITIES)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("SetTime",['ctypes.c_uint64', 'POINTER_T(struct_EFI_TIME)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("GetWakeupTime",['ctypes.c_uint64', 'POINTER_T(ctypes.c_ubyte)', 'POINTER_T(ctypes.c_ubyte)', 'POINTER_T(struct_EFI_TIME)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("SetWakeupTime",['ctypes.c_uint64', 'ctypes.c_ubyte', 'POINTER_T(struct_EFI_TIME)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("SetVirtualAddressMap",['ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint64', 'ctypes.c_uint32', 'POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("ConvertPointer",['ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(POINTER_T(None))']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("GetVariable",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint16)', 'POINTER_T(struct_GUID)', 'POINTER_T(ctypes.c_uint32)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(None)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("GetNextVariableName",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(ctypes.c_uint16)', 'POINTER_T(struct_GUID)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("SetVariable",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint16)', 'POINTER_T(struct_GUID)', 'ctypes.c_uint32', 'ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("GetNextHighMonotonicCount",['ctypes.c_uint64', 'POINTER_T(ctypes.c_uint32)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("ResetSystem",['None', 'enum_73', 'ctypes.c_uint64', 'ctypes.c_uint64', 'POINTER_T(None)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("UpdateCapsule",['ctypes.c_uint64', 'POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER))', 'ctypes.c_uint64', 'ctypes.c_uint64']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("QueryCapsuleCapabilities",['ctypes.c_uint64', 'POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER))', 'ctypes.c_uint64', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(enum_73)']))
struct_EFI_RUNTIME_SERVICES._functions_.append(("QueryVariableInfo",['ctypes.c_uint64', 'ctypes.c_uint32', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(ctypes.c_uint64)', 'POINTER_T(ctypes.c_uint64)']))
struct_EFI_SYSTEM_TABLE._pack_ = True # source:False
struct_EFI_SYSTEM_TABLE._functions_ = []
struct_EFI_SYSTEM_TABLE._fields_ = [
    ('Hdr', struct_EFI_TABLE_HEADER),
    ('FirmwareVendor', POINTER_T(ctypes.c_uint16)),
    ('FirmwareRevision', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ConsoleInHandle', POINTER_T(None)),
    ('ConIn', POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL)),
    ('ConsoleOutHandle', POINTER_T(None)),
    ('ConOut', POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)),
    ('StandardErrorHandle', POINTER_T(None)),
    ('StdErr', POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)),
    ('RuntimeServices', POINTER_T(struct_EFI_RUNTIME_SERVICES)),
    ('BootServices', POINTER_T(struct_EFI_BOOT_SERVICES)),
    ('NumberOfTableEntries', ctypes.c_uint64),
    ('ConfigurationTable', POINTER_T(struct_EFI_CONFIGURATION_TABLE)),
]

EFI_SYSTEM_TABLE = struct_EFI_SYSTEM_TABLE
PEFI_SYSTEM_TABLE = POINTER_T(struct_EFI_SYSTEM_TABLE)
EFI_IMAGE_ENTRY_POINT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(struct_EFI_SYSTEM_TABLE)))
_EFI_SIMPLE_TEXT_INPUT_PROTOCOL = struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL
P_EFI_SIMPLE_TEXT_INPUT_PROTOCOL = POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL)
EFI_SIMPLE_TEXT_INPUT_PROTOCOL = struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL
P_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL
EFI_RUNTIME_SERVICES = struct_EFI_RUNTIME_SERVICES
PEFI_RUNTIME_SERVICES = POINTER_T(struct_EFI_RUNTIME_SERVICES)
EFI_INPUT_RESET = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL), ctypes.c_ubyte))
struct_EFI_INPUT_KEY._pack_ = True # source:False
struct_EFI_INPUT_KEY._functions_ = []
struct_EFI_INPUT_KEY._fields_ = [
    ('ScanCode', ctypes.c_uint16),
    ('UnicodeChar', ctypes.c_uint16),
]

EFI_INPUT_KEY = struct_EFI_INPUT_KEY
PEFI_INPUT_KEY = POINTER_T(struct_EFI_INPUT_KEY)
EFI_INPUT_READ_KEY = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL), POINTER_T(struct_EFI_INPUT_KEY)))
EFI_TEXT_RESET = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_ubyte))
EFI_TEXT_STRING = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), POINTER_T(ctypes.c_uint16)))
EFI_TEXT_TEST_STRING = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), POINTER_T(ctypes.c_uint16)))
EFI_TEXT_QUERY_MODE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64)))
EFI_TEXT_SET_MODE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64))
EFI_TEXT_SET_ATTRIBUTE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64))
EFI_TEXT_CLEAR_SCREEN = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)))
EFI_TEXT_SET_CURSOR_POSITION = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_uint64, ctypes.c_uint64))
EFI_TEXT_ENABLE_CURSOR = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), ctypes.c_ubyte))
EFI_SIMPLE_TEXT_OUTPUT_MODE = struct_EFI_SIMPLE_TEXT_OUTPUT_MODE
PEFI_SIMPLE_TEXT_OUTPUT_MODE = POINTER_T(struct_EFI_SIMPLE_TEXT_OUTPUT_MODE)
EFI_SET_TIME = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct_EFI_TIME)))
EFI_SET_WAKEUP_TIME = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_ubyte, POINTER_T(struct_EFI_TIME)))
EFI_SET_VIRTUAL_ADDRESS_MAP = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)))
EFI_SET_VARIABLE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.c_uint16), POINTER_T(struct_GUID), ctypes.c_uint32, ctypes.c_uint64, POINTER_T(None)))
EFI_RESET_TYPE = enum_73
EFI_RESET_TYPE__enumvalues = enum_73__enumvalues
EFI_RESET_SYSTEM = POINTER_T(ctypes.CFUNCTYPE(None, enum_73, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(None)))
EFI_UPDATE_CAPSULE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER)), ctypes.c_uint64, ctypes.c_uint64))
EFI_QUERY_CAPSULE_CAPABILITIES = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER)), ctypes.c_uint64, POINTER_T(ctypes.c_uint64), POINTER_T(enum_73)))
EFI_QUERY_VARIABLE_INFO = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint32, POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64), POINTER_T(ctypes.c_uint64)))
INT32 = ctypes.c_int32
class struct_EFI_KEY_OPTION(ctypes.Structure):
    _pack_ = True # source:False
    _functions_ = []
    _fields_ = [
    ('KeyData', union_EFI_BOOT_KEY_DATA),
    ('BootOptionCrc', ctypes.c_uint32),
    ('BootOption', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 2),
     ]

EFI_KEY_OPTION = struct_EFI_KEY_OPTION
PEFI_KEY_OPTION = POINTER_T(struct_EFI_KEY_OPTION)

# values for enumeration 'enum_1'
enum_1__enumvalues = {
}
enum_1 = ctypes.c_int # enum
__all__ = \
    ['AllHandles', 'AllocateAddress', 'AllocateAnyPages',
    'AllocateMaxAddress', 'BOOLEAN', 'ByProtocol', 'ByRegisterNotify',
    'CHAR16', 'CHAR8', 'EFI_ALLOCATE_PAGES', 'EFI_ALLOCATE_POOL',
    'EFI_ALLOCATE_TYPE', 'EFI_ALLOCATE_TYPE__enumvalues',
    'EFI_ANIMATION_ID', 'EFI_BOOT_KEY_DATA', 'EFI_BOOT_SERVICES',
    'EFI_CALCULATE_CRC32', 'EFI_CAPSULE_BLOCK_DESCRIPTOR',
    'EFI_CAPSULE_HEADER', 'EFI_CAPSULE_TABLE', 'EFI_CHECK_EVENT',
    'EFI_CLOSE_EVENT', 'EFI_CLOSE_PROTOCOL',
    'EFI_CONFIGURATION_TABLE', 'EFI_CONNECT_CONTROLLER',
    'EFI_CONVERT_POINTER', 'EFI_COPY_MEM', 'EFI_CREATE_EVENT',
    'EFI_CREATE_EVENT_EX', 'EFI_DEFAULT_ID',
    'EFI_DEVICE_PATH_PROTOCOL', 'EFI_DISCONNECT_CONTROLLER',
    'EFI_EVENT', 'EFI_EVENT_NOTIFY', 'EFI_EXIT',
    'EFI_EXIT_BOOT_SERVICES', 'EFI_FORM_ID', 'EFI_FREE_PAGES',
    'EFI_FREE_POOL', 'EFI_GET_MEMORY_MAP',
    'EFI_GET_NEXT_HIGH_MONO_COUNT', 'EFI_GET_NEXT_MONOTONIC_COUNT',
    'EFI_GET_NEXT_VARIABLE_NAME', 'EFI_GET_TIME', 'EFI_GET_VARIABLE',
    'EFI_GET_WAKEUP_TIME', 'EFI_GLYPH_GIBT_END_BLOCK', 'EFI_GUID',
    'EFI_HANDLE', 'EFI_HANDLE_PROTOCOL',
    'EFI_HII_AIBT_CLEAR_IMAGES_BLOCK',
    'EFI_HII_AIBT_CLEAR_IMAGES_LOOP_BLOCK',
    'EFI_HII_AIBT_DUPLICATE_BLOCK', 'EFI_HII_AIBT_EXT1_BLOCK',
    'EFI_HII_AIBT_EXT2_BLOCK', 'EFI_HII_AIBT_EXT4_BLOCK',
    'EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK',
    'EFI_HII_AIBT_OVERLAY_IMAGES_LOOP_BLOCK',
    'EFI_HII_AIBT_RESTORE_SCRN_BLOCK',
    'EFI_HII_AIBT_RESTORE_SCRN_LOOP_BLOCK',
    'EFI_HII_AIBT_SKIP1_BLOCK', 'EFI_HII_AIBT_SKIP2_BLOCK',
    'EFI_HII_ANIMATION_BLOCK', 'EFI_HII_ANIMATION_CELL',
    'EFI_HII_ANIMATION_PACKAGE_HDR', 'EFI_HII_DATE',
    'EFI_HII_DEVICE_PATH_PACKAGE_HDR', 'EFI_HII_FONT_PACKAGE_HDR',
    'EFI_HII_FONT_STYLE', 'EFI_HII_FORM_PACKAGE_HDR',
    'EFI_HII_GIBT_DEFAULTS_BLOCK', 'EFI_HII_GIBT_DUPLICATE_BLOCK',
    'EFI_HII_GIBT_EXT1_BLOCK', 'EFI_HII_GIBT_EXT2_BLOCK',
    'EFI_HII_GIBT_EXT4_BLOCK', 'EFI_HII_GIBT_GLYPHS_BLOCK',
    'EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK', 'EFI_HII_GIBT_GLYPH_BLOCK',
    'EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK', 'EFI_HII_GIBT_SKIP1_BLOCK',
    'EFI_HII_GIBT_SKIP2_BLOCK', 'EFI_HII_GLYPH_BLOCK',
    'EFI_HII_GLYPH_INFO', 'EFI_HII_GUID_PACKAGE_HDR',
    'EFI_HII_HANDLE', 'EFI_HII_IIBT_DUPLICATE_BLOCK',
    'EFI_HII_IIBT_END_BLOCK', 'EFI_HII_IIBT_EXT1_BLOCK',
    'EFI_HII_IIBT_EXT2_BLOCK', 'EFI_HII_IIBT_EXT4_BLOCK',
    'EFI_HII_IIBT_IMAGE_1BIT_BASE', 'EFI_HII_IIBT_IMAGE_1BIT_BLOCK',
    'EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK',
    'EFI_HII_IIBT_IMAGE_24BIT_BASE', 'EFI_HII_IIBT_IMAGE_24BIT_BLOCK',
    'EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK',
    'EFI_HII_IIBT_IMAGE_4BIT_BASE', 'EFI_HII_IIBT_IMAGE_4BIT_BLOCK',
    'EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK',
    'EFI_HII_IIBT_IMAGE_8BIT_BASE', 'EFI_HII_IIBT_IMAGE_8BIT_BLOCK',
    'EFI_HII_IIBT_IMAGE_8BIT_TRAN_BLOCK', 'EFI_HII_IIBT_JPEG_BLOCK',
    'EFI_HII_IIBT_SKIP1_BLOCK', 'EFI_HII_IIBT_SKIP2_BLOCK',
    'EFI_HII_IMAGE_BLOCK', 'EFI_HII_IMAGE_PACKAGE_HDR',
    'EFI_HII_IMAGE_PALETTE_INFO', 'EFI_HII_IMAGE_PALETTE_INFO_HEADER',
    'EFI_HII_KEYBOARD_LAYOUT', 'EFI_HII_KEYBOARD_PACKAGE_HDR',
    'EFI_HII_PACKAGE_HEADER', 'EFI_HII_PACKAGE_LIST_HEADER',
    'EFI_HII_REF', 'EFI_HII_RGB_PIXEL',
    'EFI_HII_SIBT_DUPLICATE_BLOCK', 'EFI_HII_SIBT_END_BLOCK',
    'EFI_HII_SIBT_EXT1_BLOCK', 'EFI_HII_SIBT_EXT2_BLOCK',
    'EFI_HII_SIBT_EXT4_BLOCK', 'EFI_HII_SIBT_FONT_BLOCK',
    'EFI_HII_SIBT_SKIP1_BLOCK', 'EFI_HII_SIBT_SKIP2_BLOCK',
    'EFI_HII_SIBT_STRINGS_SCSU_BLOCK',
    'EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK',
    'EFI_HII_SIBT_STRINGS_UCS2_BLOCK',
    'EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK',
    'EFI_HII_SIBT_STRING_SCSU_BLOCK',
    'EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK',
    'EFI_HII_SIBT_STRING_UCS2_BLOCK',
    'EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK',
    'EFI_HII_SIMPLE_FONT_PACKAGE_HDR', 'EFI_HII_STRING_BLOCK',
    'EFI_HII_STRING_PACKAGE_HDR', 'EFI_HII_TIME', 'EFI_IFR_ACTION',
    'EFI_IFR_ACTION_1', 'EFI_IFR_ADD', 'EFI_IFR_AND',
    'EFI_IFR_ANIMATION', 'EFI_IFR_BITWISE_AND', 'EFI_IFR_BITWISE_NOT',
    'EFI_IFR_BITWISE_OR', 'EFI_IFR_CATENATE', 'EFI_IFR_CHECKBOX',
    'EFI_IFR_CONDITIONAL', 'EFI_IFR_DATE', 'EFI_IFR_DEFAULT',
    'EFI_IFR_DEFAULTSTORE', 'EFI_IFR_DEFAULT_2', 'EFI_IFR_DISABLE_IF',
    'EFI_IFR_DIVIDE', 'EFI_IFR_DUP', 'EFI_IFR_END', 'EFI_IFR_EQUAL',
    'EFI_IFR_EQ_ID_ID', 'EFI_IFR_EQ_ID_VAL', 'EFI_IFR_EQ_ID_VAL_LIST',
    'EFI_IFR_FALSE', 'EFI_IFR_FIND', 'EFI_IFR_FORM',
    'EFI_IFR_FORM_MAP', 'EFI_IFR_FORM_MAP_METHOD', 'EFI_IFR_FORM_SET',
    'EFI_IFR_GET', 'EFI_IFR_GRAY_OUT_IF', 'EFI_IFR_GREATER_EQUAL',
    'EFI_IFR_GREATER_THAN', 'EFI_IFR_GUID', 'EFI_IFR_IMAGE',
    'EFI_IFR_INCONSISTENT_IF', 'EFI_IFR_LENGTH', 'EFI_IFR_LESS_EQUAL',
    'EFI_IFR_LESS_THAN', 'EFI_IFR_LOCKED', 'EFI_IFR_MAP',
    'EFI_IFR_MATCH', 'EFI_IFR_MID', 'EFI_IFR_MODAL_TAG',
    'EFI_IFR_MODULO', 'EFI_IFR_MULTIPLY', 'EFI_IFR_NOT',
    'EFI_IFR_NOT_EQUAL', 'EFI_IFR_NO_SUBMIT_IF', 'EFI_IFR_NUMERIC',
    'EFI_IFR_ONE', 'EFI_IFR_ONES', 'EFI_IFR_ONE_OF',
    'EFI_IFR_ONE_OF_OPTION', 'EFI_IFR_OP_HEADER', 'EFI_IFR_OR',
    'EFI_IFR_ORDERED_LIST', 'EFI_IFR_PASSWORD',
    'EFI_IFR_QUESTION_HEADER', 'EFI_IFR_QUESTION_REF1',
    'EFI_IFR_QUESTION_REF2', 'EFI_IFR_QUESTION_REF3',
    'EFI_IFR_QUESTION_REF3_2', 'EFI_IFR_QUESTION_REF3_3',
    'EFI_IFR_READ', 'EFI_IFR_REF', 'EFI_IFR_REF2', 'EFI_IFR_REF3',
    'EFI_IFR_REF4', 'EFI_IFR_REF5', 'EFI_IFR_REFRESH',
    'EFI_IFR_REFRESH_ID', 'EFI_IFR_RESET_BUTTON', 'EFI_IFR_RULE',
    'EFI_IFR_RULE_REF', 'EFI_IFR_SECURITY', 'EFI_IFR_SET',
    'EFI_IFR_SHIFT_LEFT', 'EFI_IFR_SHIFT_RIGHT', 'EFI_IFR_SPAN',
    'EFI_IFR_STATEMENT_HEADER', 'EFI_IFR_STRING',
    'EFI_IFR_STRING_REF1', 'EFI_IFR_STRING_REF2', 'EFI_IFR_SUBTITLE',
    'EFI_IFR_SUBTRACT', 'EFI_IFR_SUPPRESS_IF', 'EFI_IFR_TEXT',
    'EFI_IFR_THIS', 'EFI_IFR_TIME', 'EFI_IFR_TOKEN',
    'EFI_IFR_TO_BOOLEAN', 'EFI_IFR_TO_LOWER', 'EFI_IFR_TO_STRING',
    'EFI_IFR_TO_UINT', 'EFI_IFR_TO_UPPER', 'EFI_IFR_TRUE',
    'EFI_IFR_TYPE_VALUE', 'EFI_IFR_UINT16', 'EFI_IFR_UINT32',
    'EFI_IFR_UINT64', 'EFI_IFR_UINT8', 'EFI_IFR_UNDEFINED',
    'EFI_IFR_VALUE', 'EFI_IFR_VARSTORE', 'EFI_IFR_VARSTORE_DEVICE',
    'EFI_IFR_VARSTORE_EFI', 'EFI_IFR_VARSTORE_NAME_VALUE',
    'EFI_IFR_VERSION', 'EFI_IFR_WARNING_IF', 'EFI_IFR_WRITE',
    'EFI_IFR_ZERO', 'EFI_IMAGE_ENTRY_POINT', 'EFI_IMAGE_ID',
    'EFI_IMAGE_LOAD', 'EFI_IMAGE_START', 'EFI_IMAGE_UNLOAD',
    'EFI_INPUT_KEY', 'EFI_INPUT_READ_KEY', 'EFI_INPUT_RESET',
    'EFI_INSTALL_CONFIGURATION_TABLE',
    'EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES',
    'EFI_INSTALL_PROTOCOL_INTERFACE', 'EFI_INTERFACE_TYPE',
    'EFI_INTERFACE_TYPE__enumvalues', 'EFI_IP_ADDRESS',
    'EFI_IPv4_ADDRESS', 'EFI_IPv6_ADDRESS', 'EFI_KEY',
    'EFI_KEY_DESCRIPTOR', 'EFI_KEY_OPTION', 'EFI_KEY__enumvalues',
    'EFI_LBA', 'EFI_LOCATE_DEVICE_PATH', 'EFI_LOCATE_HANDLE',
    'EFI_LOCATE_HANDLE_BUFFER', 'EFI_LOCATE_PROTOCOL',
    'EFI_LOCATE_SEARCH_TYPE', 'EFI_LOCATE_SEARCH_TYPE__enumvalues',
    'EFI_MAC_ADDRESS', 'EFI_MEMORY_DESCRIPTOR', 'EFI_MEMORY_TYPE',
    'EFI_MEMORY_TYPE__enumvalues', 'EFI_NARROW_GLYPH',
    'EFI_NATIVE_INTERFACE', 'EFI_OPEN_PROTOCOL',
    'EFI_OPEN_PROTOCOL_INFORMATION',
    'EFI_OPEN_PROTOCOL_INFORMATION_ENTRY', 'EFI_PARTITION_ENTRY',
    'EFI_PARTITION_TABLE_HEADER', 'EFI_PHYSICAL_ADDRESS',
    'EFI_PROTOCOLS_PER_HANDLE', 'EFI_QUERY_CAPSULE_CAPABILITIES',
    'EFI_QUERY_VARIABLE_INFO', 'EFI_QUESTION_ID', 'EFI_RAISE_TPL',
    'EFI_REGISTER_PROTOCOL_NOTIFY',
    'EFI_REINSTALL_PROTOCOL_INTERFACE', 'EFI_RESET_SYSTEM',
    'EFI_RESET_TYPE', 'EFI_RESET_TYPE__enumvalues', 'EFI_RESTORE_TPL',
    'EFI_RUNTIME_SERVICES', 'EFI_SET_MEM', 'EFI_SET_TIME',
    'EFI_SET_TIMER', 'EFI_SET_VARIABLE',
    'EFI_SET_VIRTUAL_ADDRESS_MAP', 'EFI_SET_WAKEUP_TIME',
    'EFI_SET_WATCHDOG_TIMER', 'EFI_SIGNAL_EVENT',
    'EFI_SIMPLE_TEXT_INPUT_PROTOCOL', 'EFI_SIMPLE_TEXT_OUTPUT_MODE',
    'EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL', 'EFI_STALL', 'EFI_STATUS',
    'EFI_STRING', 'EFI_STRING_ID', 'EFI_SYSTEM_TABLE',
    'EFI_TABLE_HEADER', 'EFI_TEXT_CLEAR_SCREEN',
    'EFI_TEXT_ENABLE_CURSOR', 'EFI_TEXT_QUERY_MODE', 'EFI_TEXT_RESET',
    'EFI_TEXT_SET_ATTRIBUTE', 'EFI_TEXT_SET_CURSOR_POSITION',
    'EFI_TEXT_SET_MODE', 'EFI_TEXT_STRING', 'EFI_TEXT_TEST_STRING',
    'EFI_TIME', 'EFI_TIMER_DELAY', 'EFI_TIMER_DELAY__enumvalues',
    'EFI_TIME_CAPABILITIES', 'EFI_TPL',
    'EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES',
    'EFI_UNINSTALL_PROTOCOL_INTERFACE', 'EFI_UPDATE_CAPSULE',
    'EFI_VARIABLE_AUTHENTICATION', 'EFI_VARIABLE_AUTHENTICATION_2',
    'EFI_VARSTORE_ID', 'EFI_VIRTUAL_ADDRESS', 'EFI_WAIT_FOR_EVENT',
    'EFI_WIDE_GLYPH', 'EfiACPIMemoryNVS', 'EfiACPIReclaimMemory',
    'EfiBootServicesCode', 'EfiBootServicesData',
    'EfiConventionalMemory', 'EfiKeyA0', 'EfiKeyA2', 'EfiKeyA3',
    'EfiKeyA4', 'EfiKeyAsterisk', 'EfiKeyB0', 'EfiKeyB1', 'EfiKeyB10',
    'EfiKeyB2', 'EfiKeyB3', 'EfiKeyB4', 'EfiKeyB5', 'EfiKeyB6',
    'EfiKeyB7', 'EfiKeyB8', 'EfiKeyB9', 'EfiKeyBackSpace', 'EfiKeyC1',
    'EfiKeyC10', 'EfiKeyC11', 'EfiKeyC12', 'EfiKeyC2', 'EfiKeyC3',
    'EfiKeyC4', 'EfiKeyC5', 'EfiKeyC6', 'EfiKeyC7', 'EfiKeyC8',
    'EfiKeyC9', 'EfiKeyCapsLock', 'EfiKeyD1', 'EfiKeyD10',
    'EfiKeyD11', 'EfiKeyD12', 'EfiKeyD13', 'EfiKeyD2', 'EfiKeyD3',
    'EfiKeyD4', 'EfiKeyD5', 'EfiKeyD6', 'EfiKeyD7', 'EfiKeyD8',
    'EfiKeyD9', 'EfiKeyDel', 'EfiKeyDownArrow', 'EfiKeyE0',
    'EfiKeyE1', 'EfiKeyE10', 'EfiKeyE11', 'EfiKeyE12', 'EfiKeyE2',
    'EfiKeyE3', 'EfiKeyE4', 'EfiKeyE5', 'EfiKeyE6', 'EfiKeyE7',
    'EfiKeyE8', 'EfiKeyE9', 'EfiKeyEight', 'EfiKeyEnd', 'EfiKeyEnter',
    'EfiKeyEsc', 'EfiKeyF1', 'EfiKeyF10', 'EfiKeyF11', 'EfiKeyF12',
    'EfiKeyF2', 'EfiKeyF3', 'EfiKeyF4', 'EfiKeyF5', 'EfiKeyF6',
    'EfiKeyF7', 'EfiKeyF8', 'EfiKeyF9', 'EfiKeyFive', 'EfiKeyFour',
    'EfiKeyHome', 'EfiKeyIns', 'EfiKeyLAlt', 'EfiKeyLCtrl',
    'EfiKeyLShift', 'EfiKeyLeftArrow', 'EfiKeyMinus', 'EfiKeyNLck',
    'EfiKeyNine', 'EfiKeyOne', 'EfiKeyPause', 'EfiKeyPeriod',
    'EfiKeyPgDn', 'EfiKeyPgUp', 'EfiKeyPlus', 'EfiKeyPrint',
    'EfiKeyRCtrl', 'EfiKeyRShift', 'EfiKeyRightArrow', 'EfiKeySLck',
    'EfiKeySeven', 'EfiKeySix', 'EfiKeySlash', 'EfiKeySpaceBar',
    'EfiKeyTab', 'EfiKeyThree', 'EfiKeyTwo', 'EfiKeyUpArrow',
    'EfiKeyZero', 'EfiLoaderCode', 'EfiLoaderData',
    'EfiMaxMemoryType', 'EfiMemoryMappedIO',
    'EfiMemoryMappedIOPortSpace', 'EfiPalCode',
    'EfiReservedMemoryType', 'EfiResetCold',
    'EfiResetPlatformSpecific', 'EfiResetShutdown', 'EfiResetWarm',
    'EfiRuntimeServicesCode', 'EfiRuntimeServicesData',
    'EfiUnusableMemory', 'GUID', 'INT16', 'INT32',
    'ImageBaseOffset32', 'MINMAXSTEP_DATA', 'MaxAllocateType',
    'PEFI_BOOT_KEY_DATA', 'PEFI_BOOT_SERVICES',
    'PEFI_CAPSULE_BLOCK_DESCRIPTOR', 'PEFI_CAPSULE_HEADER',
    'PEFI_CAPSULE_TABLE', 'PEFI_CONFIGURATION_TABLE',
    'PEFI_DEVICE_PATH_PROTOCOL', 'PEFI_HII_DATE',
    'PEFI_HII_KEYBOARD_LAYOUT', 'PEFI_HII_KEYBOARD_PACKAGE_HDR',
    'PEFI_HII_PACKAGE_HEADER', 'PEFI_HII_PACKAGE_LIST_HEADER',
    'PEFI_HII_REF', 'PEFI_HII_STRING_BLOCK', 'PEFI_HII_TIME',
    'PEFI_IFR_TYPE_VALUE', 'PEFI_INPUT_KEY', 'PEFI_IP_ADDRESS',
    'PEFI_IPv4_ADDRESS', 'PEFI_IPv6_ADDRESS', 'PEFI_KEY_DESCRIPTOR',
    'PEFI_KEY_OPTION', 'PEFI_MAC_ADDRESS', 'PEFI_MEMORY_DESCRIPTOR',
    'PEFI_NARROW_GLYPH', 'PEFI_OPEN_PROTOCOL_INFORMATION_ENTRY',
    'PEFI_PARTITION_ENTRY', 'PEFI_PARTITION_TABLE_HEADER',
    'PEFI_RUNTIME_SERVICES', 'PEFI_SIMPLE_TEXT_OUTPUT_MODE',
    'PEFI_SYSTEM_TABLE', 'PEFI_TABLE_HEADER', 'PEFI_TIME',
    'PEFI_TIME_CAPABILITIES', 'PEFI_VARIABLE_AUTHENTICATION',
    'PEFI_VARIABLE_AUTHENTICATION_2', 'PEFI_WIDE_GLYPH', 'PGUID',
    'PMINMAXSTEP_DATA', 'PWIN_CERTIFICATE',
    'PWIN_CERTIFICATE_UEFI_GUID', 'PXE_BOOL', 'PXE_CDB',
    'PXE_CONTROL', 'PXE_CPB_FILL_HEADER',
    'PXE_CPB_FILL_HEADER_FRAGMENTED', 'PXE_CPB_INITIALIZE',
    'PXE_CPB_MCAST_IP_TO_MAC', 'PXE_CPB_NVDATA_BULK',
    'PXE_CPB_NVDATA_SPARSE', 'PXE_CPB_RECEIVE',
    'PXE_CPB_RECEIVE_FILTERS', 'PXE_CPB_START_30', 'PXE_CPB_START_31',
    'PXE_CPB_STATION_ADDRESS', 'PXE_CPB_TRANSMIT',
    'PXE_CPB_TRANSMIT_FRAGMENTS', 'PXE_DB_GET_CONFIG_INFO',
    'PXE_DB_GET_INIT_INFO', 'PXE_DB_GET_STATUS', 'PXE_DB_INITIALIZE',
    'PXE_DB_MCAST_IP_TO_MAC', 'PXE_DB_NVDATA', 'PXE_DB_RECEIVE',
    'PXE_DB_RECEIVE_FILTERS', 'PXE_DB_STATION_ADDRESS',
    'PXE_DB_STATISTICS', 'PXE_DEVICE', 'PXE_FRAME_TYPE',
    'PXE_HW_UNDI', 'PXE_IFNUM', 'PXE_IFTYPE', 'PXE_IPV4', 'PXE_IPV6',
    'PXE_IP_ADDR', 'PXE_MAC_ADDR', 'PXE_MEDIA_PROTOCOL', 'PXE_OPCODE',
    'PXE_OPFLAGS', 'PXE_PCC_CONFIG_INFO', 'PXE_PCI_CONFIG_INFO',
    'PXE_STATCODE', 'PXE_STATFLAGS', 'PXE_SW_UNDI', 'PXE_UINT16',
    'PXE_UINT32', 'PXE_UINT64', 'PXE_UINT8', 'PXE_UINTN', 'PXE_UNDI',
    'PXE_VOID', 'P_EFI_GLYPH_GIBT_END_BLOCK',
    'P_EFI_HII_AIBT_CLEAR_IMAGES_BLOCK',
    'P_EFI_HII_AIBT_DUPLICATE_BLOCK', 'P_EFI_HII_AIBT_EXT1_BLOCK',
    'P_EFI_HII_AIBT_EXT2_BLOCK', 'P_EFI_HII_AIBT_EXT4_BLOCK',
    'P_EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK',
    'P_EFI_HII_AIBT_RESTORE_SCRN_BLOCK', 'P_EFI_HII_AIBT_SKIP1_BLOCK',
    'P_EFI_HII_AIBT_SKIP2_BLOCK', 'P_EFI_HII_ANIMATION_BLOCK',
    'P_EFI_HII_ANIMATION_CELL', 'P_EFI_HII_ANIMATION_PACKAGE_HDR',
    'P_EFI_HII_DEVICE_PATH_PACKAGE_HDR', 'P_EFI_HII_FONT_PACKAGE_HDR',
    'P_EFI_HII_FORM_PACKAGE_HDR', 'P_EFI_HII_GIBT_DEFAULTS_BLOCK',
    'P_EFI_HII_GIBT_DUPLICATE_BLOCK', 'P_EFI_HII_GIBT_EXT1_BLOCK',
    'P_EFI_HII_GIBT_EXT2_BLOCK', 'P_EFI_HII_GIBT_EXT4_BLOCK',
    'P_EFI_HII_GIBT_GLYPHS_BLOCK',
    'P_EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK',
    'P_EFI_HII_GIBT_GLYPH_BLOCK',
    'P_EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK',
    'P_EFI_HII_GIBT_SKIP1_BLOCK', 'P_EFI_HII_GIBT_SKIP2_BLOCK',
    'P_EFI_HII_GLYPH_BLOCK', 'P_EFI_HII_GLYPH_INFO',
    'P_EFI_HII_GUID_PACKAGE_HDR', 'P_EFI_HII_IIBT_DUPLICATE_BLOCK',
    'P_EFI_HII_IIBT_END_BLOCK', 'P_EFI_HII_IIBT_EXT1_BLOCK',
    'P_EFI_HII_IIBT_EXT2_BLOCK', 'P_EFI_HII_IIBT_EXT4_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_1BIT_BASE',
    'P_EFI_HII_IIBT_IMAGE_1BIT_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_24BIT_BASE',
    'P_EFI_HII_IIBT_IMAGE_24BIT_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_4BIT_BASE',
    'P_EFI_HII_IIBT_IMAGE_4BIT_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_8BIT_BASE',
    'P_EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK',
    'P_EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK',
    'P_EFI_HII_IIBT_JPEG_BLOCK', 'P_EFI_HII_IIBT_SKIP1_BLOCK',
    'P_EFI_HII_IIBT_SKIP2_BLOCK', 'P_EFI_HII_IMAGE_BLOCK',
    'P_EFI_HII_IMAGE_PACKAGE_HDR', 'P_EFI_HII_IMAGE_PALETTE_INFO',
    'P_EFI_HII_IMAGE_PALETTE_INFO_HEADER', 'P_EFI_HII_RGB_PIXEL',
    'P_EFI_HII_SIBT_DUPLICATE_BLOCK', 'P_EFI_HII_SIBT_END_BLOCK',
    'P_EFI_HII_SIBT_EXT1_BLOCK', 'P_EFI_HII_SIBT_EXT2_BLOCK',
    'P_EFI_HII_SIBT_EXT4_BLOCK', 'P_EFI_HII_SIBT_FONT_BLOCK',
    'P_EFI_HII_SIBT_SKIP1_BLOCK', 'P_EFI_HII_SIBT_SKIP2_BLOCK',
    'P_EFI_HII_SIBT_STRINGS_SCSU_BLOCK',
    'P_EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK',
    'P_EFI_HII_SIBT_STRINGS_UCS2_BLOCK',
    'P_EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK',
    'P_EFI_HII_SIBT_STRING_SCSU_BLOCK',
    'P_EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK',
    'P_EFI_HII_SIBT_STRING_UCS2_BLOCK',
    'P_EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK',
    'P_EFI_HII_SIMPLE_FONT_PACKAGE_HDR',
    'P_EFI_HII_STRING_PACKAGE_HDR', 'P_EFI_IFR_ACTION',
    'P_EFI_IFR_ACTION_1', 'P_EFI_IFR_ADD', 'P_EFI_IFR_AND',
    'P_EFI_IFR_ANIMATION', 'P_EFI_IFR_BITWISE_AND',
    'P_EFI_IFR_BITWISE_NOT', 'P_EFI_IFR_BITWISE_OR',
    'P_EFI_IFR_CATENATE', 'P_EFI_IFR_CHECKBOX',
    'P_EFI_IFR_CONDITIONAL', 'P_EFI_IFR_DATE', 'P_EFI_IFR_DEFAULT',
    'P_EFI_IFR_DEFAULTSTORE', 'P_EFI_IFR_DEFAULT_2',
    'P_EFI_IFR_DISABLE_IF', 'P_EFI_IFR_DIVIDE', 'P_EFI_IFR_DUP',
    'P_EFI_IFR_END', 'P_EFI_IFR_EQUAL', 'P_EFI_IFR_EQ_ID_ID',
    'P_EFI_IFR_EQ_ID_VAL', 'P_EFI_IFR_EQ_ID_VAL_LIST',
    'P_EFI_IFR_FALSE', 'P_EFI_IFR_FIND', 'P_EFI_IFR_FORM',
    'P_EFI_IFR_FORM_MAP', 'P_EFI_IFR_FORM_MAP_METHOD',
    'P_EFI_IFR_FORM_SET', 'P_EFI_IFR_GET', 'P_EFI_IFR_GRAY_OUT_IF',
    'P_EFI_IFR_GREATER_EQUAL', 'P_EFI_IFR_GREATER_THAN',
    'P_EFI_IFR_GUID', 'P_EFI_IFR_IMAGE', 'P_EFI_IFR_INCONSISTENT_IF',
    'P_EFI_IFR_LENGTH', 'P_EFI_IFR_LESS_EQUAL', 'P_EFI_IFR_LESS_THAN',
    'P_EFI_IFR_LOCKED', 'P_EFI_IFR_MAP', 'P_EFI_IFR_MATCH',
    'P_EFI_IFR_MID', 'P_EFI_IFR_MODAL_TAG', 'P_EFI_IFR_MODULO',
    'P_EFI_IFR_MULTIPLY', 'P_EFI_IFR_NOT', 'P_EFI_IFR_NOT_EQUAL',
    'P_EFI_IFR_NO_SUBMIT_IF', 'P_EFI_IFR_NUMERIC', 'P_EFI_IFR_ONE',
    'P_EFI_IFR_ONES', 'P_EFI_IFR_ONE_OF', 'P_EFI_IFR_ONE_OF_OPTION',
    'P_EFI_IFR_OP_HEADER', 'P_EFI_IFR_OR', 'P_EFI_IFR_ORDERED_LIST',
    'P_EFI_IFR_PASSWORD', 'P_EFI_IFR_QUESTION_HEADER',
    'P_EFI_IFR_QUESTION_REF1', 'P_EFI_IFR_QUESTION_REF2',
    'P_EFI_IFR_QUESTION_REF3', 'P_EFI_IFR_QUESTION_REF3_2',
    'P_EFI_IFR_QUESTION_REF3_3', 'P_EFI_IFR_READ', 'P_EFI_IFR_REF',
    'P_EFI_IFR_REF2', 'P_EFI_IFR_REF3', 'P_EFI_IFR_REF4',
    'P_EFI_IFR_REF5', 'P_EFI_IFR_REFRESH', 'P_EFI_IFR_REFRESH_ID',
    'P_EFI_IFR_RESET_BUTTON', 'P_EFI_IFR_RULE', 'P_EFI_IFR_RULE_REF',
    'P_EFI_IFR_SECURITY', 'P_EFI_IFR_SET', 'P_EFI_IFR_SHIFT_LEFT',
    'P_EFI_IFR_SHIFT_RIGHT', 'P_EFI_IFR_SPAN',
    'P_EFI_IFR_STATEMENT_HEADER', 'P_EFI_IFR_STRING',
    'P_EFI_IFR_STRING_REF1', 'P_EFI_IFR_STRING_REF2',
    'P_EFI_IFR_SUBTITLE', 'P_EFI_IFR_SUBTRACT',
    'P_EFI_IFR_SUPPRESS_IF', 'P_EFI_IFR_TEXT', 'P_EFI_IFR_THIS',
    'P_EFI_IFR_TIME', 'P_EFI_IFR_TOKEN', 'P_EFI_IFR_TO_BOOLEAN',
    'P_EFI_IFR_TO_LOWER', 'P_EFI_IFR_TO_STRING', 'P_EFI_IFR_TO_UINT',
    'P_EFI_IFR_TO_UPPER', 'P_EFI_IFR_TRUE', 'P_EFI_IFR_UINT16',
    'P_EFI_IFR_UINT32', 'P_EFI_IFR_UINT64', 'P_EFI_IFR_UINT8',
    'P_EFI_IFR_UNDEFINED', 'P_EFI_IFR_VALUE', 'P_EFI_IFR_VARSTORE',
    'P_EFI_IFR_VARSTORE_DEVICE', 'P_EFI_IFR_VARSTORE_EFI',
    'P_EFI_IFR_VARSTORE_NAME_VALUE', 'P_EFI_IFR_VERSION',
    'P_EFI_IFR_WARNING_IF', 'P_EFI_IFR_WRITE', 'P_EFI_IFR_ZERO',
    'P_EFI_SIMPLE_TEXT_INPUT_PROTOCOL',
    'P_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL', 'P_struct_113',
    'P_struct_121', 'P_struct_124', 'P_struct_230', 'P_struct_231',
    'P_struct_232', 'P_struct_233', 'P_struct_86', 'P_struct_94',
    'P_union_101', 'P_union_114', 'P_union_117', 'P_union_202',
    'P_union_311', 'P_union_313', 'P_union_78', 'P_union_99',
    'Ppxe_device', 'Ps_pxe_cdb', 'Ps_pxe_cpb_fill_header',
    'Ps_pxe_cpb_fill_header_fragmented', 'Ps_pxe_cpb_initialize',
    'Ps_pxe_cpb_mcast_ip_to_mac', 'Ps_pxe_cpb_nvdata_sparse',
    'Ps_pxe_cpb_receive', 'Ps_pxe_cpb_receive_filters',
    'Ps_pxe_cpb_start_30', 'Ps_pxe_cpb_start_31',
    'Ps_pxe_cpb_station_address', 'Ps_pxe_cpb_transmit',
    'Ps_pxe_cpb_transmit_fragments', 'Ps_pxe_db_get_init_info',
    'Ps_pxe_db_get_status', 'Ps_pxe_db_initialize',
    'Ps_pxe_db_mcast_ip_to_mac', 'Ps_pxe_db_nvdata',
    'Ps_pxe_db_receive', 'Ps_pxe_db_receive_filters',
    'Ps_pxe_db_statistics', 'Ps_pxe_dpb_station_address',
    'Ps_pxe_hw_undi', 'Ps_pxe_pcc_config_info',
    'Ps_pxe_pci_config_info', 'Ps_pxe_sw_undi',
    'Pu_pxe_cpb_nvdata_bulk', 'Pu_pxe_db_get_config_info',
    'Pu_pxe_ip_addr', 'Pu_pxe_undi', 'RETURN_STATUS', 'TimerCancel',
    'TimerPeriodic', 'TimerRelative', 'UINT16', 'UINT32', 'UINT64',
    'UINT8', 'UINTN', 'WIN_CERTIFICATE', 'WIN_CERTIFICATE_UEFI_GUID',
    '_EFI_GLYPH_GIBT_END_BLOCK', '_EFI_HII_AIBT_CLEAR_IMAGES_BLOCK',
    '_EFI_HII_AIBT_DUPLICATE_BLOCK', '_EFI_HII_AIBT_EXT1_BLOCK',
    '_EFI_HII_AIBT_EXT2_BLOCK', '_EFI_HII_AIBT_EXT4_BLOCK',
    '_EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK',
    '_EFI_HII_AIBT_RESTORE_SCRN_BLOCK', '_EFI_HII_AIBT_SKIP1_BLOCK',
    '_EFI_HII_AIBT_SKIP2_BLOCK', '_EFI_HII_ANIMATION_BLOCK',
    '_EFI_HII_ANIMATION_CELL', '_EFI_HII_ANIMATION_PACKAGE_HDR',
    '_EFI_HII_DEVICE_PATH_PACKAGE_HDR', '_EFI_HII_FONT_PACKAGE_HDR',
    '_EFI_HII_FORM_PACKAGE_HDR', '_EFI_HII_GIBT_DEFAULTS_BLOCK',
    '_EFI_HII_GIBT_DUPLICATE_BLOCK', '_EFI_HII_GIBT_EXT1_BLOCK',
    '_EFI_HII_GIBT_EXT2_BLOCK', '_EFI_HII_GIBT_EXT4_BLOCK',
    '_EFI_HII_GIBT_GLYPHS_BLOCK',
    '_EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK', '_EFI_HII_GIBT_GLYPH_BLOCK',
    '_EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK', '_EFI_HII_GIBT_SKIP1_BLOCK',
    '_EFI_HII_GIBT_SKIP2_BLOCK', '_EFI_HII_GLYPH_BLOCK',
    '_EFI_HII_GLYPH_INFO', '_EFI_HII_GUID_PACKAGE_HDR',
    '_EFI_HII_IIBT_DUPLICATE_BLOCK', '_EFI_HII_IIBT_END_BLOCK',
    '_EFI_HII_IIBT_EXT1_BLOCK', '_EFI_HII_IIBT_EXT2_BLOCK',
    '_EFI_HII_IIBT_EXT4_BLOCK', '_EFI_HII_IIBT_IMAGE_1BIT_BASE',
    '_EFI_HII_IIBT_IMAGE_1BIT_BLOCK',
    '_EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK',
    '_EFI_HII_IIBT_IMAGE_24BIT_BASE',
    '_EFI_HII_IIBT_IMAGE_24BIT_BLOCK',
    '_EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK',
    '_EFI_HII_IIBT_IMAGE_4BIT_BASE', '_EFI_HII_IIBT_IMAGE_4BIT_BLOCK',
    '_EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK',
    '_EFI_HII_IIBT_IMAGE_8BIT_BASE',
    '_EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK',
    '_EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK',
    '_EFI_HII_IIBT_JPEG_BLOCK', '_EFI_HII_IIBT_SKIP1_BLOCK',
    '_EFI_HII_IIBT_SKIP2_BLOCK', '_EFI_HII_IMAGE_BLOCK',
    '_EFI_HII_IMAGE_PACKAGE_HDR', '_EFI_HII_IMAGE_PALETTE_INFO',
    '_EFI_HII_IMAGE_PALETTE_INFO_HEADER', '_EFI_HII_RGB_PIXEL',
    '_EFI_HII_SIBT_DUPLICATE_BLOCK', '_EFI_HII_SIBT_END_BLOCK',
    '_EFI_HII_SIBT_EXT1_BLOCK', '_EFI_HII_SIBT_EXT2_BLOCK',
    '_EFI_HII_SIBT_EXT4_BLOCK', '_EFI_HII_SIBT_FONT_BLOCK',
    '_EFI_HII_SIBT_SKIP1_BLOCK', '_EFI_HII_SIBT_SKIP2_BLOCK',
    '_EFI_HII_SIBT_STRINGS_SCSU_BLOCK',
    '_EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK',
    '_EFI_HII_SIBT_STRINGS_UCS2_BLOCK',
    '_EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK',
    '_EFI_HII_SIBT_STRING_SCSU_BLOCK',
    '_EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK',
    '_EFI_HII_SIBT_STRING_UCS2_BLOCK',
    '_EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK',
    '_EFI_HII_SIMPLE_FONT_PACKAGE_HDR', '_EFI_HII_STRING_PACKAGE_HDR',
    '_EFI_IFR_ACTION', '_EFI_IFR_ACTION_1', '_EFI_IFR_ADD',
    '_EFI_IFR_AND', '_EFI_IFR_ANIMATION', '_EFI_IFR_BITWISE_AND',
    '_EFI_IFR_BITWISE_NOT', '_EFI_IFR_BITWISE_OR',
    '_EFI_IFR_CATENATE', '_EFI_IFR_CHECKBOX', '_EFI_IFR_CONDITIONAL',
    '_EFI_IFR_DATE', '_EFI_IFR_DEFAULT', '_EFI_IFR_DEFAULTSTORE',
    '_EFI_IFR_DEFAULT_2', '_EFI_IFR_DISABLE_IF', '_EFI_IFR_DIVIDE',
    '_EFI_IFR_DUP', '_EFI_IFR_END', '_EFI_IFR_EQUAL',
    '_EFI_IFR_EQ_ID_ID', '_EFI_IFR_EQ_ID_VAL',
    '_EFI_IFR_EQ_ID_VAL_LIST', '_EFI_IFR_FALSE', '_EFI_IFR_FIND',
    '_EFI_IFR_FORM', '_EFI_IFR_FORM_MAP', '_EFI_IFR_FORM_MAP_METHOD',
    '_EFI_IFR_FORM_SET', '_EFI_IFR_GET', '_EFI_IFR_GRAY_OUT_IF',
    '_EFI_IFR_GREATER_EQUAL', '_EFI_IFR_GREATER_THAN',
    '_EFI_IFR_GUID', '_EFI_IFR_IMAGE', '_EFI_IFR_INCONSISTENT_IF',
    '_EFI_IFR_LENGTH', '_EFI_IFR_LESS_EQUAL', '_EFI_IFR_LESS_THAN',
    '_EFI_IFR_LOCKED', '_EFI_IFR_MAP', '_EFI_IFR_MATCH',
    '_EFI_IFR_MID', '_EFI_IFR_MODAL_TAG', '_EFI_IFR_MODULO',
    '_EFI_IFR_MULTIPLY', '_EFI_IFR_NOT', '_EFI_IFR_NOT_EQUAL',
    '_EFI_IFR_NO_SUBMIT_IF', '_EFI_IFR_NUMERIC', '_EFI_IFR_ONE',
    '_EFI_IFR_ONES', '_EFI_IFR_ONE_OF', '_EFI_IFR_ONE_OF_OPTION',
    '_EFI_IFR_OP_HEADER', '_EFI_IFR_OR', '_EFI_IFR_ORDERED_LIST',
    '_EFI_IFR_PASSWORD', '_EFI_IFR_QUESTION_HEADER',
    '_EFI_IFR_QUESTION_REF1', '_EFI_IFR_QUESTION_REF2',
    '_EFI_IFR_QUESTION_REF3', '_EFI_IFR_QUESTION_REF3_2',
    '_EFI_IFR_QUESTION_REF3_3', '_EFI_IFR_READ', '_EFI_IFR_REF',
    '_EFI_IFR_REF2', '_EFI_IFR_REF3', '_EFI_IFR_REF4',
    '_EFI_IFR_REF5', '_EFI_IFR_REFRESH', '_EFI_IFR_REFRESH_ID',
    '_EFI_IFR_RESET_BUTTON', '_EFI_IFR_RULE', '_EFI_IFR_RULE_REF',
    '_EFI_IFR_SECURITY', '_EFI_IFR_SET', '_EFI_IFR_SHIFT_LEFT',
    '_EFI_IFR_SHIFT_RIGHT', '_EFI_IFR_SPAN',
    '_EFI_IFR_STATEMENT_HEADER', '_EFI_IFR_STRING',
    '_EFI_IFR_STRING_REF1', '_EFI_IFR_STRING_REF2',
    '_EFI_IFR_SUBTITLE', '_EFI_IFR_SUBTRACT', '_EFI_IFR_SUPPRESS_IF',
    '_EFI_IFR_TEXT', '_EFI_IFR_THIS', '_EFI_IFR_TIME',
    '_EFI_IFR_TOKEN', '_EFI_IFR_TO_BOOLEAN', '_EFI_IFR_TO_LOWER',
    '_EFI_IFR_TO_STRING', '_EFI_IFR_TO_UINT', '_EFI_IFR_TO_UPPER',
    '_EFI_IFR_TRUE', '_EFI_IFR_UINT16', '_EFI_IFR_UINT32',
    '_EFI_IFR_UINT64', '_EFI_IFR_UINT8', '_EFI_IFR_UNDEFINED',
    '_EFI_IFR_VALUE', '_EFI_IFR_VARSTORE', '_EFI_IFR_VARSTORE_DEVICE',
    '_EFI_IFR_VARSTORE_EFI', '_EFI_IFR_VARSTORE_NAME_VALUE',
    '_EFI_IFR_VERSION', '_EFI_IFR_WARNING_IF', '_EFI_IFR_WRITE',
    '_EFI_IFR_ZERO', '_EFI_SIMPLE_TEXT_INPUT_PROTOCOL',
    '_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL', '_struct_113', '_struct_121',
    '_struct_124', '_struct_230', '_struct_231', '_struct_232',
    '_struct_233', '_struct_86', '_struct_94', '_union_101',
    '_union_114', '_union_117', '_union_202', '_union_311',
    '_union_313', '_union_78', '_union_99', 'byte', 'dword', 'enum_1',
    'enum_13', 'enum_317', 'enum_69', 'enum_71', 'enum_73', 'enum_74',
    'enum_76', 'longlong', 'pxe_device', 'qword', 's_pxe_cdb',
    's_pxe_cpb_fill_header', 's_pxe_cpb_fill_header_fragmented',
    's_pxe_cpb_initialize', 's_pxe_cpb_mcast_ip_to_mac',
    's_pxe_cpb_nvdata_sparse', 's_pxe_cpb_receive',
    's_pxe_cpb_receive_filters', 's_pxe_cpb_start_30',
    's_pxe_cpb_start_31', 's_pxe_cpb_station_address',
    's_pxe_cpb_transmit', 's_pxe_cpb_transmit_fragments',
    's_pxe_db_get_init_info', 's_pxe_db_get_status',
    's_pxe_db_initialize', 's_pxe_db_mcast_ip_to_mac',
    's_pxe_db_nvdata', 's_pxe_db_receive', 's_pxe_db_receive_filters',
    's_pxe_db_statistics', 's_pxe_dpb_station_address',
    's_pxe_hw_undi', 's_pxe_pcc_config_info', 's_pxe_pci_config_info',
    's_pxe_sw_undi', 'struct_EFI_BOOT_SERVICES',
    'struct_EFI_CAPSULE_BLOCK_DESCRIPTOR',
    'struct_EFI_CAPSULE_HEADER', 'struct_EFI_CAPSULE_TABLE',
    'struct_EFI_CONFIGURATION_TABLE',
    'struct_EFI_DEVICE_PATH_PROTOCOL', 'struct_EFI_HII_DATE',
    'struct_EFI_HII_KEYBOARD_LAYOUT',
    'struct_EFI_HII_KEYBOARD_PACKAGE_HDR',
    'struct_EFI_HII_PACKAGE_HEADER',
    'struct_EFI_HII_PACKAGE_LIST_HEADER', 'struct_EFI_HII_REF',
    'struct_EFI_HII_STRING_BLOCK', 'struct_EFI_HII_TIME',
    'struct_EFI_INPUT_KEY', 'struct_EFI_IPv4_ADDRESS',
    'struct_EFI_IPv6_ADDRESS', 'struct_EFI_KEY_DESCRIPTOR',
    'struct_EFI_KEY_OPTION', 'struct_EFI_MAC_ADDRESS',
    'struct_EFI_MEMORY_DESCRIPTOR', 'struct_EFI_NARROW_GLYPH',
    'struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY',
    'struct_EFI_PARTITION_ENTRY', 'struct_EFI_PARTITION_TABLE_HEADER',
    'struct_EFI_RUNTIME_SERVICES',
    'struct_EFI_SIMPLE_TEXT_OUTPUT_MODE', 'struct_EFI_SYSTEM_TABLE',
    'struct_EFI_TABLE_HEADER', 'struct_EFI_TIME',
    'struct_EFI_TIME_CAPABILITIES',
    'struct_EFI_VARIABLE_AUTHENTICATION',
    'struct_EFI_VARIABLE_AUTHENTICATION_2', 'struct_EFI_WIDE_GLYPH',
    'struct_GUID', 'struct_WIN_CERTIFICATE',
    'struct_WIN_CERTIFICATE_UEFI_GUID',
    'struct__EFI_GLYPH_GIBT_END_BLOCK',
    'struct__EFI_HII_AIBT_CLEAR_IMAGES_BLOCK',
    'struct__EFI_HII_AIBT_DUPLICATE_BLOCK',
    'struct__EFI_HII_AIBT_EXT1_BLOCK',
    'struct__EFI_HII_AIBT_EXT2_BLOCK',
    'struct__EFI_HII_AIBT_EXT4_BLOCK',
    'struct__EFI_HII_AIBT_OVERLAY_IMAGES_BLOCK',
    'struct__EFI_HII_AIBT_RESTORE_SCRN_BLOCK',
    'struct__EFI_HII_AIBT_SKIP1_BLOCK',
    'struct__EFI_HII_AIBT_SKIP2_BLOCK',
    'struct__EFI_HII_ANIMATION_BLOCK',
    'struct__EFI_HII_ANIMATION_CELL',
    'struct__EFI_HII_ANIMATION_PACKAGE_HDR',
    'struct__EFI_HII_DEVICE_PATH_PACKAGE_HDR',
    'struct__EFI_HII_FONT_PACKAGE_HDR',
    'struct__EFI_HII_FORM_PACKAGE_HDR',
    'struct__EFI_HII_GIBT_DEFAULTS_BLOCK',
    'struct__EFI_HII_GIBT_DUPLICATE_BLOCK',
    'struct__EFI_HII_GIBT_EXT1_BLOCK',
    'struct__EFI_HII_GIBT_EXT2_BLOCK',
    'struct__EFI_HII_GIBT_EXT4_BLOCK',
    'struct__EFI_HII_GIBT_GLYPHS_BLOCK',
    'struct__EFI_HII_GIBT_GLYPHS_DEFAULT_BLOCK',
    'struct__EFI_HII_GIBT_GLYPH_BLOCK',
    'struct__EFI_HII_GIBT_GLYPH_DEFAULT_BLOCK',
    'struct__EFI_HII_GIBT_SKIP1_BLOCK',
    'struct__EFI_HII_GIBT_SKIP2_BLOCK', 'struct__EFI_HII_GLYPH_BLOCK',
    'struct__EFI_HII_GLYPH_INFO', 'struct__EFI_HII_GUID_PACKAGE_HDR',
    'struct__EFI_HII_IIBT_DUPLICATE_BLOCK',
    'struct__EFI_HII_IIBT_END_BLOCK',
    'struct__EFI_HII_IIBT_EXT1_BLOCK',
    'struct__EFI_HII_IIBT_EXT2_BLOCK',
    'struct__EFI_HII_IIBT_EXT4_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_1BIT_BASE',
    'struct__EFI_HII_IIBT_IMAGE_1BIT_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_1BIT_TRANS_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_24BIT_BASE',
    'struct__EFI_HII_IIBT_IMAGE_24BIT_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_24BIT_TRANS_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_4BIT_BASE',
    'struct__EFI_HII_IIBT_IMAGE_4BIT_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_4BIT_TRANS_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_8BIT_BASE',
    'struct__EFI_HII_IIBT_IMAGE_8BIT_PALETTE_BLOCK',
    'struct__EFI_HII_IIBT_IMAGE_8BIT_TRANS_BLOCK',
    'struct__EFI_HII_IIBT_JPEG_BLOCK',
    'struct__EFI_HII_IIBT_SKIP1_BLOCK',
    'struct__EFI_HII_IIBT_SKIP2_BLOCK', 'struct__EFI_HII_IMAGE_BLOCK',
    'struct__EFI_HII_IMAGE_PACKAGE_HDR',
    'struct__EFI_HII_IMAGE_PALETTE_INFO',
    'struct__EFI_HII_IMAGE_PALETTE_INFO_HEADER',
    'struct__EFI_HII_RGB_PIXEL',
    'struct__EFI_HII_SIBT_DUPLICATE_BLOCK',
    'struct__EFI_HII_SIBT_END_BLOCK',
    'struct__EFI_HII_SIBT_EXT1_BLOCK',
    'struct__EFI_HII_SIBT_EXT2_BLOCK',
    'struct__EFI_HII_SIBT_EXT4_BLOCK',
    'struct__EFI_HII_SIBT_FONT_BLOCK',
    'struct__EFI_HII_SIBT_SKIP1_BLOCK',
    'struct__EFI_HII_SIBT_SKIP2_BLOCK',
    'struct__EFI_HII_SIBT_STRINGS_SCSU_BLOCK',
    'struct__EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK',
    'struct__EFI_HII_SIBT_STRINGS_UCS2_BLOCK',
    'struct__EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK',
    'struct__EFI_HII_SIBT_STRING_SCSU_BLOCK',
    'struct__EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK',
    'struct__EFI_HII_SIBT_STRING_UCS2_BLOCK',
    'struct__EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK',
    'struct__EFI_HII_SIMPLE_FONT_PACKAGE_HDR',
    'struct__EFI_HII_STRING_PACKAGE_HDR', 'struct__EFI_IFR_ACTION',
    'struct__EFI_IFR_ACTION_1', 'struct__EFI_IFR_ADD',
    'struct__EFI_IFR_AND', 'struct__EFI_IFR_ANIMATION',
    'struct__EFI_IFR_BITWISE_AND', 'struct__EFI_IFR_BITWISE_NOT',
    'struct__EFI_IFR_BITWISE_OR', 'struct__EFI_IFR_CATENATE',
    'struct__EFI_IFR_CHECKBOX', 'struct__EFI_IFR_CONDITIONAL',
    'struct__EFI_IFR_DATE', 'struct__EFI_IFR_DEFAULT',
    'struct__EFI_IFR_DEFAULTSTORE', 'struct__EFI_IFR_DEFAULT_2',
    'struct__EFI_IFR_DISABLE_IF', 'struct__EFI_IFR_DIVIDE',
    'struct__EFI_IFR_DUP', 'struct__EFI_IFR_END',
    'struct__EFI_IFR_EQUAL', 'struct__EFI_IFR_EQ_ID_ID',
    'struct__EFI_IFR_EQ_ID_VAL', 'struct__EFI_IFR_EQ_ID_VAL_LIST',
    'struct__EFI_IFR_FALSE', 'struct__EFI_IFR_FIND',
    'struct__EFI_IFR_FORM', 'struct__EFI_IFR_FORM_MAP',
    'struct__EFI_IFR_FORM_MAP_METHOD', 'struct__EFI_IFR_FORM_SET',
    'struct__EFI_IFR_GET', 'struct__EFI_IFR_GRAY_OUT_IF',
    'struct__EFI_IFR_GREATER_EQUAL', 'struct__EFI_IFR_GREATER_THAN',
    'struct__EFI_IFR_GUID', 'struct__EFI_IFR_IMAGE',
    'struct__EFI_IFR_INCONSISTENT_IF', 'struct__EFI_IFR_LENGTH',
    'struct__EFI_IFR_LESS_EQUAL', 'struct__EFI_IFR_LESS_THAN',
    'struct__EFI_IFR_LOCKED', 'struct__EFI_IFR_MAP',
    'struct__EFI_IFR_MATCH', 'struct__EFI_IFR_MID',
    'struct__EFI_IFR_MODAL_TAG', 'struct__EFI_IFR_MODULO',
    'struct__EFI_IFR_MULTIPLY', 'struct__EFI_IFR_NOT',
    'struct__EFI_IFR_NOT_EQUAL', 'struct__EFI_IFR_NO_SUBMIT_IF',
    'struct__EFI_IFR_NUMERIC', 'struct__EFI_IFR_ONE',
    'struct__EFI_IFR_ONES', 'struct__EFI_IFR_ONE_OF',
    'struct__EFI_IFR_ONE_OF_OPTION', 'struct__EFI_IFR_OP_HEADER',
    'struct__EFI_IFR_OR', 'struct__EFI_IFR_ORDERED_LIST',
    'struct__EFI_IFR_PASSWORD', 'struct__EFI_IFR_QUESTION_HEADER',
    'struct__EFI_IFR_QUESTION_REF1', 'struct__EFI_IFR_QUESTION_REF2',
    'struct__EFI_IFR_QUESTION_REF3',
    'struct__EFI_IFR_QUESTION_REF3_2',
    'struct__EFI_IFR_QUESTION_REF3_3', 'struct__EFI_IFR_READ',
    'struct__EFI_IFR_REF', 'struct__EFI_IFR_REF2',
    'struct__EFI_IFR_REF3', 'struct__EFI_IFR_REF4',
    'struct__EFI_IFR_REF5', 'struct__EFI_IFR_REFRESH',
    'struct__EFI_IFR_REFRESH_ID', 'struct__EFI_IFR_RESET_BUTTON',
    'struct__EFI_IFR_RULE', 'struct__EFI_IFR_RULE_REF',
    'struct__EFI_IFR_SECURITY', 'struct__EFI_IFR_SET',
    'struct__EFI_IFR_SHIFT_LEFT', 'struct__EFI_IFR_SHIFT_RIGHT',
    'struct__EFI_IFR_SPAN', 'struct__EFI_IFR_STATEMENT_HEADER',
    'struct__EFI_IFR_STRING', 'struct__EFI_IFR_STRING_REF1',
    'struct__EFI_IFR_STRING_REF2', 'struct__EFI_IFR_SUBTITLE',
    'struct__EFI_IFR_SUBTRACT', 'struct__EFI_IFR_SUPPRESS_IF',
    'struct__EFI_IFR_TEXT', 'struct__EFI_IFR_THIS',
    'struct__EFI_IFR_TIME', 'struct__EFI_IFR_TOKEN',
    'struct__EFI_IFR_TO_BOOLEAN', 'struct__EFI_IFR_TO_LOWER',
    'struct__EFI_IFR_TO_STRING', 'struct__EFI_IFR_TO_UINT',
    'struct__EFI_IFR_TO_UPPER', 'struct__EFI_IFR_TRUE',
    'struct__EFI_IFR_UINT16', 'struct__EFI_IFR_UINT32',
    'struct__EFI_IFR_UINT64', 'struct__EFI_IFR_UINT8',
    'struct__EFI_IFR_UNDEFINED', 'struct__EFI_IFR_VALUE',
    'struct__EFI_IFR_VARSTORE', 'struct__EFI_IFR_VARSTORE_DEVICE',
    'struct__EFI_IFR_VARSTORE_EFI',
    'struct__EFI_IFR_VARSTORE_NAME_VALUE', 'struct__EFI_IFR_VERSION',
    'struct__EFI_IFR_WARNING_IF', 'struct__EFI_IFR_WRITE',
    'struct__EFI_IFR_ZERO', 'struct__EFI_SIMPLE_TEXT_INPUT_PROTOCOL',
    'struct__EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL', 'struct__struct_113',
    'struct__struct_121', 'struct__struct_124', 'struct__struct_230',
    'struct__struct_231', 'struct__struct_232', 'struct__struct_233',
    'struct__struct_86', 'struct__struct_94', 'struct_s_pxe_cdb',
    'struct_s_pxe_cpb_fill_header',
    'struct_s_pxe_cpb_fill_header_fragmented',
    'struct_s_pxe_cpb_initialize', 'struct_s_pxe_cpb_mcast_ip_to_mac',
    'struct_s_pxe_cpb_nvdata_sparse', 'struct_s_pxe_cpb_receive',
    'struct_s_pxe_cpb_receive_filters', 'struct_s_pxe_cpb_start_30',
    'struct_s_pxe_cpb_start_31', 'struct_s_pxe_cpb_station_address',
    'struct_s_pxe_cpb_transmit',
    'struct_s_pxe_cpb_transmit_fragments',
    'struct_s_pxe_db_get_init_info', 'struct_s_pxe_db_get_status',
    'struct_s_pxe_db_initialize', 'struct_s_pxe_db_mcast_ip_to_mac',
    'struct_s_pxe_db_nvdata', 'struct_s_pxe_db_receive',
    'struct_s_pxe_db_receive_filters', 'struct_s_pxe_db_statistics',
    'struct_s_pxe_dpb_station_address', 'struct_s_pxe_hw_undi',
    'struct_s_pxe_pcc_config_info', 'struct_s_pxe_pci_config_info',
    'struct_s_pxe_sw_undi', 'u_pxe_cpb_nvdata_bulk',
    'u_pxe_db_get_config_info', 'u_pxe_ip_addr', 'u_pxe_undi',
    'uchar', 'uint', 'ulonglong', 'undefined', 'undefined1',
    'undefined2', 'undefined4', 'undefined8',
    'union_EFI_BOOT_KEY_DATA', 'union_EFI_IFR_TYPE_VALUE',
    'union_EFI_IP_ADDRESS', 'union_MINMAXSTEP_DATA',
    'union__union_101', 'union__union_114', 'union__union_117',
    'union__union_202', 'union__union_311', 'union__union_313',
    'union__union_78', 'union__union_99', 'union_pxe_device',
    'union_u_pxe_cpb_nvdata_bulk', 'union_u_pxe_db_get_config_info',
    'union_u_pxe_ip_addr', 'union_u_pxe_undi', 'ushort', 'word']

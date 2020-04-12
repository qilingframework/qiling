#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

##############################################
# These are part of the core.py Qiling class #
# Functions below are imported at runtime    #
##############################################

import struct
from .const import *

def unpack64(self, x):
    return struct.unpack('Q', x)[0]

def pack64(self, x):
    return struct.pack('Q', x)

def pack64s(self, x):
    return struct.pack('q', x)

def unpack64s(self, x):
    return struct.unpack('q', x)[0]

def unpack32(self, x):
    if self.archendian == QL_ENDIAN_EB:
        return struct.unpack('>I', x)[0]
    else:
        return struct.unpack('I', x)[0]

def pack32(self, x):
    if self.archendian == QL_ENDIAN_EB:
        return struct.pack('>I', x)
    else:
        return struct.pack('I', x)

def unpack32s(self, x):
    if self.archendian == QL_ENDIAN_EB:
        return struct.unpack('>i', x)[0]
    else:
        return struct.unpack('i', x)[0]

def unpack32s_ne(self, x):
    return struct.unpack('i', x)[0]

def pack32s(self, x):
    if self.archendian == QL_ENDIAN_EB:
        return struct.pack('>i', x)
    else:
        return struct.pack('i', x)

def unpack16(self, x):
    if self.archendian == QL_ENDIAN_EB:
        return struct.unpack('>H', x)[0]
    else:
        return struct.unpack('H', x)[0]

def pack16(self, x):
    if self.archendian == QL_ENDIAN_EB:
        return struct.pack('>H', x)
    else:
        return struct.pack('H', x)

def pack(self, data):
    if self.archbit == 64:
        return self.pack64(data)
    elif self.archbit == 32:
        return self.pack32(data)
    else:
        raise

def packs(self, data):
    if self.archbit == 64:
        return self.pack64s(data)
    elif self.archbit == 32:
        return self.pack32s(data)
    else:
        raise

def unpack(self, data):
    if self.archbit == 64:
        return self.unpack64(data)
    elif self.archbit == 32:
        return self.unpack32(data)
    else:
        raise

def unpacks(self, data):
    if self.archbit == 64:
        return self.unpack64s(data)
    elif self.archbit == 32:
        return self.unpack32s(data)
    else:
        raise
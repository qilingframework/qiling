#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

##############################################
# These are part of the core.py Qiling class #
# handling structure packing and unpacking   #
# for different architecture bits            #
##############################################

import struct
from .const import QL_ENDIAN
from .exception import QlErrorStructConversion

# Don't assume self is Qiling.
class QlCoreStructs:
    def __init__(self, endian, bit):
        self._endian = endian
        self._bit = bit

    def pack64(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.pack('>Q', x)
        else:
            return struct.pack('Q', x)

    def pack64s(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.pack('>q', x)
        else:
            return struct.pack('q', x)

    def unpack64(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.unpack('>Q', x)[0]
        else:
            return struct.unpack('Q', x)[0]

    def unpack64s(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.unpack('>q', x)[0]
        else:
            return struct.unpack('q', x)[0]

    def pack32(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.pack('>I', x)
        else:
            return struct.pack('I', x)

    def pack32s(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.pack('>i', x)
        else:
            return struct.pack('i', x)

    def unpack32(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.unpack('>I', x)[0]
        else:
            return struct.unpack('I', x)[0]

    def unpack32s(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.unpack('>i', x)[0]
        else:
            return struct.unpack('i', x)[0]

    def pack16(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.pack('>H', x)
        else:
            return struct.pack('H', x)

    def pack16s(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.pack('>h', x)
        else:
            return struct.pack('h', x)

    def unpack16(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.unpack('>H', x)[0]
        else:
            return struct.unpack('H', x)[0]

    def unpack16s(self, x):
        if self._endian == QL_ENDIAN.EB:
            return struct.unpack('>h', x)[0]
        else:
            return struct.unpack('h', x)[0]

    def pack(self, data):
        if self._bit == 64:
            return self.pack64(data)
        elif self._bit == 32:
            return self.pack32(data)
        elif self._bit == 16:
            return self.pack16(data)
        raise QlErrorStructConversion("[!] Qiling pack conversion failed!")

    def packs(self, data):
        if self._bit == 64:
            return self.pack64s(data)
        elif self._bit == 32:
            return self.pack32s(data)
        elif self._bit == 16:
            return self.pack16s(data)
        raise QlErrorStructConversion("[!] Qiling packs conversion failed!")

    def unpack(self, data):
        if self._bit == 64:
            return self.unpack64(data)
        elif self._bit == 32:
            return self.unpack32(data)
        elif self._bit == 16:
            return self.unpack16(data)
        raise QlErrorStructConversion("[!] Qiling unpack conversion failed!")

    def unpacks(self, data):
        if self._bit == 64:
            return self.unpack64s(data)
        elif self._bit == 32:
            return self.unpack32s(data)
        elif self._bit == 16:
            return self.unpack16s(data)
        raise QlErrorStructConversion("[!] Qiling unpacks conversion failed!")

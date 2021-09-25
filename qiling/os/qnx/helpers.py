#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from ctypes import c_int32

class QnxConn:
    def __init__(self, pid, chid, fd = None):
        self.__pid = pid   # Process Id
        self.__chid = chid # Channel Id
        self.__fd = fd     # File Descriptor

    @property
    def chid(self):
        return self.__chid

    @property
    def fd(self):
        return self.__fd

    @fd.setter
    def fd(self, value):
        self.__fd = value

    @property
    def pid(self):
        return self.__pid

def get_message_body(ql, msg, parts):
    parts = c_int32(parts).value
    if parts >= 0:
        return ql.mem.read(ql.unpack32(ql.mem.read(msg, 4)), ql.unpack32(ql.mem.read(msg + 4, 4)))
    elif parts < 0:
        return ql.mem.read(msg, -parts)

def ux32s(value):
    return "0x%s" % ("00000000%x" % (value & 0xffffffff))[-8:]

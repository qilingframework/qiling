#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)


import os
import json
import sys
from Registry import Registry
from qiling.os.windows.const import *
from qiling.exception import *


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

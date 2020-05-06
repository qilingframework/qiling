#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import read_cstring, read_wstring, read_guid, print_function

DWORD = 1
UINT = 1
INT = 1
BOOL = 1
SIZE_T = 1
BYTE = 1
ULONGLONG = 2
HANDLE = 3
POINTER = 3
STRING = 4
WSTRING = 5
STRING_ADDR = 6
WSTRING_ADDR = 7
GUID = 8

def dxeapi(param_num=None, params=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            class hook_context:
                EFI_MAX_BIT = 0x8000000000000000
                EFI_SUCCESS = 0
                EFI_LOAD_ERROR = EFI_MAX_BIT | 1
                EFI_INVALID_PARAMETER = EFI_MAX_BIT | 2
                EFI_UNSUPPORTED = EFI_MAX_BIT | 3
                EFI_BAD_BUFFER_SIZE = EFI_MAX_BIT | 4
                EFI_BUFFER_TOO_SMALL = EFI_MAX_BIT | 5
                EFI_NOT_READY = EFI_MAX_BIT | 6
                EFI_DEVICE_ERROR = EFI_MAX_BIT | 7
                EFI_WRITE_PROTECTED = EFI_MAX_BIT | 8
                EFI_OUT_OF_RESOURCES = EFI_MAX_BIT | 9
                EFI_VOLUME_CORRUPTED = EFI_MAX_BIT | 10
                EFI_VOLUME_FULL = EFI_MAX_BIT | 11
                EFI_NO_MEDIA = EFI_MAX_BIT | 12
                EFI_MEDIA_CHANGED = EFI_MAX_BIT | 13
                EFI_NOT_FOUND = EFI_MAX_BIT | 14
                EFI_ACCESS_DENIED = EFI_MAX_BIT | 15
                EFI_NO_RESPONSE = EFI_MAX_BIT | 16
                EFI_NO_MAPPING = EFI_MAX_BIT | 17
                EFI_TIMEOUT = EFI_MAX_BIT | 18
                EFI_NOT_STARTED = EFI_MAX_BIT | 19
                EFI_ALREADY_STARTED = EFI_MAX_BIT | 20
                EFI_ABORTED = EFI_MAX_BIT | 21
                EFI_ICMP_ERROR = EFI_MAX_BIT | 22
                EFI_TFTP_ERROR = EFI_MAX_BIT | 23
                EFI_PROTOCOL_ERROR = EFI_MAX_BIT | 24
                EFI_INCOMPATIBLE_VERSION = EFI_MAX_BIT | 25
                EFI_SECURITY_VIOLATION = EFI_MAX_BIT | 26
                EFI_CRC_ERROR = EFI_MAX_BIT | 27
                EFI_END_OF_MEDIA = EFI_MAX_BIT | 28
                EFI_END_OF_FILE = EFI_MAX_BIT | 31
                EFI_INVALID_LANGUAGE = EFI_MAX_BIT | 32
                EFI_WARN_UNKNOWN_GLYPH = EFI_MAX_BIT | 1
                EFI_WARN_DELETE_FAILURE = EFI_MAX_BIT | 2
                EFI_WARN_WRITE_FAILURE = EFI_MAX_BIT | 3
                EFI_WARN_BUFFER_TOO_SMALL = EFI_MAX_BIT | 4

                SEARCHTYPE_AllHandles = 0
                SEARCHTYPE_ByRegisterNotify = 1
                SEARCHTYPE_ByProtoco = 2
                
                def __init__(self, ql):
                    self.PE_RUN = True
                    self.ql = ql
                def write_int32(self, address, num):
                    if self.ql.archendian == QL_ENDIAN.EL:
                        self.ql.mem.write(address, struct.pack('<I',(num)))
                    else:
                        self.ql.mem.write(address, struct.pack('>I',(num)))
                def write_int64(self, address, num):
                    if self.ql.archendian == QL_ENDIAN.EL:
                        self.ql.mem.write(address, struct.pack('<Q',(num)))
                    else:
                        self.ql.mem.write(address, struct.pack('>Q',(num)))
                def read_int64(self, address):
                    if self.ql.archendian == QL_ENDIAN.EL:
                        return struct.unpack('<Q', self.ql.mem.read(address, 8))[0]
                    else:
                        return struct.unpack('>Q',self.ql.mem.read(address, 8))[0]
            
            ql = args[0]
            ql.os.ctx = hook_context(ql)
            arg = (ql, ql.reg.arch_pc, {})
            f = func
            if func.__name__ in ql.loader.user_defined_api:
                f = ql.loader.user_defined_api[func.__name__]
            return x8664_fastcall(ql, param_num, params, f, arg, kwargs)

        return wrapper

    return decorator

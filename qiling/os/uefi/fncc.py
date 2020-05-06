#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.const import *

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

def _get_param_by_index(ql, index):
    if ql.archtype == QL_ARCH.X86:
        return _x86_get_params_by_index(ql, index)
    elif ql.archtype == QL_ARCH.X8664:
        return _x8664_get_params_by_index(ql, index)

def _x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)

def _x8664_get_params_by_index(ql, index):
    reg_list = ["rcx", "rdx", "r8", "r9"]
    if index < 4:
        return ql.reg.read(reg_list[index])

    index -= 4
    # skip ret_addr
    return ql.stack_read((index + 5) * 8)

def set_return_value(ql, ret):
    if ql.archtype == QL_ARCH.X86:
        ql.reg.eax = ret
    elif ql.archtype == QL_ARCH.X8664:
        ql.reg.rax = ret

def set_function_params(ql, in_params, out_params):
    index = 0
    for each in in_params:
        if in_params[each] == DWORD or in_params[each] == POINTER:
            out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == ULONGLONG:
            if ql.archtype == QL_ARCH.X86:
                low = _get_param_by_index(ql, index)
                index += 1
                high = _get_param_by_index(ql, index)
                out_params[each] = high << 32 + low
            else:
                out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == STRING or in_params[each] == STRING_ADDR:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                content = read_cstring(ql, ptr)
                if in_params[each] == STRING_ADDR:
                    out_params[each] = (ptr, content)
                else:
                    out_params[each] = content
        elif in_params[each] == WSTRING or in_params[each] == WSTRING_ADDR:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                content = read_wstring(ql, ptr)
                if in_params[each] == WSTRING_ADDR:
                    out_params[each] = (ptr, content)
                else:
                    out_params[each] = content
        elif in_params[each] == GUID:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = str(read_guid(ql, ptr))
        index += 1
    return index

def __x86_cc(ql, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_function_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)

    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[2], result)

    return result, param_num



def _call_api(ql, name, params, result, address, return_address):
    params_with_values = {}
    if name.startswith("hook_"):
        name = name.split("hook_", 1)[1]
        # printfs are shit
        if params is not None:
            set_function_params(ql, params, params_with_values)
    ql.os.syscalls.setdefault(name, []).append({
        "params": params_with_values,
        "result": result,
        "address": address,
        "return_address": return_address,
        "position": ql.os.syscalls_counter
    })

    ql.os.syscalls_counter += 1

def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)
    old_pc = ql.reg.arch_pc
    # append syscall to list
    _call_api(ql, func.__name__, params, result, old_pc, ql.stack_read(0))

    if ql.os.PE_RUN:
        ql.reg.arch_pc = ql.stack_pop()

    return result

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
            if func.__name__ in ql.loader.hook_override:
                f = ql.loader.hook_override[func.__name__]
            return x8664_fastcall(ql, param_num, params, f, arg, kwargs)

        return wrapper

    return decorator

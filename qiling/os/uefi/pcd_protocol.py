#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
from qiling.os.const import *
from .const import *
from .utils import *
from .pcd_protocol_type64 import *
from .fncc import *


@dxeapi(params={
    "SkuId": ULONGLONG,
})
def hook_SetSku(ql, address, params):
    ql.os.SkuId = params["SkuId"]

def check_args(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    if guid in ql.os.efi_pcd_protocol_storage:
        namespace = ql.os.efi_pcd_protocol_storage[guid]
        return (token in namespace, guid, token)
    return (False, guid, token)

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_Get8(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return ql.os.efi_pcd_protocol_storage[guid][token] & 0xff
    return 0

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_Get16(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return ql.os.efi_pcd_protocol_storage[guid][token] & 0xffff
    return 0

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_Get32(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return ql.os.efi_pcd_protocol_storage[guid][token] & 0xffffffff
    return 0

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_Get64(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return ql.os.efi_pcd_protocol_storage[guid][token] & 0xffffffffffffffff
    return 0

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_GetPtr(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return ql.os.efi_pcd_protocol_storage[guid][token] & 0xffffffffffffffff
    return 0

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_GetBool(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return ql.os.efi_pcd_protocol_storage[guid][token] & 1
    return 0


@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
})
def hook_GetSize(ql, address, params):
    arg_ok, guid, token = check_args(ql, address, params)
    if arg_ok:
        return len(ql.os.efi_pcd_protocol_storage[guid][token])
    return 0

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
    "Value": ULONGLONG,
})
def hook_Set8(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    ql.os.efi_pcd_protocol_storage[guid]= {token: params["Value"] & 0xff}
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
    "Value": ULONGLONG,
})
def hook_Set16(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    ql.os.efi_pcd_protocol_storage[guid]= {token: params["Value"] & 0xffff}
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
    "Value": UINT,
})
def hook_Set32(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    ql.os.efi_pcd_protocol_storage[guid]= {token: params["Value"] & 0xffffffff}
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
    "Value": ULONGLONG,
})
def hook_Set64(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    ql.os.efi_pcd_protocol_storage[guid]= {token: params["Value"] & 0xffffffffffffffff}
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
    "SizeOfValue": POINTER, #POINTER_T(ctypes.c_uint64)
    "Buffer": POINTER, #POINTER_T(None)
})
def hook_SetPtr(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    size = params["SizeOfValue"]
    buffer = params["Buffer"]
    buf = ql.loader.heap.alloc(size)
    ql.mem.write(buf, ql.mem.read(buffer, size))
    ql.os.efi_pcd_protocol_storage[guid]= {token: buf}
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": ULONGLONG,
    "Value": ULONGLONG,
})
def hook_SetBool(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    ql.os.efi_pcd_protocol_storage[guid]= {token: params["Value"] & 1}
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "CallBackToken": ULONGLONG,
    "CallBackFunction": POINTER,
})
def hook_CallbackOnSet(ql, address, params):
    guid = params["Guid"]
    return EFI_NOT_FOUND # let's see if we need to implement this.

@dxeapi(params={
    "Guid": GUID,
    "CallBackToken": ULONGLONG,
    "CallBackFunction": POINTER,
})
def hook_CancelCallback(ql, address, params):
    guid = params["Guid"]
    return EFI_NOT_FOUND # let's see if we need to implement this.

@dxeapi(params={
    "Guid": GUID,
    "TokenNumber": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_GetNextToken(ql, address, params):
    guid = params["Guid"]
    token = params["TokenNumber"]
    lst = list(ql.os.efi_pcd_protocol_storage[guid])
    try:
        index = lst.index(token)
        if index + 1 < len(lst):
            return lst[index + 1]
    except:
        pass
    return EFI_NOT_FOUND

@dxeapi(params={
    "Guid": POINTER,
})
def hook_GetNextTokenSpace(ql, address, params):
    guid = params["Guid"]
    lst = list(ql.os.efi_pcd_protocol_storage)
    try:
        index = lst.index(guid)
        if index + 1 < len(lst):
            return lst[index + 1]
    except:
        pass
    return EFI_NOT_FOUND



def install_EFI_PCD_PROTOCOL(ql, start_ptr):
    efi_pcd_protocol = EFI_PCD_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8
    efi_pcd_protocol.SetSku = ptr
    ql.hook_address(hook_SetSku, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Get8 = ptr
    ql.hook_address(hook_Get8, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Get16 = ptr
    ql.hook_address(hook_Get16, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Get32 = ptr
    ql.hook_address(hook_Get32, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Get64 = ptr
    ql.hook_address(hook_Get64, ptr)
    ptr += pointer_size
    efi_pcd_protocol.GetPtr = ptr
    ql.hook_address(hook_GetPtr, ptr)
    ptr += pointer_size
    efi_pcd_protocol.GetBool = ptr
    ql.hook_address(hook_GetBool, ptr)
    ptr += pointer_size
    efi_pcd_protocol.GetSize = ptr
    ql.hook_address(hook_GetSize, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Set8 = ptr
    ql.hook_address(hook_Set8, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Set16 = ptr
    ql.hook_address(hook_Set16, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Set32 = ptr
    ql.hook_address(hook_Set32, ptr)
    ptr += pointer_size
    efi_pcd_protocol.Set64 = ptr
    ql.hook_address(hook_Set64, ptr)
    ptr += pointer_size
    efi_pcd_protocol.SetPtr = ptr
    ql.hook_address(hook_SetPtr, ptr)
    ptr += pointer_size
    efi_pcd_protocol.SetBool = ptr
    ql.hook_address(hook_SetBool, ptr)
    ptr += pointer_size
    efi_pcd_protocol.CallbackOnSet = ptr
    ql.hook_address(hook_CallbackOnSet, ptr)
    ptr += pointer_size
    efi_pcd_protocol.CancelCallback = ptr
    ql.hook_address(hook_CancelCallback, ptr)
    ptr += pointer_size
    efi_pcd_protocol.GetNextToken = ptr
    ql.hook_address(hook_GetNextToken, ptr)
    ptr += pointer_size
    efi_pcd_protocol.GetNextTokenSpace = ptr
    ql.hook_address(hook_GetNextTokenSpace, ptr)
    ptr += pointer_size
    return (ptr, efi_pcd_protocol)


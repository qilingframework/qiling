from qiling.const import *
from qiling.os.const import *
from .const import *
from .utils import *
from .mm_access_type import *
from .fncc import *


@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
})
def hook_Open(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
})
def hook_Close(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
})
def hook_Lock(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
    "MmramMapSize": POINTER, #POINTER_T(ctypes.c_uint64)
    "MmramMap": POINTER, #POINTER_T(struct_EFI_MMRAM_DESCRIPTOR)
})
def hook_GetCapabilities(ql, address, params):
    write_int64(ql, params["MmramMapSize"], 0)
    if params['MmramMap'] != 0:
        write_int64(ql, params["MmramMap"], 0)
    return EFI_SUCCESS



def install_EFI_MM_ACCESS_PROTOCOL(ql, start_ptr):
    efi_mm_access_protocol = EFI_MM_ACCESS_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8
    efi_mm_access_protocol.Open = ptr
    ql.hook_address(hook_Open, ptr)
    ptr += pointer_size
    efi_mm_access_protocol.Close = ptr
    ql.hook_address(hook_Close, ptr)
    ptr += pointer_size
    efi_mm_access_protocol.Lock = ptr
    ql.hook_address(hook_Lock, ptr)
    ptr += pointer_size
    efi_mm_access_protocol.GetCapabilities = ptr
    ql.hook_address(hook_GetCapabilities, ptr)
    ptr += pointer_size
    return (ptr, efi_mm_access_protocol)


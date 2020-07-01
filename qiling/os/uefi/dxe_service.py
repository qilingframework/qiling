from qiling.const import *
from qiling.os.const import *
from .const import *
from .utils import *
from .dxe_service_type64 import *
from .fncc import *

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": ULONGLONG,
})
def hook_AddMemorySpace(ctx, address, params):
    return EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": ULONGLONG,
    "a4": POINTER, #POINTER_T(ctypes.c_uint64)
    "a5": POINTER, #POINTER_T(None)
    "a6": POINTER, #POINTER_T(None)
})
def hook_AllocateMemorySpace(ctx, address, params):
    return EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
})
def hook_FreeMemorySpace(ctx, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
})
def hook_RemoveMemorySpace(ctx, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR)
})
def hook_GetMemorySpaceDescriptor(ctx, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
})
def hook_SetMemorySpaceAttributes(ctx, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint64)
    "a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR))
})
def hook_GetMemorySpaceMap(ctx, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
})
def hook_AddIoSpace(ctx, address, params):
    return EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": ULONGLONG,
    "a4": POINTER, #POINTER_T(ctypes.c_uint64)
    "a5": POINTER, #POINTER_T(None)
    "a6": POINTER, #POINTER_T(None)
})
def hook_AllocateIoSpace(ctx, address, params):
    return EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
})
def hook_FreeIoSpace(ctx, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
})
def hook_RemoveIoSpace(ctx, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR)
})
def hook_GetIoSpaceDescriptor(ctx, address, params):
    return EFI_NOT_FOUND

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint64)
    "a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR))
})
def hook_GetIoSpaceMap(ctx, address, params):
    return EFI_OUT_OF_RESOURCES

@dxeapi(params={
})
def hook_Dispatch(ctx, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": GUID,
})
def hook_Schedule(ctx, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": GUID,
})
def hook_Trust(ctx, address, params):
    return EFI_NOT_FOUND

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": ULONGLONG,
    "a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_ProcessFirmwareVolume(ctx, address, params):
    return EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
})
def hook_SetMemorySpaceCapabilities(ctx, address, params):
    return EFI_UNSUPPORTED



def install_EFI_DXE_SERVICES(ql, start_ptr):
    efi_dxe_services = EFI_DXE_SERVICES()
    ptr = start_ptr
    pointer_size = 8
    efi_dxe_services.AddMemorySpace = ptr
    ql.hook_address(hook_AddMemorySpace, ptr)
    ptr += pointer_size
    efi_dxe_services.AllocateMemorySpace = ptr
    ql.hook_address(hook_AllocateMemorySpace, ptr)
    ptr += pointer_size
    efi_dxe_services.FreeMemorySpace = ptr
    ql.hook_address(hook_FreeMemorySpace, ptr)
    ptr += pointer_size
    efi_dxe_services.RemoveMemorySpace = ptr
    ql.hook_address(hook_RemoveMemorySpace, ptr)
    ptr += pointer_size
    efi_dxe_services.GetMemorySpaceDescriptor = ptr
    ql.hook_address(hook_GetMemorySpaceDescriptor, ptr)
    ptr += pointer_size
    efi_dxe_services.SetMemorySpaceAttributes = ptr
    ql.hook_address(hook_SetMemorySpaceAttributes, ptr)
    ptr += pointer_size
    efi_dxe_services.GetMemorySpaceMap = ptr
    ql.hook_address(hook_GetMemorySpaceMap, ptr)
    ptr += pointer_size
    efi_dxe_services.AddIoSpace = ptr
    ql.hook_address(hook_AddIoSpace, ptr)
    ptr += pointer_size
    efi_dxe_services.AllocateIoSpace = ptr
    ql.hook_address(hook_AllocateIoSpace, ptr)
    ptr += pointer_size
    efi_dxe_services.FreeIoSpace = ptr
    ql.hook_address(hook_FreeIoSpace, ptr)
    ptr += pointer_size
    efi_dxe_services.RemoveIoSpace = ptr
    ql.hook_address(hook_RemoveIoSpace, ptr)
    ptr += pointer_size
    efi_dxe_services.GetIoSpaceDescriptor = ptr
    ql.hook_address(hook_GetIoSpaceDescriptor, ptr)
    ptr += pointer_size
    efi_dxe_services.GetIoSpaceMap = ptr
    ql.hook_address(hook_GetIoSpaceMap, ptr)
    ptr += pointer_size
    efi_dxe_services.Dispatch = ptr
    ql.hook_address(hook_Dispatch, ptr)
    ptr += pointer_size
    efi_dxe_services.Schedule = ptr
    ql.hook_address(hook_Schedule, ptr)
    ptr += pointer_size
    efi_dxe_services.Trust = ptr
    ql.hook_address(hook_Trust, ptr)
    ptr += pointer_size
    efi_dxe_services.ProcessFirmwareVolume = ptr
    ql.hook_address(hook_ProcessFirmwareVolume, ptr)
    ptr += pointer_size
    efi_dxe_services.SetMemorySpaceCapabilities = ptr
    ql.hook_address(hook_SetMemorySpaceCapabilities, ptr)
    ptr += pointer_size
    return (ptr, efi_dxe_services)


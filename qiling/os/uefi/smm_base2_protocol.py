from qiling.const import *
from qiling.os.const import *
from .const import *
from .utils import *
from .smm_base2_type import *
from .fncc import *


@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_BASE2_PROTOCOL)
    "InSmram": POINTER, #POINTER_T(ctypes.c_ubyte)
})
def hook_InSmm(ql, address, params):
    write_int64(ql, params["InSmram"], 0)
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_BASE2_PROTOCOL)
    "Smst": POINTER, #POINTER_T(POINTER_T(struct__EFI_SMM_SYSTEM_TABLE2))
})
def hook_GetSmstLocation(ql, address, params):
    if params["Smst"] == 0:
        return EFI_INVALID_PARAMETER
    write_int64(ql, params["Smst"], ql.loader.mm_system_table_ptr)
    return EFI_SUCCESS


# mm_system_table functions

@dxeapi(params={
    "Procedure": POINTER,
    "CpuNumber": INT, 
    "ProcArguments": POINTER
})
def hook_mm_startup_this_ap(ql, address, params):
    return EFI_INVALID_PARAMETER

@dxeapi(params={
    "HandlerType": GUID, 
    "Context": POINTER, 
    "CommBuffer": POINTER, 
    "CommBufferSize": POINTER, 
})
def hook_mm_interrupt_manage(ql, address, params):
    return EFI_NOT_FOUND

@dxeapi(params={
    "Handler": POINTER, 
    "HandlerType": GUID, 
    "DispatchHandle": POINTER, 
})
def hook_mm_interrupt_register(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "DispatchHandle": POINTER, 
})
def hook_efi_mm_interrupt_unregister(ql, address, params):
    return EFI_SUCCESS

def install_EFI_SMM_BASE2_PROTOCOL(ql, start_ptr, efi_mm_system_table):
    efi_smm_base2_protocol = EFI_SMM_BASE2_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8
    efi_smm_base2_protocol.InSmm = ptr
    ql.hook_address(hook_InSmm, ptr)
    ptr += pointer_size
    efi_smm_base2_protocol.GetSmstLocation = ptr
    ql.hook_address(hook_GetSmstLocation, ptr)
    ptr += pointer_size

    # mm_system_table functions
    efi_mm_system_table.MmStartupThisAp = ptr
    ql.hook_address(hook_mm_startup_this_ap, ptr)
    ptr += pointer_size
    efi_mm_system_table.MmiManage = ptr
    ql.hook_address(hook_mm_interrupt_manage, ptr)
    ptr += pointer_size
    efi_mm_system_table.MmiHandlerRegister = ptr
    ql.hook_address(hook_mm_interrupt_register, ptr)
    ptr += pointer_size
    efi_mm_system_table.MmiHandlerUnRegister = ptr
    ql.hook_address(hook_efi_mm_interrupt_unregister, ptr)
    ptr += pointer_size

    return (ptr, efi_smm_base2_protocol, efi_mm_system_table)


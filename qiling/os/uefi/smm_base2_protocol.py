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
    return EFI_UNSUPPORTED # since InSmm always returns False, we should return EFI_UNSUPPORTED here, since we are not in SMM mode.



def install_EFI_SMM_BASE2_PROTOCOL(ql, start_ptr):
    efi_smm_base2_protocol = EFI_SMM_BASE2_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8
    efi_smm_base2_protocol.InSmm = ptr
    ql.hook_address(hook_InSmm, ptr)
    ptr += pointer_size
    efi_smm_base2_protocol.GetSmstLocation = ptr
    ql.hook_address(hook_GetSmstLocation, ptr)
    ptr += pointer_size
    return (ptr, efi_smm_base2_protocol)


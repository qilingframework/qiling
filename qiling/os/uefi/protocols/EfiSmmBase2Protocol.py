#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.const import *

from ..const import EFI_SUCCESS, EFI_INVALID_PARAMETER
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *
from ..smst import *

# @see: MdePkg\Include\Protocol\SmmBase2.h
class EFI_SMM_BASE2_PROTOCOL(STRUCT):
    EFI_SMM_BASE2_PROTOCOL = STRUCT

    _fields_ = [
        ('InSmm',           FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE2_PROTOCOL), PTR(BOOLEAN))),
        ('GetSmstLocation', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE2_PROTOCOL), PTR(PTR(EFI_SMM_SYSTEM_TABLE2)))),
    ]

@dxeapi(params = {
    "This":     POINTER,
    "InSmram":  POINTER
})
def hook_InSmm(ql: Qiling, address: int, params):
    ql.log.debug(f'InSmram = {ql.os.smm.active}')

    ql.mem.write_ptr(params["InSmram"], int(ql.os.smm.active), 1)

    return EFI_SUCCESS

@dxeapi(params = {
    "This": POINTER,
    "Smst": POINTER
})
def hook_GetSmstLocation(ql: Qiling, address: int, params):
    Smst = params["Smst"]

    if Smst == 0:
        return EFI_INVALID_PARAMETER

    ql.mem.write_ptr(Smst, ql.loader.gSmst)

    return EFI_SUCCESS

descriptor = {
    "guid" : "f4ccbfb7-f6e0-47fd-9dd4-10a8f150c191",
    "struct" : EFI_SMM_BASE2_PROTOCOL,
    "fields" : (
        ("InSmm",           hook_InSmm),
        ("GetSmstLocation", hook_GetSmstLocation)
    )
}

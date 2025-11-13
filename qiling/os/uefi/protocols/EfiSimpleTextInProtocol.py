#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.fncc import dxeapi
from qiling.os.uefi.utils import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import EFI_STATUS, EFI_EVENT


# @see: MdePkg/Include/Protocol/SimpleTextIn.h
class EFI_INPUT_KEY(STRUCT):
    _fields_ = [
        ('ScanCode',    UINT16),
        ('UnicodeChar', CHAR16)
    ]

class EFI_SIMPLE_TEXT_INPUT_PROTOCOL(STRUCT):
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL = STRUCT

    _fields_ = [
        ('Reset',         FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_INPUT_PROTOCOL), BOOLEAN)),
        ('ReadKeyStroke', FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_INPUT_PROTOCOL), PTR(EFI_INPUT_KEY))),
        ('WaitForKey',    EFI_EVENT)
    ]


@dxeapi(params={
    "This":	POINTER,              # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "ExtendedVerification": BOOL  # IN BOOLEAN
})
def hook_Input_Reset(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER,  # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "Key": POINTER    # OUT PTR(EFI_INPUT_KEY)
})
def hook_Read_Key_Stroke(ql: Qiling, address: int, params):
    pass


def initialize(ql: Qiling, gIP: int):
    descriptor = {
        'struct': EFI_SIMPLE_TEXT_INPUT_PROTOCOL,
        'fields': (
            ('Reset',         hook_Input_Reset),
            ('ReadKeyStroke', hook_Read_Key_Stroke),
            ('WaitForKey',    None)
        )
    }

    instance = init_struct(ql, gIP, descriptor)
    instance.save_to(ql.mem, gIP)

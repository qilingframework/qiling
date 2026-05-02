#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.fncc import dxeapi
from qiling.os.uefi.utils import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import EFI_STATUS


# @see: MdePkg/Include/Protocol/SimpleTextOut.h
class SIMPLE_TEXT_OUTPUT_MODE(STRUCT):
    _fields_ = [
        ("MaxMode",       INT32),
        ("Mode",          INT32),
        ("Attribute",     INT32),
        ("CursorColumn",  INT32),
        ("CursorRow",     INT32),
        ("CursorVisible", BOOLEAN),
    ]


class EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL(STRUCT):
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = STRUCT

    _fields_ = [
        ("Reset",             FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), BOOLEAN)),
        ("OutputString",      FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), PTR(CHAR16))),
        ("TestString",        FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), PTR(CHAR16))),
        ("QueryMode",         FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), UINTN, PTR(UINTN), PTR(UINTN))),
        ("SetMode",           FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), UINTN)),
        ("SetAttribute",      FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), UINTN)),
        ("ClearScreen",       FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL))),
        ("SetCursorPosition", FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), UINTN, UINTN)),
        ("EnableCursor",      FUNCPTR(EFI_STATUS, PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL), BOOLEAN)),
        ("Mode",              PTR(SIMPLE_TEXT_OUTPUT_MODE))
    ]


@dxeapi(params={
    "This":	POINTER,              # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "ExtendedVerification": BOOL  # IN BOOLEAN
})
def hook_TextReset(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	  POINTER,  # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "String": WSTRING   # IN PTR(CHAR16)
})
def hook_OutputString(ql: Qiling, address: int, params):
    print(params['String'])

    return EFI_SUCCESS

@dxeapi(params={
    "This":	  POINTER,  # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "String": WSTRING   # IN PTR(CHAR16)
})
def hook_TestString(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER,          # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "ModeNumber": ULONGLONG,  # IN UINTN
    "Columns": POINTER,       # OUT PTR(UINTN)
    "Rows": POINTER           # OUT PTR(UINTN)
})
def hook_QueryMode(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER,         # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "ModeNumber": ULONGLONG  # IN UINTN
})
def hook_SetMode(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER,        # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "Attribute": ULONGLONG  # IN UINTN
})
def hook_SetAttribute(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER   # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
})
def hook_ClearScreen(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER,      # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "Column": ULONGLONG,  # IN UINTN
    "Row": ULONGLONG      # IN UINTN
})
def hook_SetCursorPosition(ql: Qiling, address: int, params):
    pass

@dxeapi(params={
    "This":	POINTER,  # IN PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL)
    "Visible": BOOL   # IN BOOLEAN
})
def hook_EnableCursor(ql: Qiling, address: int, params):
    pass


def initialize(ql: Qiling, base: int):
    descriptor = {
        'struct': EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL,
        'fields': (
            ('Reset',             hook_TextReset),
            ('OutputString',      hook_OutputString),
            ('TestString',        hook_TestString),
            ('QueryMode',         hook_QueryMode),
            ('SetMode',           hook_SetMode),
            ('SetAttribute',      hook_SetAttribute),
            ('ClearScreen',       hook_ClearScreen),
            ('SetCursorPosition', hook_SetCursorPosition),
            ('EnableCursor',      hook_EnableCursor),
            ('Mode',              None)
        )
    }

    instance = init_struct(ql, base, descriptor)
    instance.save_to(ql.mem, base)

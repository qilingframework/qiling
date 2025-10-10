#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import TYPE_CHECKING

from qiling.os.uefi import bs, rt, ds
from qiling.os.uefi.context import UefiContext
from qiling.os.uefi.utils import install_configuration_table
from qiling.os.uefi.UefiSpec import EFI_SYSTEM_TABLE, EFI_SIMPLE_TEXT_INPUT_PROTOCOL, EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL, EFI_BOOT_SERVICES, EFI_RUNTIME_SERVICES

import qiling.os.uefi.protocols.EfiSimpleTextInProtocol as txt_in
import qiling.os.uefi.protocols.EfiSimpleTextOutProtocol as txt_out


if TYPE_CHECKING:
    from qiling import Qiling

# static mem layout:
#
#        +-- EFI_SYSTEM_TABLE -----------------+
#        |                                     |
#        | ...                                 |
#        | ConIn*                       -> (1) |
#        | ConOut*                      -> (2) |
#        | RuntimeServices*             -> (3) |
#        | BootServices*                -> (4) |
#        | NumberOfTableEntries                |
#        | ConfigurationTable*          -> (6) |
#        +-------------------------------------+
#    (1) +-- EFI_SIMPLE_TEXT_INPUT_PROTOCOL ---+
#        |                                     |
#        | ...                                 |
#        +-------------------------------------+
#    (2) +-- EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL --+
#        |                                     |
#        | ...                                 |
#        +-------------------------------------+
#    (3) +-- EFI_RUNTIME_SERVICES -------------+
#        |                                     |
#        | ...                                 |
#        +-------------------------------------+
#    (4) +-- EFI_BOOT_SERVICES ----------------+
#        |                                     |
#        | ...                                 |
#        +-------------------------------------+
#    (5) +-- EFI_DXE_SERVICES -----------------+
#        |                                     |
#        | ...                                 |
#        +-------------------------------------+
#    (6) +-- EFI_CONFIGURATION_TABLE ----------+        of HOB_LIST
#        | VendorGuid                          |
#        | VendorTable*                 -> (7) |
#        +-------------------------------------+
#        +-- EFI_CONFIGURATION_TABLE ----------+        of DXE_SERVICE_TABLE
#        | VendorGuid                          |
#        | VendorTable*                 -> (5) |
#        +-------------------------------------+
#
#        ... the remainder of the chunk may be used for additional EFI_CONFIGURATION_TABLE entries
#
# dynamically allocated (context.conf_table_data_ptr):
#
#    (7) +-- VOID* ----------------------------+
#        | ...                                 |
#        +-------------------------------------+


def initialize(ql: Qiling, context: UefiContext, gST: int):
    ql.loader.gST = gST

    sti = gST + EFI_SYSTEM_TABLE.sizeof()                 # input protocols
    sto = sti + EFI_SIMPLE_TEXT_INPUT_PROTOCOL.sizeof()   # output protocols
    gRT = sto + EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.sizeof()  # runtime services
    gBS = gRT + EFI_RUNTIME_SERVICES.sizeof()             # boot services
    gDS = gBS + EFI_BOOT_SERVICES.sizeof()                # dxe services
    cfg = gDS + ds.EFI_DXE_SERVICES.sizeof()              # configuration tables array

    ql.log.info(f'Global tables:')
    ql.log.info(f' | gST   {gST:#010x}')
    ql.log.info(f' | gBS   {gBS:#010x}')
    ql.log.info(f' | gRT   {gRT:#010x}')
    ql.log.info(f' | gDS   {gDS:#010x}')
    ql.log.info(f'')

    txt_in.initialize(ql, sti)
    txt_out.initialize(ql, sto)

    bs.initialize(ql, gBS)
    rt.initialize(ql, gRT)
    ds.initialize(ql, gDS)

    EFI_SYSTEM_TABLE(
        ConIn = sti,
        ConOut = sto,
        RuntimeServices = gRT,
        BootServices = gBS,
        NumberOfTableEntries = 0,
        ConfigurationTable = cfg
    ).save_to(ql.mem, gST)

    install_configuration_table(context, "HOB_LIST", None)
    install_configuration_table(context, "DXE_SERVICE_TABLE", gDS)

__all__ = [
    'initialize'
]

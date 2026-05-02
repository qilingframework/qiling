#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import TYPE_CHECKING

from qiling.os.uefi.const import EFI_SUCCESS, EFI_NOT_FOUND, EFI_UNSUPPORTED, EFI_BUFFER_TOO_SMALL, EFI_INVALID_PARAMETER
from qiling.os.uefi.UefiSpec import EFI_LOCATE_SEARCH_TYPE

if TYPE_CHECKING:
    from qiling.os.uefi.context import UefiContext

def LocateHandles(context: UefiContext, params):
    SearchType = params["SearchType"]
    Protocol = params["Protocol"]

    # get all handles
    if SearchType == EFI_LOCATE_SEARCH_TYPE.AllHandles:
        handles = context.protocols.keys()

    # get all handles that support the specified protocol
    elif SearchType == EFI_LOCATE_SEARCH_TYPE.ByProtocol:
        handles = [handle for handle, guid_dic in context.protocols.items() if Protocol in guid_dic]

    else:
        handles = []

    return len(handles) * context.ql.arch.pointersize, handles

def InstallProtocolInterface(context: UefiContext, params):
    handle = context.ql.mem.read_ptr(params["Handle"])

    if handle == 0:
        handle = context.heap.alloc(1)

    dic = context.protocols.get(handle, {})

    dic[params["Protocol"]] = params["Interface"]
    context.protocols[handle] = dic

    context.ql.mem.write_ptr(params["Handle"], handle)
    context.notify_protocol(params['Handle'], params['Protocol'], params['Interface'], True)

    return EFI_SUCCESS

def ReinstallProtocolInterface(context: UefiContext, params):
    handle = params["Handle"]

    if handle not in context.protocols:
        return EFI_NOT_FOUND

    dic = context.protocols[handle]
    protocol = params["Protocol"]

    if protocol not in dic:
        return EFI_NOT_FOUND

    dic[protocol] = params["NewInterface"]

    return EFI_SUCCESS

def UninstallProtocolInterface(context: UefiContext, params):
    handle = params["Handle"]

    if handle not in context.protocols:
        return EFI_NOT_FOUND

    dic = context.protocols[handle]
    protocol = params["Protocol"]

    if protocol not in dic:
        return EFI_NOT_FOUND

    del dic[protocol]

    return EFI_SUCCESS

def HandleProtocol(context: UefiContext, params):
    handle = params["Handle"]
    protocol = params["Protocol"]
    interface = params['Interface']

    if handle in context.protocols:
        supported = context.protocols[handle]

        if protocol in supported:
            context.ql.mem.write_ptr(interface, supported[protocol])

            return EFI_SUCCESS

    return EFI_UNSUPPORTED

def LocateHandle(context: UefiContext, params):
    buffer_size, handles = LocateHandles(context, params)

    if len(handles) == 0:
        return EFI_NOT_FOUND

    ret = EFI_BUFFER_TOO_SMALL

    if context.ql.mem.read_ptr(params["BufferSize"]) >= buffer_size:
        ptr = params["Buffer"]

        for handle in handles:
            context.ql.mem.write_ptr(ptr, handle)
            ptr += context.ql.arch.pointersize

        ret = EFI_SUCCESS

    context.ql.mem.write_ptr(params["BufferSize"], buffer_size)

    return ret

def LocateProtocol(context: UefiContext, params):
    protocol = params['Protocol']

    for handle, guid_dic in context.protocols.items():
        if "Handle" in params and params["Handle"] != handle:
            continue

        if protocol in guid_dic:
            # write protocol address to out variable Interface
            context.ql.mem.write_ptr(params['Interface'], guid_dic[protocol])
            return EFI_SUCCESS

    return EFI_NOT_FOUND

def InstallConfigurationTable(context: UefiContext, params):
    guid = params["Guid"]
    table = params["Table"]

    if not guid:
        return EFI_INVALID_PARAMETER

    context.conftable.install(guid, table)

    return EFI_SUCCESS

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
import sys

from unicorn import *
from unicorn.x86_const import *

from capstone import *
from capstone.x86_const import *

from keystone import *
from keystone.x86_const import *

from struct import pack
import os
import types

import string

# impport read_string and other commom utils.
from qiling.loader.pe import PE, Shellcode
from qiling.arch.x86 import *
from qiling.os.windows.dlls import *
from qiling.os.utils import *
from qiling.os.windows.memory import Heap
from qiling.os.windows.registry import RegistryManager

QL_X86_WINDOWS_STACK_ADDRESS = 0xfffdd000
QL_X86_WINDOWS_STACK_SIZE = 0x21000
QL_X86_WINDOWS_EMU_END = 0x0


# hook WinAPI in PE EMU
def hook_winapi(ql, address, size):
    # call win32 api
    if address in ql.PE.import_symbols:
        try:
            ql.dprint('[+] Hooking 0x{:08x}: {}'.format(address, ql.PE.import_symbols[address]))
            globals()['hook_' + ql.PE.import_symbols[address]['name'].decode()](ql, address, {})
        except KeyError as e:
            print("[!]", e, "\t is not implemented")


def setup_windows32(ql):
    ql.FS_SEGMENT_ADDR = 0x6000
    ql.FS_SEGMENT_SIZE = 0x6000
    ql.STRUCTERS_LAST_ADDR = ql.FS_SEGMENT_ADDR

    ql.GS_SEGMENT_ADDR = 0x5000
    ql.GS_SEGMENT_SIZE = 0x1000

    ql.PE_IMAGE_BASE = 0
    ql.PE_IMAGE_SIZE = 0
    ql.DEFAULT_IMAGE_BASE = 0x400000
    ql.entry_point = 0

    ql.HEAP_BASE_ADDR = 0x5000000
    ql.HEAP_SIZE = 0x5000000

    ql.DLL_BASE_ADDR = 0x10000000
    ql.DLL_SIZE = 0
    ql.DLL_LAST_ADDR = ql.DLL_BASE_ADDR

    ql.heap = Heap(ql, ql.HEAP_BASE_ADDR, ql.HEAP_BASE_ADDR + ql.HEAP_SIZE)
    ql.hook_mem_unmapped(ql_x86_windows_hook_mem_error)

    ql.RUN = True

    # New set GDT Share with Linux
    ql_x86_setup_gdt_segment_fs(ql, ql.FS_SEGMENT_ADDR, ql.FS_SEGMENT_SIZE)
    ql_x86_setup_gdt_segment_gs(ql, ql.GS_SEGMENT_ADDR, ql.GS_SEGMENT_SIZE)
    ql_x86_setup_gdt_segment_ds(ql)
    ql_x86_setup_gdt_segment_cs(ql)
    ql_x86_setup_gdt_segment_ss(ql)

    # handle manager
    ql.handle_manager = HandleManager()
    # registry manger
    ql.registry_manager = RegistryManager(ql)
    # thread manager
    main_thread = Thread(ql)
    ql.thread_manager = ThreadManager(ql, main_thread)
    new_handle = Handle(thread=main_thread)
    ql.handle_manager.append(new_handle)


def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    ql.uc = uc

    # MAPPED Vars for loadPE32
    if (ql.stack_address == 0): 
        ql.stack_address = QL_X86_WINDOWS_STACK_ADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_X86_WINDOWS_STACK_SIZE


    setup_windows32(ql)

    # load pe
    ql.PE = PE(ql, ql.path)
    ql.PE.load()

    # hook win api
    ql.hook_code(hook_winapi)


def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    ql.uc = uc

    # MAPPED Vars for loadPE32
    if (ql.stack_address == 0):
        ql.stack_address = QL_X86_WINDOWS_STACK_ADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_X86_WINDOWS_STACK_SIZE

    ql.code_address = 0x40000
    ql.code_size = 10 * 1024 * 1024

    setup_windows32(ql)

    # load shellcode
    ql.PE = Shellcode(ql, [b"ntdll.dll", b"kernel32.dll", b"user32.dll"])
    ql.PE.load()

    # hook win api
    ql.hook_code(hook_winapi)


def runner(ql):
    ql_setup(ql)
    # registry manger
    ql.registry_manager = RegistryManager(ql)

    if (ql.until_addr == 0):
        ql.until_addr = QL_X86_WINDOWS_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.code_address, ql.code_address + len(ql.shellcoder))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError as e:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.uc.mem_read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise QlErrorExecutionStop('[!] Emulation Stopped due to %s' %(e))

    ql.registry_manager.save()

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


from unicorn import *
from unicorn.x86_const import *
import types

# impport read_string and other commom utils.
from qiling.loader.pe import PE, Shellcode
from qiling.os.windows.dlls import *
from qiling.os.utils import *
from qiling.os.windows.memory import Heap
from qiling.os.windows.registry import RegistryManager

QL_X8664_WINDOWS_STACK_ADDRESS = 0x7ffffffde000
QL_X8664_WINDOWS_STACK_SIZE = 0x40000
QL_X8664_WINSOWS_EMU_END = 0x0


def set_pe64_gdt(ql):
    # uc.mem_map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)
    # setup_gdt_segment(uc, GDT_ADDR, GDT_LIMIT, UC_X86_REG_GS, 15, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, S_GDT | S_PRIV_3)
    GSMSR = 0xC0000101
    ql.uc.mem_map(ql.GS_SEGMENT_ADDR, ql.GS_SEGMENT_SIZE)
    ql.uc.msr_write(GSMSR, ql.GS_SEGMENT_ADDR)


# hook WinAPI in PE EMU
def hook_winapi(ql, address, size):
    if address in ql.PE.import_symbols:
        try:
            ql.dprint('Hooking 0x{:08x}: {}'.format(address, ql.PE.import_symbols[address]))
            globals()['hook_' + ql.PE.import_symbols[address]['name'].decode()](ql, address, {})
        except KeyError as e:
            print("[!]", e, "\t is not implemented")


def windows_setup64(ql):

    ql.GS_SEGMENT_ADDR = 0x6000
    ql.GS_SEGMENT_SIZE = 0x8000
    ql.STRUCTERS_LAST_ADDR = ql.GS_SEGMENT_ADDR

    ql.DLL_BASE_ADDR = 0x7ffff0000000
    ql.DLL_SIZE = 0
    ql.DLL_LAST_ADDR = ql.DLL_BASE_ADDR

    ql.HEAP_BASE_ADDR = 0x500000000
    ql.HEAP_SIZE = 0x5000000

    ql.PE_IMAGE_BASE = 0
    ql.PE_IMAGE_SIZE = 0
    ql.DEFAULT_IMAGE_BASE = 0x140000000
    ql.entry_point = 0

    ql.RUN = True

    ql.heap = Heap(ql, ql.HEAP_BASE_ADDR, ql.HEAP_BASE_ADDR + ql.HEAP_SIZE)

    # setup gdt
    set_pe64_gdt(ql)

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
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    # init ql pe
    if (ql.stack_address == 0): 
        ql.stack_address = QL_X8664_WINDOWS_STACK_ADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_X8664_WINDOWS_STACK_SIZE

    windows_setup64(ql)

    # load pe
    ql.PE = PE(ql, ql.path)
    ql.PE.load()

    ql.hook_code(hook_winapi)

def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc

    # init ql pe
    if (ql.stack_address == 0): 
        ql.stack_address = QL_X8664_WINDOWS_STACK_ADDRESS
    if (ql.stack_size == 0):
        ql.stack_size = QL_X8664_WINDOWS_STACK_SIZE

    ql.code_address = 0x140000000
    ql.code_size = 10 * 1024 * 1024

    windows_setup64(ql)

    # load shellcode
    ql.PE = Shellcode(ql, [b"ntdll.dll", b"kernel32.dll", b"user32.dll"])
    ql.PE.load()

    # hook win api
    ql.hook_code(hook_winapi)


def runner(ql):
    ql_setup(ql)
    if (ql.until_addr == 0):
        ql.until_addr = QL_X8664_WINSOWS_EMU_END
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
        ql.errmsg = 1
        ql.nprint("%s" % e)
        raise QlErrorExecutionStop('[!] Emulation Stopped')

    ql.registry_manager.save()

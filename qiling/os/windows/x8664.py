#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import types

from unicorn import *
from unicorn.x86_const import *

# import read_string and other common utils.
from qiling.loader.pe import PE, Shellcode
from qiling.os.windows.dlls import *
from qiling.arch.x86 import *
from qiling.os.utils import *
from qiling.os.memory import Heap
from qiling.os.windows.const import *
from qiling.os.windows.registry import RegistryManager
from qiling.os.windows.clipboard import Clipboard
from qiling.os.windows.fiber import FiberManager
from qiling.os.windows.const import Mapper

QL_X8664_WINDOWS_STACK_ADDRESS = 0x7ffffffde000
QL_X8664_WINDOWS_STACK_SIZE = 0x40000
QL_X8664_WINSOWS_EMU_END = 0x0

# hook WinAPI in PE EMU
def hook_winapi(ql, address, size):
    if address in ql.PE.import_symbols:
        winapi_name = ql.PE.import_symbols[address]['name']
        if winapi_name is None:
            winapi_name = Mapper[ql.PE.import_symbols[address]['dll']][ql.PE.import_symbols[address]['ordinal']]
        else:
            winapi_name = winapi_name.decode()
        winapi_func = None

        if winapi_name in ql.user_defined_api:
            if isinstance(ql.user_defined_api[winapi_name], types.FunctionType):
                winapi_func = ql.user_defined_api[winapi_name]
        else:
            try:
                counter = ql.PE.syscall_count.get(winapi_name, 0) + 1
                ql.PE.syscall_count[winapi_name] = counter
                winapi_func = globals()['hook_' + winapi_name]
            except KeyError:
                winapi_func = None

        if winapi_func:
            try:
                winapi_func(ql, address, {})
            except Exception:
                ql.dprint(0, "[!] %s Exception Found" % winapi_name)
                raise QlErrorSyscallError("[!] Windows API Implementation Error")
        else:
            ql.nprint("[!] %s is not implemented\n" % winapi_name)
            if ql.debug_stop:
                raise QlErrorSyscallNotFound("[!] Windows API Implementation Not Found")


def set_pe64_gdt(ql):
    ql.mem.map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)
    ql_x8664_set_gs(ql, GS_SEGMENT_ADDR)


def windows_setup64(ql):
    ql.STRUCTERS_LAST_ADDR = GS_SEGMENT_ADDR

    ql.PE_IMAGE_BASE = 0
    ql.PE_IMAGE_SIZE = 0
    ql.DEFAULT_IMAGE_BASE = 0x140000000
    ql.entry_point = 0

    ql.HEAP_BASE_ADDR = 0x500000000
    ql.HEAP_SIZE = 0x5000000

    ql.DLL_BASE_ADDR = 0x7ffff0000000
    ql.DLL_SIZE = 0
    ql.DLL_LAST_ADDR = ql.DLL_BASE_ADDR

    ql.RUN = True

    ql.heap = Heap(ql, ql.HEAP_BASE_ADDR, ql.HEAP_BASE_ADDR + ql.HEAP_SIZE)
    ql.hook_mem_unmapped(ql_x86_windows_hook_mem_error)

    # setup gdt
    set_pe64_gdt(ql)

    # handle manager
    ql.handle_manager = HandleManager()
    # registry manger
    ql.registry_manager = RegistryManager(ql)
    # clipboard manager
    ql.clipboard = Clipboard(ql)
    # fibers
    ql.fiber_manager = FiberManager(ql)
    # Place to set errors for retrieval by GetLastError()
    ql.last_error = 0
    # thread manager
    main_thread = Thread(ql)
    ql.thread_manager = ThreadManager(ql, main_thread)
    new_handle = Handle(thread=main_thread)
    ql.handle_manager.append(new_handle)
    # user configuration
    ql.config = ql_init_configuration(ql)
    # variables used inside hooks
    ql.hooks_variables = {}

def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    # init ql pe
    if ql.stack_address == 0:
        ql.stack_address = QL_X8664_WINDOWS_STACK_ADDRESS
    if ql.stack_size == 0:
        ql.stack_size = QL_X8664_WINDOWS_STACK_SIZE

    windows_setup64(ql)

    # load pe
    ql.PE = PE(ql, ql.path)
    ql.PE.load()

    ql.hook_code(hook_winapi)
    ql_setup_output(ql)


def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc

    # init ql pe
    if ql.stack_address == 0:
        ql.stack_address = QL_X8664_WINDOWS_STACK_ADDRESS
    if ql.stack_size == 0:
        ql.stack_size = QL_X8664_WINDOWS_STACK_SIZE

    ql.code_address = 0x140000000
    ql.code_size = 10 * 1024 * 1024

    windows_setup64(ql)

    # load shellcode
    ql.PE = Shellcode(ql, [b"ntdll.dll", b"kernel32.dll", b"user32.dll"])
    ql.PE.load()

    # hook win api
    ql.hook_code(hook_winapi)
    ql_setup_output(ql)


def runner(ql):
    if ql.until_addr == 0:
        ql.until_addr = QL_X8664_WINSOWS_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.code_address, ql.code_address + len(ql.shellcoder))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC = 0x%x\n" %(ql.pc))
            ql.show_map_info()
            try:
                buf = ql.mem.read(ql.pc, 8)
                ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                ql.nprint("\n")
                ql_hook_code_disasm(ql, ql.pc, 64)
            except:
                pass
        raise

    ql.registry_manager.save()

    post_report(ql)

    if ql.internal_exception is not None:
        raise ql.internal_exception

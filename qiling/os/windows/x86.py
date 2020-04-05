#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import types

from unicorn import *

from qiling.loader.pe import PE, Shellcode
from qiling.os.windows.dlls import *
from qiling.arch.x86_const import *
from qiling.os.utils import *

from qiling.os.windows.const import *
from qiling.os.windows.const import Mapper

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


def loader_file(ql):
    ql.uc = Uc(UC_ARCH_X86, UC_MODE_32)
    if ql.stack_address == 0:
        ql.stack_address = QL_X86_WINDOWS_STACK_ADDRESS
    if ql.stack_size == 0:
        ql.stack_size = QL_X86_WINDOWS_STACK_SIZE
    setup(ql)
    # load pe
    ql.PE = PE(ql, ql.path)
    ql.PE.load()
    # hook win api
    ql.hook_code(hook_winapi)
    ql_setup_output(ql)


def loader_shellcode(ql):
    ql.uc = Uc(UC_ARCH_X86, UC_MODE_32)
    # MAPPED Vars for loadPE32
    if ql.stack_address == 0:
        ql.stack_address = QL_X86_WINDOWS_STACK_ADDRESS
    if ql.stack_size == 0:
        ql.stack_size = QL_X86_WINDOWS_STACK_SIZE
    ql.code_address = 0x40000
    ql.code_size = 10 * 1024 * 1024
    setup(ql)
    # load shellcode
    ql.PE = Shellcode(ql, [b"ntdll.dll", b"kernel32.dll", b"user32.dll"])
    ql.PE.load()
    # hook win api
    ql.hook_code(hook_winapi)
    ql_setup_output(ql)


def runner(ql):
    ql_os_run(ql)

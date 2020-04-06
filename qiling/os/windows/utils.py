#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.const import *
from qiling.os.utils import *
from qiling.arch.x86 import *
from qiling.os.memory import Heap
from qiling.os.windows.registry import RegistryManager
from qiling.os.windows.clipboard import Clipboard
from qiling.os.windows.fiber import FiberManager
from qiling.os.windows.handle import HandleManager, Handle
from qiling.os.windows.thread import ThreadManager, Thread

def setup(ql):
    ql.heap = Heap(ql, ql.commos.HEAP_BASE_ADDR, ql.commos.HEAP_BASE_ADDR + ql.commos.HEAP_SIZE)
    ql.hook_mem_unmapped(ql_x86_windows_hook_mem_error)
    
    # setup gdt
    if ql.arch == QL_X86:
        ql_x86_setup_gdt_segment_fs(ql, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE)
        ql_x86_setup_gdt_segment_gs(ql, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)
        ql_x86_setup_gdt_segment_ds(ql)
        ql_x86_setup_gdt_segment_cs(ql)
        ql_x86_setup_gdt_segment_ss(ql)
    elif ql.arch == QL_X8664:
        ql_x8664_set_gs(ql)     
    
    # handle manager
    ql.handle_manager = HandleManager()
    # registry manger
    ql.registry_manager = RegistryManager(ql)
    # clipboard
    ql.clipboard = Clipboard(ql)
    # fibers
    ql.fiber_manager = FiberManager(ql)
    # Place to set errors for retrieval by GetLastError()
    # thread manager
    main_thread = Thread(ql)
    ql.thread_manager = ThreadManager(ql, main_thread)
    new_handle = Handle(thread=main_thread)
    ql.handle_manager.append(new_handle)
    # user configuration
    ql.config = ql_init_configuration(ql)
    # variables used inside hooks
    ql.hooks_variables = {}


def ql_x86_windows_hook_mem_error(ql, addr, size, value):
    ql.dprint(0, "[+] ERROR: unmapped memory access at 0x%x" % addr)
    return False


def string_unpack(string):
    return string.decode().split("\x00")[0]


def read_wstring(ql, address):
    result = ""
    char = ql.mem.read(address, 2)
    while char.decode(errors="ignore") != "\x00\x00":
        address += 2
        result += char.decode(errors="ignore")
        char = ql.mem.read(address, 2)
    # We need to remove \x00 inside the string. Compares do not work otherwise
    return result.replace("\x00", "")


def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def debug_print_stack(ql, num, message=None):
    if message:
        ql.dprint(0, "========== %s ==========" % message)
    if ql.arch == QL_X86:
        sp = ql.register(UC_X86_REG_ESP)
    else:
        sp = ql.register(UC_X86_REG_RSP)
    for i in range(num):
        ql.dprint(0, hex(sp + ql.pointersize * i) + ": " + hex(ql.stack_read(i * ql.pointersize)))


def is_file_library(string):
    string = string.lower()
    extension = string[-4:]
    return extension in (".dll", ".exe", ".sys", ".drv")


def string_to_hex(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)


def printf(ql, address, fmt, params_addr, name, wstring=False):
    count = fmt.count("%")
    params = []
    if count > 0:
        for i in range(count):
            # We don't need to mem_read here, otherwise we have a problem with strings, since read_wstring/read_cstring
            #  already take a pointer, and we will have pointer -> pointer -> STRING instead of pointer -> STRING
            params.append(
                params_addr + i * ql.pointersize,
            )

        formats = fmt.split("%")[1:]
        index = 0
        for f in formats:
            if f.startswith("s"):
                if wstring:
                    params[index] = read_wstring(ql, params[index])
                else:
                    params[index] = read_cstring(ql, params[index])
            else:
                # if is not a string, then they are already values!
                pass
            index += 1

        output = '0x%0.2x: %s(format = %s' % (address, name, repr(fmt))
        for each in params:
            if type(each) == str:
                output += ', "%s"' % each
            else:
                output += ', 0x%0.2x' % each
        output += ')'
        fmt = fmt.replace("%llx", "%x")
        stdout = fmt % tuple(params)
        output += " = 0x%x" % len(stdout)
    else:
        output = '0x%0.2x: %s(format = %s) = 0x%x' % (address, name, repr(fmt), len(fmt))
        stdout = fmt
    ql.nprint(output)
    ql.stdout.write(bytes(stdout + "\n", 'utf-8'))
    return len(stdout), stdout

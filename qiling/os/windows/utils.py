#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
from qiling.os.const import *

from .registry import RegistryManager
from .clipboard import Clipboard
from .fiber import FiberManager
from .handle import HandleManager, Handle
from .thread import QlWindowsThreadManagement, QlWindowsThread


def ql_x86_windows_hook_mem_error(ql, addr, size, value):
    #self.ql.dprint(D_INFO, "[+] ERROR: unmapped memory access at 0x%x" % addr)
    return False

def string_unpack(string):
    return string.decode().split("\x00")[0]


def print_function(ql, address, function_name, params, ret):
    function_name = function_name.replace('hook_', '')
    if function_name in ("__stdio_common_vfprintf", "printf", "wsprintfW", "sprintf"):
        return
    log = '0x%0.2x: %s(' % (address, function_name)
    for each in params:
        value = params[each]
        if type(value) == str or type(value) == bytearray:
            log += '%s = "%s", ' % (each, value)
        else:
            log += '%s = 0x%x, ' % (each, value)
    log = log.strip(", ")
    log += ')'
    if ret is not None:
        log += ' = 0x%x' % ret

    if ql.output == QL_OUTPUT.DEFAULT:
        log = log.partition(" ")[-1]
        ql.nprint(log)

    elif ql.output == QL_OUTPUT.DEBUG:
        ql.dprint(D_INFO, log)

def read_wstring(ql, address):
    result = ""
    char = ql.mem.read(address, 2)
    while char.decode(errors="ignore") != "\x00\x00":
        address += 2
        result += char.decode(errors="ignore")
        char = ql.mem.read(address, 2)
    # We need to remove \x00 inside the string. Compares do not work otherwise
    return result.replace("\x00", "")


def read_cstring(ql, address):
    result = ""
    char = ql.mem.read(address, 1)
    while char.decode(errors="ignore") != "\x00":
        address += 1
        result += char.decode(errors="ignore")
        char = ql.mem.read(address, 1)
    return result


def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def debug_print_stack(ql, num, message=None):
    if message:
        ql.dprint(D_INFO, "========== %s ==========" % message)
        sp = ql.reg.sp
        ql.dprint(D_INFO, hex(sp + ql.pointersize * i) + ": " + hex(ql.stack_read(i * ql.pointersize)))


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
    ql.os.stdout.write(bytes(stdout + "\n", 'utf-8'))
    return len(stdout), stdout





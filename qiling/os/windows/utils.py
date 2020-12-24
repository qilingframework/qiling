#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os
import uuid
import ntpath
import logging
from sys import getsizeof

from qiling.const import *
from qiling.os.const import *

from .registry import RegistryManager
from .clipboard import Clipboard
from .fiber import FiberManager
from .handle import HandleManager, Handle
from .thread import QlWindowsThreadManagement, QlWindowsThread
from .structs import UNICODE_STRING32, UNICODE_STRING64


def ql_x86_windows_hook_mem_error(ql, access, addr, size, value):
    logging.debug("[+] ERROR: unmapped memory access at 0x%x" % addr)
    return False


def string_unpack(string):
    return string.decode().split("\x00")[0]


def read_guid(ql, address):
    result = ""
    raw_guid = ql.mem.read(address, 16)
    return uuid.UUID(bytes_le=bytes(raw_guid))


def print_function(ql, passthru, address, function_name, params, ret):
    function_name = function_name.replace('hook_', '')
    if function_name in ("__stdio_common_vfprintf", "__stdio_common_vfwprintf",
                         "printf", "wsprintfW", "sprintf"):
        return
    log = '0x%0.2x: %s(' % (address, function_name)
    for each in params:
        value = params[each]
        if type(value) == str or type(value) == bytearray:
            log += '%s = "%s", ' % (each, value)
        elif type(value) == tuple:
            log += '%s = 0x%x, ' % (each, value[0])
        else:
            log += '%s = 0x%x, ' % (each, value)
    log = log.strip(", ")
    log += ')'
    if ret is not None:
        log += ' = 0x%x' % ret

    if passthru:
        log += ' (PASSTHRU)'

    if ql.output != QL_OUTPUT.DEBUG:
        log = log.partition(" ")[-1]
        logging.info(log)
    else:
        logging.debug(log)


def read_wstring(ql, address):
    result = ""
    char = ql.mem.read(address, 2)
    # decode as utf-16-le only
    while char.decode('utf-16-le', errors="backslashreplace") != "\x00":
        address += 2
        result += char.decode('utf-16-le', errors="backslashreplace")
        char = ql.mem.read(address, 2)

    # We need to remove \x00 inside the string. Compares do not work otherwise
    result = result.replace("\x00", "")
    string_appearance(ql, result)
    return result


def read_wchar(ql, val):
    return val.decode('utf-16-le', errors="backslashreplace")


def read_punicode_string(ql, address):
    if ql.archbit == 64:  # Win64
        ub = ql.mem.read(address, getsizeof(UNICODE_STRING64))
        us = UNICODE_STRING64.from_buffer_copy(ub)
    else:  # Win32
        ub = ql.mem.read(address, getsizeof(UNICODE_STRING32))
        us = UNICODE_STRING32.from_buffer_copy(ub)

    return read_wstring(ql, us.Buffer)


def read_cstring(ql, address):
    result = ""
    char = ql.mem.read(address, 1)
    while char.decode(errors="ignore") != "\x00":
        address += 1
        result += char.decode(errors="ignore")
        char = ql.mem.read(address, 1)
    string_appearance(ql, result)
    return result


def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def debug_print_stack(ql, num, message=None):
    if message:
        logging.debug("========== %s ==========" % message)
        sp = ql.reg.arch_sp
        logging.debug(hex(sp + ql.pointersize * num) + ": " + hex(ql.stack_read(num * ql.pointersize)))


def is_file_library(string):
    string = string.lower()
    extension = string[-4:]
    return extension in (".dll", ".exe", ".sys", ".drv")


def string_to_hex(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)


def string_appearance(ql, string):
    strings = string.split(" ")
    for string in strings:
        val = ql.os.appeared_strings.get(string, set())
        val.add(ql.os.syscalls_counter)
        ql.os.appeared_strings[string] = val


def printf(ql,
           address,
           fmt,
           params_addr,
           name,
           wstring=False,
           double_pointer=False):
    count = fmt.count("%")
    params = []
    if count > 0:
        for i in range(count):
            # We don't need to mem_read here, otherwise we have a problem with strings, since read_wstring/read_cstring
            #  already take a pointer, and we will have pointer -> pointer -> STRING instead of pointer -> STRING
            params.append(params_addr + i * ql.pointersize, )

        formats = fmt.split("%")[1:]
        index = 0
        for f in formats:
            if f.startswith("s"):
                if wstring:
                    if double_pointer:
                        params[index] = ql.unpack32(
                            ql.mem.read(params[index], ql.pointersize))
                    params[index] = read_wstring(ql, params[index])
                else:
                    params[index] = read_cstring(ql, params[index])
            else:
                # if is not a string, then they are already values!
                pass
            index += 1

        output = '%s(format = %s' % (name, repr(fmt))
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
        output = '%s(format = %s) = 0x%x' % (name, repr(fmt), len(fmt))
        stdout = fmt
    logging.info(output)
    ql.os.stdout.write(bytes(stdout, 'utf-8'))
    return len(stdout), stdout

def canonical_path(ql, file_path):
    file_path = file_path.replace("C:", ql.rootfs)
    file_path = file_path.replace("\\", os.sep)
    if ql.archbit == 32:
        real_path = os.path.join(ql.rootfs, "Windows", "System32")
        if not os.path.exists(real_path):
            real_path = os.path.join(ql.rootfs, "Windows", "SysWOW64")
    else:
        real_path = os.path.join(ql.rootfs, "Windows", "System32")

    system_path = os.path.join(ql.rootfs, "Windows", "System32")
    if system_path in file_path:
        file_path = file_path.replace(system_path, real_path)
    return file_path

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)
def find_size_function(ql, func_addr):
    # We have to retrieve the return address position
    code = ql.mem.read(func_addr, 0x100)
    return_procedures = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]
    min_index = min([code.index(return_value) for return_value in return_procedures if return_value in code])
    return min_index

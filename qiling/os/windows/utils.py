#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *
from qiling.arch.filetype import *


def ql_x86_windows_hook_mem_error(ql, addr, size, value):
    ql.dprint("[+] ERROR: unmapped memory access at 0x%x" % addr)
    return False


def string_unpack(string):
    return string.decode().split("\x00")[0]


def read_wstring(ql, address):
    result = ""
    char = ql.uc.mem_read(address, 2)
    while char.decode("utf-8", "backslashreplace") != "\x00\x00":
        address += 2
        result += char.decode("utf-8", "backslashreplace")
        char = ql.uc.mem_read(address, 2)
    return result


def w2cstring(string):
    return bytes(string, "ascii").decode("utf-16le")


def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def debug_print_stack(ql, num, message=None):
    if message:
        print("========== %s ==========" % message)
    if ql.arch == QL_X86:
        sp = ql.uc.reg_read(UC_X86_REG_ESP)
    else:
        sp = ql.uc.reg_read(UC_X86_REG_RSP)
    for i in range(num):
        print(hex(sp + ql.pointersize * i) + ": " + hex(ql.stack_read(i * ql.pointersize)))


def is_file_library(string):
    string = string.lower().replace("\x00", "")
    extension = string[-4:]
    return extension in (".dll", ".exe", ".sys", ".drv")


def string_to_hex(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)

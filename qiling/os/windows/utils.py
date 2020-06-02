#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import uuid

from qiling.const import *
from qiling.os.const import *

from .registry import RegistryManager
from .clipboard import Clipboard
from .fiber import FiberManager
from .handle import HandleManager, Handle
from .thread import QlWindowsThreadManagement, QlWindowsThread


def ql_x86_windows_hook_mem_error(ql, access, addr, size, value):
    ql.dprint(D_INFO, "[+] ERROR: unmapped memory access at 0x%x" % addr)
    return False


def string_unpack(string):
    return string.decode().split("\x00")[0]


def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def debug_print_stack(ql, num, message=None):
    if message:
        ql.dprint(D_INFO, "========== %s ==========" % message)
        sp = ql.reg.arch_sp
        ql.dprint(D_INFO, hex(sp + ql.pointersize * i) + ": " + hex(ql.stack_read(i * ql.pointersize)))


def is_file_library(string):
    string = string.lower()
    extension = string[-4:]
    return extension in (".dll", ".exe", ".sys", ".drv")


def string_to_hex(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)

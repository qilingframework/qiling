#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os

from unicorn.x86_const import *
from unicorn.arm_const import *

from qiling.os.const import *

def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list

def page_align_end(addr, page_size):
    if addr % page_size == 0:
        return addr
    else:
        return int(((addr / page_size) + 1) * page_size)

def set_eflags_cf(ql, target_cf):
    ql.reg.ef = ( ql.reg.ef & 0xfffffffe ) | target_cf
    return ql.reg.ef

def ql_real_to_vm_abspath(ql, path):
    # rm ".." in path
    abs_path = os.path.abspath(path)
    abs_rootfs = os.path.abspath(ql.rootfs)

    return '/' + abs_path.lstrip(abs_rootfs)

def macho_read_string(ql, address, max_length):
    ret = ""
    c = ql.mem.read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = ql.mem.read(address + read_bytes, 1)[0]
        read_bytes += 1
        if read_bytes > max_length:
            break
    return ret

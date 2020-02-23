#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.x86_const import *

def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list

def page_align_end(addr, page_size):
    if addr % page_size == 0:
        return addr
    else:
        return ((addr / page_size) + 1) * page_size

def set_eflags_cf(ql, target_cf):
    tmp_flags = ql.uc.reg_read(UC_X86_REG_EFLAGS)
    tmp_flags = tmp_flags & 0xfffffffe
    tmp_flags = tmp_flags | target_cf
    return ql.uc.reg_write(UC_X86_REG_EFLAGS, tmp_flags)


def macho_read_string(ql, address, max_length):
    ret = ""
    c = ql.uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = ql.uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
        if read_bytes > max_length:
            break
    return ret
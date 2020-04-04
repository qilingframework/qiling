#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.x86_const import *
from unicorn.arm_const import *

from qiling.os.const import *
from qiling.os.utils import *

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
    tmp_flags = ql.register(UC_X86_REG_EFLAGS)
    tmp_flags = tmp_flags & 0xfffffffe
    tmp_flags = tmp_flags | target_cf
    return ql.register(UC_X86_REG_EFLAGS, tmp_flags)


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

def ql_run_os(ql):
    if (ql.until_addr == 0):
        ql.until_addr = QL_ARCHBIT64_EMU_END
    try:
        if ql.shellcoder:
            ql.uc.emu_start(ql.stack_address, (ql.stack_address + len(ql.shellcoder)))
        else:
            ql.uc.emu_start(ql.entry_point, ql.until_addr, ql.timeout)
    except UcError:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.mem.read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql_hook_code_disasm(ql, ql.pc, 64)
        raise QlErrorExecutionStop("[!] Execution Terminated")    
    
    if ql.internal_exception != None:
        raise ql.internal_exception  

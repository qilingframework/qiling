#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

import string

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.const import STRING

LOAD_BASE = 0x47BA000

def _mem_write(ql, unk, addr, size, value):
    #print(f"_mem_write at {addr:#08x} size {size} value {value:#08x}")
    pass

def ql_hook_block_disasm(ql, address, size):
    ql.log.warning("\n[+] Tracing basic block at 0x%x" % (address))

def ql_hook_addr(ql):
    ql.log.info("R4(sync) = %08X, R5(mtx) = %08X, R2(cpupage) = %08X" % (ql.reg.r4, ql.reg.r5, ql.reg.r2))

md = None

def print_asm(ql, address, size):
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s\t\t(r0:%08x, r1:%08x, r2:%08x, r3:%08x)" % (
            i.address, i.mnemonic, i.op_str,
            ql.reg.r0, ql.reg.r1, ql.reg.r2, ql.reg.r3
        ))


if __name__ == "__main__":
    env = {
    }
    ql = Qiling(["examples/rootfs/arm_qnx/bin/hello"], "examples/rootfs/arm_qnx", env=env)
    ql.debugger = True
    md = ql.create_disassembler()
    #ql.hook_code(print_asm)
    #ql.hook_mem_write(_mem_write)
    #ql.hook_block(ql_hook_block_disasm)
    #ql.hook_address(ql_hook_addr, LOAD_BASE + 0x26860)
    ql.run()

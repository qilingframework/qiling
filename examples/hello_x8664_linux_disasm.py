#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from capstone import Cs
from qiling import Qiling

def trace(ql: Qiling, address: int, size: int, md: Cs):
    """Emit tracing info for each and every instruction that is about to be executed.

    Args:
        ql: the qiling instance
        address: the address of the instruction that is about to be executed
        size: size of the instruction (in bytes)
        md: initialized disassembler object
    """

    buf = ql.mem.read(address, size)
    nibbles = ql.archbit // 4

    esc_dgray = "\x1b[90m"
    esc_reset = "\x1b[39m"

    for insn in md.disasm(buf, address):
        opcode = ''.join(f'{b:02x}' for b in insn.bytes)

        # BUG: insn.regs_read doesn't work well, so we use insn.regs_access()[0] instead
        reads = (f'{md.reg_name(reg)} = {ql.reg.read(reg):#x}' for reg in insn.regs_access()[0])
        trace_line = f'{insn.address:0{nibbles}x} | {opcode:20s} {insn.mnemonic:10} {insn.op_str:35s} | {", ".join(reads)}'

        # emit trace line in dark gray so it would be easier to tell trace info from other log entries
        ql.log.info(f'{esc_dgray}{trace_line}{esc_reset}')

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")

    md = ql.create_disassembler()
    md.detail = True

    ql.hook_code(trace, user_data=md)
    ql.run()

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from typing import Mapping
from capstone import Cs

from qiling import Qiling

def __map_regs() -> Mapping[int, int]:
    """Map Capstone x86 regs definitions to Unicorn's.
    """

    from capstone import x86_const as cs_x86_const
    from unicorn import x86_const as uc_x86_const

    def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
        return dict((k[len(prefix):], getattr(module, k)) for k in dir(module) if k.startswith(prefix))

    cs_x86_regs = __canonicalized_mapping(cs_x86_const, 'X86_REG')
    uc_x86_regs = __canonicalized_mapping(uc_x86_const, 'UC_X86_REG')

    return dict((cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs if k in uc_x86_regs)

# capstone to unicorn regs mapping
CS_UC_REGS = __map_regs()

def trace(ql: Qiling, address: int, size: int, md: Cs):
    """Emit tracing info for each and every instruction that is about to be executed.

    Args:
        ql: the qiling instance
        address: the address of the instruction that is about to be executed
        size: size of the instruction (in bytes)
        md: initialized disassembler object
    """

    # read current instruction bytes and disassemble it
    buf = ql.mem.read(address, size)
    insn = next(md.disasm(buf, address))

    nibbles = ql.arch.bits // 4
    color_faded = '\033[2m'
    color_reset = '\033[0m'

    # get values of the registers referenced by this instruction.
    #
    # note: since this method is called before the instruction has been emulated, the 'rip'
    # register still points to the current instruction, while the instruction considers it
    # as if it was pointing to the next one. that will cause 'rip' to show an incorrect value
    reads = (f'{md.reg_name(reg)} = {ql.arch.regs.read(CS_UC_REGS[reg]):#x}' for reg in insn.regs_access()[0])

    # construct a human-readable trace line
    trace_line = f'{insn.address:0{nibbles}x} | {insn.bytes.hex():24s} {insn.mnemonic:12} {insn.op_str:35s} | {", ".join(reads)}'

    # emit the trace line in a faded color, so it would be easier to tell trace info from other log entries
    ql.log.info(f'{color_faded}{trace_line}{color_reset}')

if __name__ == "__main__":
    ql = Qiling([r"rootfs/x8664_linux/bin/x8664_hello"], r"rootfs/x8664_linux")

    # acquire a disassembler instance bound to arch
    md = ql.arch.disassembler
    md.detail = True

    # register the trace method to be called before each instruction
    ql.hook_code(trace, user_data=md)

    # go!
    ql.run()

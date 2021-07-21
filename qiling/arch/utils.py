#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

from typing import Tuple
from os.path import basename

from capstone import CS_MODE_MCLASS, Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_ARCH_MIPS, CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MIPS32 ,CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86, KS_ARCH_MIPS, KS_MODE_16, KS_MODE_32, KS_MODE_64, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_MIPS32 ,KS_MODE_BIG_ENDIAN, KS_MODE_LITTLE_ENDIAN

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN
from qiling.const import QL_VERBOSE
from qiling.exception import QlErrorArch

__cs_endian = {
    QL_ENDIAN.EL : CS_MODE_LITTLE_ENDIAN,
    QL_ENDIAN.EB : CS_MODE_BIG_ENDIAN
}

__ks_endian = {
    QL_ENDIAN.EL : KS_MODE_LITTLE_ENDIAN,
    QL_ENDIAN.EB : KS_MODE_BIG_ENDIAN
}

__reg_cpsr_v = {
    QL_ENDIAN.EL : 0b100000,
    QL_ENDIAN.EB : 0b100000   # FIXME: should be: 0b000000
}

class QlArchUtils:
    def __init__(self, ql: Qiling):
        self.ql = ql
        self.md = None
        self._disasm_hook = None
        self._block_hook = None

    def get_offset_and_name(self, addr: int) -> Tuple[int, str]:
        for begin, end, _, name in self.ql.mem.map_info:
            if begin <= addr < end:
                return addr - begin, basename(name)

        return addr, '-'

    def disassembler(self, ql, address, size):
        tmp = self.ql.mem.read(address, size)

        if not self.md:
            self.md = self.ql.create_disassembler()
        elif self.ql.archtype == QL_ARCH.ARM: # Update disassembler for arm considering thumb swtich.
            self.md = self.ql.create_disassembler()

        insn = self.md.disasm(tmp, address)
        opsize = int(size)

        offset, name = self.get_offset_and_name(address)
        log_data = '0x%0*x {%-20s + 0x%06x}   ' % (self.ql.archbit // 4, address, name, offset)

        temp_str = ""
        for i in tmp:
            temp_str += ("%02x " % i)
        log_data += temp_str.ljust(30)

        first = True
        for i in insn:
            if not first:
                log_data += '\n> '
            first = False
            log_data += "%s %s" % (i.mnemonic, i.op_str)
        self.ql.log.info(log_data)

        if self.ql.verbose >= QL_VERBOSE.DUMP:
            for reg in self.ql.reg.register_mapping:
                if isinstance(reg, str):
                    REG_NAME = reg
                    REG_VAL = self.ql.reg.read(reg)
                    self.ql.log.debug("%s\t:\t 0x%x" % (REG_NAME, REG_VAL))

    def setup_output(self):
        def ql_hook_block_disasm(ql, address, size):
            self.ql.log.info("\nTracing basic block at 0x%x" % (address))

        if self._disasm_hook:
            self._disasm_hook.remove()
            self._disasm_hook = None
        if self._block_hook:
            self._block_hook.remove()
            self._block_hook = None

        if self.ql.verbose >= QL_VERBOSE.DISASM:
            if self.ql.verbose >= QL_VERBOSE.DUMP:
                self._block_hook = self.ql.hook_block(ql_hook_block_disasm)
            self._disasm_hook = self.ql.hook_code(self.disassembler)

def ql_create_disassembler(archtype: QL_ARCH, archendian: QL_ENDIAN, reg_cpsr=None) -> Cs:
    if archtype == QL_ARCH.X86:
        md = Cs(CS_ARCH_X86, CS_MODE_32)

    elif archtype == QL_ARCH.X8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    elif archtype == QL_ARCH.ARM:
        mode = CS_MODE_THUMB if reg_cpsr & __reg_cpsr_v[archendian] else CS_MODE_ARM

        md = Cs(CS_ARCH_ARM, mode) # FIXME: should be: mode + __cs_endian[archendian]

    elif archtype == QL_ARCH.ARM_THUMB:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    elif archtype == QL_ARCH.ARM64:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    elif archtype == QL_ARCH.MIPS:
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + __cs_endian[archendian])

    elif archtype == QL_ARCH.A8086:
        md = Cs(CS_ARCH_X86, CS_MODE_16)

    elif archtype == QL_ARCH.CORTEX_M:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)

    elif archtype == QL_ARCH.EVM:
        raise NotImplementedError('evm')

    else:
        raise QlErrorArch(f'{archtype:d}')

    return md

def ql_create_assembler(archtype: QL_ARCH, archendian: QL_ENDIAN, reg_cpsr=None) -> Ks:
    if archtype == QL_ARCH.X86:
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

    elif archtype == QL_ARCH.X8664:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

    elif archtype == QL_ARCH.ARM:
        mode = KS_MODE_THUMB if reg_cpsr & __reg_cpsr_v[archendian] else KS_MODE_ARM

        ks = Ks(KS_ARCH_ARM, mode) # FIXME: should be: mode + __ks_endian[archendian]

    elif archtype == QL_ARCH.ARM_THUMB:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    elif archtype == QL_ARCH.ARM64:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    elif archtype == QL_ARCH.MIPS:
        ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + __ks_endian[archendian])

    elif archtype == QL_ARCH.A8086:
        ks = Ks(KS_ARCH_X86, KS_MODE_16)

    elif archtype == QL_ARCH.EVM:
        raise NotImplementedError('evm')

    else:
        raise QlErrorArch(f'{archtype:d}')

    return ks
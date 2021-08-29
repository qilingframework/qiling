#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

from typing import Tuple
from os.path import basename

from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN, QL_VERBOSE
from qiling.exception import QlErrorArch

class QlArchUtils:
    def __init__(self, ql: Qiling):
        self.ql = ql
        self.qd = None
        self._disasm_hook = None
        self._block_hook = None

    def get_offset_and_name(self, addr: int) -> Tuple[int, str]:
        for begin, end, _, name in self.ql.mem.map_info:
            if begin <= addr < end:
                return addr - begin, basename(name)

        return addr, '-'

    def disassembler(self, ql, address, size):
        tmp = self.ql.mem.read(address, size)

        if not self.qd:
            self.qd = self.ql.create_disassembler()
        elif self.ql.archtype == QL_ARCH.ARM: # Update disassembler for arm considering thumb swtich.
            self.qd = self.ql.create_disassembler()

        insn = self.qd.disasm(tmp, address)
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
    raise QlErrorArch(f'{archtype:d}')

def ql_create_assembler(archtype: QL_ARCH, archendian: QL_ENDIAN, reg_cpsr=None) -> Ks:
    raise QlErrorArch(f'{archtype:d}')

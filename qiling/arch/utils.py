#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

from typing import Tuple
from os.path import basename

from qiling import Qiling
from qiling.const import QL_VERBOSE

class QlArchUtils:
    def __init__(self, ql: Qiling):
        self.ql = ql

        self._disasm_hook = None
        self._block_hook = None

    def get_offset_and_name(self, addr: int) -> Tuple[int, str]:
        for begin, end, _, name in self.ql.mem.map_info:
            if begin <= addr < end:
                return addr - begin, basename(name)

        return addr, '-'

    def disassembler(self, ql: Qiling, address: int, size: int):
        tmp = ql.mem.read(address, size)
        qd = ql.arch.create_disassembler()

        offset, name = self.get_offset_and_name(address)
        log_data = f'{address:0{ql.archbit // 4}x} [{name:20s} + {offset:#08x}]  {tmp.hex(" "):30s}'
        log_insn = '\n> '.join(f'{insn.mnemonic:20s} {insn.op_str}' for insn in qd.disasm(tmp, address))

        ql.log.info(log_data + log_insn)

        if ql.verbose >= QL_VERBOSE.DUMP:
            for reg in ql.reg.register_mapping:
                if type(reg) is str:
                    ql.log.debug(f'{reg}\t: {ql.reg.read(reg):#x}')

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

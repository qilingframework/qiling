#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

from typing import Tuple
from os.path import basename
from functools import lru_cache

from keystone import (Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_ARCH_X86, KS_ARCH_PPC,
    KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_MIPS32, KS_MODE_PPC32, KS_MODE_16, KS_MODE_32, KS_MODE_64,
    KS_MODE_LITTLE_ENDIAN, KS_MODE_BIG_ENDIAN)

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN, QL_VERBOSE

class QlArchUtils:
    def __init__(self, ql: Qiling):
        self.ql = ql

        self._disasm_hook = None
        self._block_hook = None

    @lru_cache(maxsize=64)
    def get_base_and_name(self, addr: int) -> Tuple[int, str]:
        for begin, end, _, name, _ in self.ql.mem.map_info:
            if begin <= addr < end:
                return begin, basename(name)

        return addr, '-'

    def disassembler(self, ql: Qiling, address: int, size: int):
        data = ql.mem.read(address, size)

        # knowing that all binary sections are aligned to page boundary allows
        # us to 'cheat' and search for the containing image using the aligned
        # address instead of the actual one.
        #
        # also, the locality property determines that consequent instructions
        # are most likely to reside at the same page in memory, so the containing
        # page of the current instruction is probably the same as the previous
        # one.
        #
        # both assumptions make it possible to cache the search results and pull
        # them off by lru, which provides about 20% speed-up in this case
        ba, name = self.get_base_and_name(ql.mem.align(address))

        anibbles = ql.arch.bits // 4

        for insn in ql.arch.disassembler.disasm(data, address):
            offset = insn.address - ba

            ql.log.info(f'{insn.address:0{anibbles}x} [{name:20s} + {offset:#08x}]  {insn.bytes.hex(" "):20s} {insn.mnemonic:20s} {insn.op_str}')

        if ql.verbose >= QL_VERBOSE.DUMP:
            for reg in ql.arch.regs.register_mapping:
                ql.log.info(f'{reg:10s} : {ql.arch.regs.read(reg):#x}')

    def setup_output(self, verbosity: QL_VERBOSE):
        def ql_hook_block_disasm(ql: Qiling, address: int, size: int):
            self.ql.log.info(f'\nTracing basic block at {address:#x}')

        if self._disasm_hook:
            self._disasm_hook.remove()
            self._disasm_hook = None

        if self._block_hook:
            self._block_hook.remove()
            self._block_hook = None

        if verbosity >= QL_VERBOSE.DISASM:
            self._disasm_hook = self.ql.hook_code(self.disassembler)

            if verbosity >= QL_VERBOSE.DUMP:
                self._block_hook = self.ql.hook_block(ql_hook_block_disasm)

# used by qltool prior to ql instantiation. to get an assembler object
# after ql instantiation, use the appropriate ql.arch method
def assembler(arch: QL_ARCH, endianess: QL_ENDIAN, is_thumb: bool) -> Ks:
    """Instantiate an assembler object for a specified architecture.

    Args:
        arch: architecture type
        endianess: architecture endianess
        is_thumb: thumb mode for ARM (ignored otherwise)

    Returns: an assembler object
    """

    endian = {
        QL_ENDIAN.EL : KS_MODE_LITTLE_ENDIAN,
        QL_ENDIAN.EB : KS_MODE_BIG_ENDIAN
    }[endianess]

    thumb = KS_MODE_THUMB if is_thumb else 0

    asm_map = {
        QL_ARCH.ARM   : (KS_ARCH_ARM, KS_MODE_ARM + endian + thumb),
        QL_ARCH.ARM64 : (KS_ARCH_ARM64, KS_MODE_ARM),
        QL_ARCH.MIPS  : (KS_ARCH_MIPS, KS_MODE_MIPS32 + endian),
        QL_ARCH.A8086 : (KS_ARCH_X86, KS_MODE_16),
        QL_ARCH.X86   : (KS_ARCH_X86, KS_MODE_32),
        QL_ARCH.X8664 : (KS_ARCH_X86, KS_MODE_64),
        QL_ARCH.PPC   : (KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)
    }

    if arch in asm_map:
        return Ks(*asm_map[arch])

    raise NotImplementedError

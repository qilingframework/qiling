#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_BIG_ENDIAN
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_BIG_ENDIAN

from qiling import Qiling
from qiling.const import QL_ENDIAN
from qiling.arch.arch import QlArch
from qiling.arch import arm_const
from qiling.arch.register import QlRegisterManager

class QlArchARM(QlArch):
    bits = 32

    def __init__(self, ql: Qiling, endian: QL_ENDIAN, thumb: bool):
        super().__init__(ql)

        self._init_endian = endian
        self._init_thumb = thumb

        self.arm_get_tls_addr = 0xFFFF0FE0

    @cached_property
    def uc(self) -> Uc:
        mode = UC_MODE_ARM

        if self._init_endian == QL_ENDIAN.EB:
            mode += UC_MODE_BIG_ENDIAN

        if self._init_thumb:
            mode += UC_MODE_THUMB

        return Uc(UC_ARCH_ARM, mode)

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = arm_const.reg_map
        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @property
    def is_thumb(self) -> bool:
        return bool(self.regs.cpsr & (1 << 5))

    @property
    def endian(self) -> QL_ENDIAN:
        # FIXME: ARM is a bi-endian architecture which allows flipping core endianess
        # while running. endianess is tested in runtime through CPSR[9], however unicorn
        # doesn't reflect the endianess correctly through that bit.
        # @see: https://github.com/unicorn-engine/unicorn/issues/1542
        #
        # we work around this by using the initial endianess configuration, even though
        # it might have been changed since.
        #
        # return QL_ENDIAN.EB if self.regs.cpsr & (1 << 9) else QL_ENDIAN.EL

        return self._init_endian

    def get_pc(self) -> int:
        """Get effective PC value, taking Thumb mode into account.
        """

        # append 1 to pc if in thumb mode, or 0 otherwise
        return self.regs.pc + int(self.is_thumb)

    @property
    def disassembler(self) -> Cs:
        # note: we do not cache the disassembler instance; rather we refresh it
        # each time to make sure current endianess and thumb mode are taken into
        # account

        mode = CS_MODE_ARM

        if self.endian == QL_ENDIAN.EB:
            mode += CS_MODE_BIG_ENDIAN

        if self.is_thumb:
            mode += CS_MODE_THUMB

        return Cs(CS_ARCH_ARM, mode)

    @property
    def assembler(self) -> Ks:
        # note: we do not cache the assembler instance; rather we refresh it
        # each time to make sure current endianess and thumb mode are taken into
        # account

        mode = KS_MODE_ARM

        if self.endian == QL_ENDIAN.EB:
            mode += KS_MODE_BIG_ENDIAN

        if self.is_thumb:
            mode += KS_MODE_THUMB

        return Ks(KS_ARCH_ARM, mode)

    def enable_vfp(self) -> None:
        # set full access to cp10 and cp11
        self.regs.c1_c0_2 = self.regs.c1_c0_2 | (0xb11 << 20) | (0xb11 << 22)

        self.regs.fpexc = (1 << 30)

    """
    set_tls
    """
    def init_get_tls(self):
        self.ql.mem.map(0xFFFF0000, 0x1000, info="[arm_tls]")
        """
        'adr r0, data; ldr r0, [r0]; mov pc, lr; data:.ascii "\x00\x00"'
        """
        sc = b'\x04\x00\x8f\xe2\x00\x00\x90\xe5\x0e\xf0\xa0\xe1\x00\x00\x00\x00'

        # if self.endian == QL_ENDIAN.EB:
        #    sc = swap_endianess(sc)

        self.ql.mem.write(self.arm_get_tls_addr, sc)
        self.ql.log.debug("Set init_kernel_get_tls")    

    def swap_endianess(self, s: bytes, blksize=4) -> bytes:
        blocks = (s[i:i + blksize] for i in range(0, len(s), blksize))

        return b''.join(bytes(reversed(b)) for b in blocks)
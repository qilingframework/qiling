#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import ClassVar, Dict, Optional

from .arch import Arch


class ArchARM(Arch):
    _flags_reg: ClassVar[str] = 'cpsr'

    def __init__(self) -> None:
        regs = (
            'r0', 'r1', 'r2', 'r3',
            'r4', 'r5', 'r6', 'r7',
            'r8', 'r9', 'r10', 'r11',
            'r12', 'sp', 'lr', 'pc'
        )

        aliases = {
            'r9' : 'sb',
            'r10': 'sl',
            'r12': 'ip',
            'r11': 'fp'
        }

        asize = 4
        isize = 4

        super().__init__(regs, aliases, asize, isize)

    @staticmethod
    def get_flags(bits: int) -> Dict[str, bool]:
        return {
            'thumb':    bits & (0b1 <<  5) != 0,
            'fiq':      bits & (0b1 <<  6) != 0,
            'irq':      bits & (0b1 <<  7) != 0,
            'overflow': bits & (0b1 << 28) != 0,
            'carry':    bits & (0b1 << 29) != 0,
            'zero':     bits & (0b1 << 30) != 0,
            'neg':      bits & (0b1 << 31) != 0
        }

    @staticmethod
    def get_mode(bits: int) -> str:
        modes = {
            0b10000: 'User',
            0b10001: 'FIQ',
            0b10010: 'IRQ',
            0b10011: 'Supervisor',
            0b10110: 'Monitor',
            0b10111: 'Abort',
            0b11010: 'Hypervisor',
            0b11011: 'Undefined',
            0b11111: 'System'
        }

        return modes.get(bits & 0b11111, '?')

    @property
    def is_thumb(self) -> bool:
        """Query whether the processor is currently in thumb mode.
        """

        return self.ql.arch.is_thumb

    @property
    def isize(self) -> int:
        return 2 if self.is_thumb else self._isize

    @staticmethod
    def __is_wide_insn(data: bytes) -> bool:
        """Determine whether a sequence of bytes respresents a wide thumb instruction.
        """

        assert len(data) in (2, 4), f'unexpected instruction length: {len(data)}'

        # determine whether this is a wide instruction by inspecting the 5 most
        # significant bits in the first half-word
        return (data[1] >> 3) & 0b11111 in (0b11101, 0b11110, 0b11111)

    def __read_thumb_insn_fail(self, address: int) -> Optional[bytearray]:
        """A failsafe method for reading thumb instructions. This method is needed for
        rare cases in which a narrow instruction is on a page boundary where the next
        page is unavailable.
        """

        lo_half = self.try_read_mem(address, 2)

        if lo_half is None:
            return None

        data = lo_half

        if ArchARM.__is_wide_insn(data):
            hi_half = self.try_read_mem(address + 2, 2)

            # fail if higher half-word was required but could not be read
            if hi_half is None:
                return None

            data.extend(hi_half)

        return data

    def __read_thumb_insn(self, address: int) -> Optional[bytearray]:
        """Read one instruction in thumb mode.

        Thumb instructions may be either 2 or 4 bytes long, depending on encoding of
        the first word. However, reading two chunks of two bytes each is slower. For
        most cases reading all four bytes in advance will be safe and quicker.
        """

        data = self.try_read_mem(address, 4)

        if data is None:
            # there is a slight chance we could not read 4 bytes because only 2
            # are available. try the failsafe method to find out
            return self.__read_thumb_insn_fail(address)

        if ArchARM.__is_wide_insn(data):
            return data

        return data[:2]

    def read_insn(self, address: int) -> Optional[bytearray]:
        """Read one instruction worth of bytes.
        """

        if self.is_thumb:
            return self.__read_thumb_insn(address)

        return super().read_insn(address)


class ArchCORTEX_M(ArchARM):
    _flags_reg: ClassVar[str] = 'xpsr'

    def __init__(self):
        super().__init__()

        self._regs += (
            'xpsr', 'control', 'primask',
            'basepri', 'faultmask'
        )

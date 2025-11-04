#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Collection, Dict, Mapping, Optional, TypeVar

T = TypeVar('T')


class Arch:
    """Arch base class.
    """

    def __init__(self, regs: Collection[str], swaps: Mapping[str, str], asize: int, isize: int) -> None:
        """Initialize architecture instance.

        Args:
            regs  : collection of registers names to include in context
            asize : native address size in bytes
            isize : instruction size in bytes
            swaps : readable register names alternatives, may be empty
        """

        self._regs = regs
        self._swaps = swaps
        self._asize = asize
        self._isize = isize

    @property
    def regs(self) -> Collection[str]:
        """Collection of registers names.
        """

        return self._regs

    @property
    def isize(self) -> int:
        """Native instruction size.
        """

        return self._isize

    @property
    def asize(self) -> int:
        """Native pointer size.
        """

        return self._asize

    def swap_regs(self, mapping: Mapping[str, T]) -> Dict[str, T]:
        """Swap default register names with their aliases.

        Args:
            mapping: regsiters names mapped to their values

        Returns: a new dictionary where all swappable names were swapped with their aliases
        """

        return {self._swaps.get(k, k): v for k, v in mapping.items()}

    def unalias(self, name: str) -> str:
        """Get original register name for the specified alias.

        Args:
            name: aliaes register name

        Returns: original name of aliased register, or same name if not an alias
        """

        # perform a reversed lookup in swaps to find the original name for given alias
        return next((org for org, alt in self._swaps.items() if name == alt), name)

    def read_insn(self, address: int) -> Optional[bytearray]:
        """Read a single instruction from given address.

        Args:
            address: memory address to read from

        Returns: instruction bytes, or None if memory could not be read
        """

        return self.try_read_mem(address, self.isize)

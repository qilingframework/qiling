#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc


class QlMsrManager:
    """Enables access to Intel MSR.
    """

    def __init__(self, uc: Uc) -> None:
        self.uc = uc

    def read(self, msr: int) -> int:
        """Read a model-specific register value.
        """

        return self.uc.msr_read(msr)

    def write(self, msr: int, value: int):
        """Write a model-specific register value.
        """

        self.uc.msr_write(msr, value)

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .render import ContextRender
from ..arch import ArchRISCV, ArchRISCV64


class ContextRenderRISCV(ContextRender, ArchRISCV):
    """Context renderer for RISC-V architecture.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.regs_a_row = 5

    def print_mode_info(self) -> None:
        pass


class ContextRenderRISCV64(ContextRenderRISCV, ArchRISCV64):
    """Context renderer for RISC-V 64-bit architecture.
    """

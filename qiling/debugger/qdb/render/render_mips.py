#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .render import ContextRender
from ..arch import ArchMIPS


class ContextRenderMIPS(ContextRender, ArchMIPS):
    """Context renderer for MIPS architecture.
    """

    def print_mode_info(self) -> None:
        pass

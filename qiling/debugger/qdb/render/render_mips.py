#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



from .render import *
from ..arch import ArchMIPS

class ContextRenderMIPS(ContextRender, ArchMIPS):
    """
    context render for MIPS
    """

    def __init__(self, ql, predictor):
        super().__init__(ql, predictor)
        ArchMIPS.__init__(self)

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        """
        redering context registers
        """

        cur_regs = self.dump_regs()
        cur_regs = self.swap_reg_name(cur_regs)
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)

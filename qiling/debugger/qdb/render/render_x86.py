#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



from .render import *
from ..arch import ArchX86

class ContextRenderX86(ContextRender, ArchX86):
    """
    context render for X86
    """

    def __init__(self, ql, predictor):
        super().__init__(ql, predictor)
        ArchX86.__init__(self)

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        cur_regs = self.dump_regs()
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)
        print(color.GREEN, "EFLAGS: [CF: {flags[CF]}, PF: {flags[PF]}, AF: {flags[AF]}, ZF: {flags[ZF]}, SF: {flags[SF]}, OF: {flags[OF]}]".format(flags=self.get_flags(self.ql.arch.regs.eflags)), color.END, sep="")

    @Render.divider_printer("[ DISASM ]")
    def context_asm(self):
        lines = {}
        past_list = []

        cur_addr = self.cur_addr
        while len(past_list) < 10:
            line = self.disasm(cur_addr)
            past_list.append(line)
            cur_addr += line.size

        fd_list = []
        cur_insn = None
        for each in past_list:
            if each.address > self.cur_addr:
                fd_list.append(each)

            elif each.address == self.cur_addr:
                cur_insn = each 

        """
        only forward and current instruction will be printed, 
        because we don't have a solid method to disasm backward instructions,
        since it's x86 instruction length is variadic 
        """

        lines.update({
            "current": cur_insn,
            "forward": fd_list,
            })

        self.render_assembly(lines)

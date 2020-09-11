from idaapi import *
from idc import *
from idautils import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import (QPushButton, QHBoxLayout)
from qiling.extensions.idaplugin.utils import QlEmuMisc
from qiling import Qiling
from qiling.const import *
from qiling.utils import ql_get_arch_bits

import struct

class QlEmuStackView(simplecustviewer_t):
    def __init__(self, ql_emu_plugin):
        super(QlEmuStackView, self).__init__()
        self.ql_emu_plugin = ql_emu_plugin

    def Create(self):
        title = "QL Stack View"
        if not simplecustviewer_t.Create(self, title):
            return False
        return True

    def SetStack(self, ql:Qiling):
        self.ClearLines()
        if ql is None:
            return
        
        sp = ql.reg.arch_sp
        self.AddLine('')
        self.AddLine(COLSTR('  Stack at 0x%X' % sp, SCOLOR_AUTOCMT))
        self.AddLine('')

        arch = ql.archtype
        if arch == "":
            return

        reg_bit_size = ql_get_arch_bits(arch)
        reg_byte_size = reg_bit_size // 8
        value_format = '% .16X' if reg_bit_size == 64 else '% .8X'

        for i in range(-30, 30):
            clr = SCOLOR_DREF if i < 0 else SCOLOR_INSN
            cur_addr = (sp + i * reg_byte_size)
            line = ('  ' + value_format + ': ') % cur_addr
            try:
                value = ql.mem.read(cur_addr, reg_byte_size)
                value, = struct.unpack('Q' if reg_bit_size == 64 else 'I', value)
                line += value_format % value
            except Exception:
                line += '?' * reg_byte_size * 2

            self.AddLine(COLSTR(line, clr))  

    def OnClose(self):
        self.ql_emu_plugin.ql_close_stack_view()
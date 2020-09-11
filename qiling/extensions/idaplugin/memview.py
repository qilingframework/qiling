from idaapi import *
from idc import *
from idautils import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import (QPushButton, QHBoxLayout)
from qiling.extensions.idaplugin.utils import QlEmuMisc
from qiling import Qiling
from qiling.const import *

class QlEmuMemView(simplecustviewer_t):
    def __init__(self, ql_emu_plugin, addr, size):
        super(QlEmuMemView, self).__init__()
        self.ql_emu_plugin = ql_emu_plugin
        self.viewid = addr
        self.addr = addr
        self.size = size
        self.lastContent = []

    def Create(self, title):
        if not simplecustviewer_t.Create(self, title):
            return False
        return True

    def SetMem(self, ql:Qiling):
        self.ClearLines()

        if ql is None:
            return

        try:
            memory = ql.mem.read(self.addr, self.size)
        except:
            return

        size = len(memory)

        view_title = COLSTR("  Memory at [ ", SCOLOR_AUTOCMT)
        view_title += COLSTR("0x%X: %d byte(s)" % (self.addr, size), SCOLOR_DREF)
        view_title += COLSTR(" ]", SCOLOR_AUTOCMT)
        self.AddLine(str(view_title))
        self.AddLine("")
        self.AddLine(COLSTR("                0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", SCOLOR_AUTOCMT))

        startAddress = self.addr
        line = ""
        chars = ""
        get_char = lambda byte: chr(byte) if 0x20 <= byte <= 0x7E else '.'

        if size != 0:
            for x in range(size):
                if x%16==0:
                    line += COLSTR(" %.12X: " % startAddress, SCOLOR_AUTOCMT)
                if len(self.lastContent) == len(memory):
                    if memory[x] != self.lastContent[x]:
                        line += COLSTR(str("%.2X " % memory[x]), SCOLOR_VOIDOP)
                        chars += COLSTR(get_char(memory[x]), SCOLOR_VOIDOP)
                    else:
                        line += COLSTR(str("%.2X " % memory[x]), SCOLOR_NUMBER)
                        chars += COLSTR(get_char(memory[x]), SCOLOR_NUMBER)
                else:
                    line += COLSTR(str("%.2X " % memory[x]), SCOLOR_NUMBER)
                    chars += COLSTR(get_char(memory[x]), SCOLOR_NUMBER)

                if (x+1)%16==0:
                    line += "  " + chars
                    self.AddLine(line)
                    startAddress += 16
                    line = ""
                    chars = ""

            # add padding
            tail = 16 - size%16
            if tail != 0:
                for x in range(tail): line += "   "
                line += "  " + chars
                self.AddLine(line)

        self.Refresh()
        self.lastContent = memory

    def OnClose(self):
        self.ql_emu_plugin.ql_close_mem_view(self.viewid)
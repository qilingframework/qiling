from idaapi import *
from idc import *
from idautils import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import (QPushButton, QHBoxLayout)
from qiling.extensions.idaplugin.utils import QlEmuMisc
from qiling import Qiling
from qiling.const import *

### View Class
class QlEmuRegView(simplecustviewer_t):
    def __init__(self, ql_emu_plugin):
        super(QlEmuRegView, self).__init__()
        self.hooks = None
        self.ql_emu_plugin = ql_emu_plugin

    def Create(self):
        title = "QL Register View"
        if not simplecustviewer_t.Create(self, title):
            return False

        self.menu_update = 1

        class Hooks(UI_Hooks):
            class PopupActionHandler(action_handler_t):
                def __init__(self, subview, menu_id):
                    action_handler_t.__init__(self)
                    self.subview = subview
                    self.menu_id = menu_id

                def activate(self, ctx):
                    self.subview.OnPopupMenu(self.menu_id)

                def update(self, ctx):
                    return AST_ENABLE_ALWAYS

            def __init__(self, form):
                UI_Hooks.__init__(self)
                self.form = form

            def finish_populating_widget_popup(self, widget, popup):
                if self.form.title == get_widget_title(widget):
                    attach_dynamic_action_to_popup(widget, popup, action_desc_t(None, "Edit Register", self.PopupActionHandler(self.form, self.form.menu_update),  None, None, -1))     
        
        if self.hooks is None:
            self.hooks = Hooks(self)
            self.hooks.hook()

        return True

    def SetReg(self, addr, ql:Qiling):
        arch = ql.archtype
        if arch == "":
            return
        
        #clear
        self.ClearLines()

        view_title = COLSTR("Reg value at { ", SCOLOR_AUTOCMT)
        view_title += COLSTR("IDA Address:0x%X | QL Address:0x%X" % (addr, addr - self.ql_emu_plugin.qlemu.baseaddr + get_imagebase()), SCOLOR_DREF)
        # TODO: Add disass should be better
        view_title += COLSTR(" }", SCOLOR_AUTOCMT)
        self.AddLine(view_title)
        self.AddLine("")

        reglist = QlEmuMisc.get_reg_map(ql)
        line = ""
        cols = 3
        reglist = [reglist[i:i+cols] for i in range(0,len(reglist),cols)]
        for regs in reglist:
            for reg in regs:
                line += COLSTR(" %4s: " % str(reg), SCOLOR_REG)
                regvalue = ql.reg.read(reg)
                if arch in [QL_ARCH.X8664, QL_ARCH.ARM64]:
                    value_format = "0x%.16X"
                else:
                    value_format = "0x%.8X"
                line += COLSTR(str(value_format % regvalue), SCOLOR_NUMBER)
                # TODO: ljust will looks better
            self.AddLine(line)
            line = ''
        self.AddLine(line)
        self.Refresh()

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_update:
            self.ql_emu_plugin.ql_chang_reg()

    def OnClose(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
        self.ql_emu_plugin.ql_close_reg_view()
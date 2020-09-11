from idaapi import *
from idc import *
from idautils import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import (QPushButton, QHBoxLayout)
from qiling.extensions.idaplugin.utils import QlEmuMisc
from qiling import Qiling
from qiling.const import *

### Dialog Class
class QlEmuMemDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:mem_addr}
BUTTON YES* Add
BUTTON CANCEL Cancel
Show Memory Range
Specify start address and size of new memory range.
<##Address\::{mem_addr}> <##Size\::{mem_size}>
<##Comment\::{mem_cmnt}>
""", {
        'mem_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'mem_size': Form.NumericInput(swidth=10, tp=Form.FT_DEC),
        'mem_cmnt': Form.StringInput(swidth=41)
    })

class QlEmuSetupDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:path_name}
BUTTON YES* Start
BUTTON CANCEL Cancel
Setup Qiling
<#Select Rootfs to open#Rootfs path\:        :{path_name}>
<#Custom script path   #Custom script path\: :{script_name}>
""", {
        'path_name': Form.DirInput(swidth=50),
        'script_name': Form.DirInput(swidth=50),
    })
 
class QlEmuSaveDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:path_name}
BUTTON YES* Save
BUTTON CANCEL Cancel
Save Path
<#Save to#Path\::{path_name}>
""", {
        'path_name': Form.FileInput(swidth=50, save=True),
    })    

class QlEmuLoadDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:file_name}
BUTTON YES* Load
BUTTON CANCEL Cancel
Load File
<#Load From#File\::{file_name}>
""", {
        'file_name': Form.FileInput(swidth=50, open=True)
    })   

class QlEmuAboutDialog(Form):
    def __init__(self, version):
        super(QlEmuAboutDialog, self).__init__(
            r"""STARTITEM 0
BUTTON YES* Open Qiling Website
Qiling:: About
            {FormChangeCb}
            Qiling IDA plugin v%s, using Qiling Engine v%s.
            (c) Qiling Team, 2020.
            Qiling is released under the GPL v2.
            Find more info at https://www.qiling.io
            """ %(version, QLVERSION), {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            import webbrowser
            # open Keypatch homepage in a new tab, if possible
            webbrowser.open(QilingHomePage, new = 2)

        return 1

class QlEmuUpdateDialog(Form):
    def __init__(self, version, message):
        super(QlEmuUpdateDialog, self).__init__(
            r"""STARTITEM 0
BUTTON YES* Open Qiling Website
Qiling:: Check for update
            {FormChangeCb}
            Your Qiling is v%s
            %s
            """ %(version, message), {
            'FormChangeCb': self.FormChangeCb(self.OnFormChange),
            })
        self.Compile()

    # callback to be executed when any form control changed
    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            import webbrowser
            # open Keypatch homepage in a new tab, if possible
            webbrowser.open(QilingHomePage, new = 2)

        return 1

class QlEmuRegEditDialog(Form):
    def __init__(self, regName):
        Form.__init__(self, r"""STARTITEM {id:reg_val}
BUTTON YES* Save
BUTTON CANCEL Cancel
Register Value
{reg_label}
<##:{reg_val}>
""", {
        'reg_label': Form.StringLabel("Edit [ " + regName + " ] value"),
        'reg_val': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })

class QlEmuRegDialog(Choose):
    def __init__(self, reglist, flags=0, width=None, height=None, embedded=False):
        Choose.__init__(
            self, "QL Register Edit", 
            [ ["Register", 10 | Choose.CHCOL_PLAIN], 
              ["Value", 30] ])
        self.popup_names = ["", "", "Edit Value", ""]
        self.items = reglist

    def show(self):
        return self.Show(True) >= 0

    def OnEditLine(self, n):
        edit_dlg = QlEmuRegEditDialog(self.items[n][0])
        edit_dlg.Compile()
        edit_dlg.reg_val.value = self.items[n][1]
        ok = edit_dlg.Execute()
        if ok == 1:
            newvalue = edit_dlg.reg_val.value
            self.items[n][1] = int("%X" % newvalue, 16)
        self.Refresh()

    def OnGetLine(self, n):
        if self.items[n][2] == 32:
            return [ self.items[n][0], "0x%08X" % self.items[n][1] ]
        if self.items[n][2] == 64:
            return [ self.items[n][0], "0x%16X" % self.items[n][1] ]        

    def OnGetSize(self):
        return len(self.items)

    def OnClose(self):
        pass
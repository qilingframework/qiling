# Cross Platform and Multi Architecture Advanced Binary Emulation Framework Plugin For IDA
# Built on top of Unicorn emulator (www.unicorn-engine.org)
# Learn how to use? Please visit https://docs.qiling.io/en/latest/ida/
# Plugin Author: kabeor

UseAsScript = False
RELEASE = True

import collections

# Qiling
from qiling import *
from qiling.const import *
from qiling.arch.x86_const import reg_map_32 as x86_reg_map_32
from qiling.arch.x86_const import reg_map_64 as x86_reg_map_64
from qiling.arch.x86_const import reg_map_misc as x86_reg_map_misc
from qiling.arch.x86_const import reg_map_st as x86_reg_map_st
from qiling.arch.arm_const import reg_map as arm_reg_map
from qiling.arch.arm64_const import reg_map as arm64_reg_map
from qiling.arch.mips_const import reg_map as mips_reg_map
from qiling.utils import ql_get_arch_bits
from qiling import __version__ as QLVERSION
from qiling.os.filestruct import ql_file

if RELEASE:
    # IDA Python SDK
    from idaapi import *
    from idc import *
    from idautils import *
    # PyQt
    from PyQt5 import QtCore, QtWidgets
    from PyQt5.QtWidgets import (QPushButton, QHBoxLayout)

else:
    import sys
    sys.path.append("./idapython3")
    from idapython3 import *

QilingHomePage = 'https://www.qiling.io'
QilingGithubVersion = 'https://raw.githubusercontent.com/qilingframework/qiling/dev/qiling/core.py'

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
        view_title += COLSTR("IDA Address:0x%X | QL Address:0x%X" % (addr, addr + self.ql_emu_plugin.qlemu.baseaddr), SCOLOR_DREF)
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


### Misc

class QlEmuMisc:
    MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])
    class menu_action_handler(action_handler_t):
        def __init__(self, handler, action):
            action_handler_t.__init__(self)
            self.action_handler = handler
            self.action_type = action

        def activate(self, ctx):
            if ctx.form_type == BWN_DISASM:
                self.action_handler.ql_handle_menu_action(self.action_type)
            return 1

        # This action is always available.
        def update(self, ctx):
            return AST_ENABLE_ALWAYS

    @staticmethod
    def get_reg_map(ql:Qiling):
        tables = {
            QL_ARCH.X86     : list({**x86_reg_map_32, **x86_reg_map_misc, **x86_reg_map_st}.keys()),
            QL_ARCH.X8664   : list({**x86_reg_map_64, **x86_reg_map_misc, **x86_reg_map_st}.keys()),
            QL_ARCH.ARM     : list({**arm_reg_map}.keys()),
            QL_ARCH.ARM64   : list({**arm64_reg_map}.keys()),
            QL_ARCH.MIPS    : list({**mips_reg_map}.keys()),
        }

        if ql.archtype == QL_ARCH.X86:
            return tables[QL_ARCH.X86]
        elif ql.archtype == QL_ARCH.X8664:
            return tables[QL_ARCH.X8664]
        elif ql.archtype == QL_ARCH.ARM:
            return tables[QL_ARCH.ARM]
        elif ql.archtype == QL_ARCH.ARM64:
            return tables[QL_ARCH.ARM64]
        elif ql.archtype == QL_ARCH.MIPS:
            return tables[QL_ARCH.MIPS]
        else:
            return []

    @staticmethod
    def url_download(url):
        try:
            from urllib2 import Request, urlopen, URLError, HTTPError
        except:
            from urllib.request import Request, urlopen
            from urllib.error import URLError, HTTPError

        # create the url and the request
        req = Request(url)

        # Open the url
        try:
            # download this URL
            f = urlopen(req)
            content = f.read()
            return (0, content)

        # handle errors
        except HTTPError as e:
            # print "HTTP Error:", e.code , url
            # fail to download this file
            return (1, None)
        except URLError as e:
            # print "URL Error:", e.reason , url
            # fail to download this file
            return (1, None)
        except Exception as e:
            # fail to save the downloaded file
            # print("Error:", e)
            return (2, None)

    class QLStdIO(ql_file):
        def __init__(self, path, fd):
            super().__init__(path, fd)
            self.__fd = fd

        def write(self, write_buf):
            super().write(write_buf) 
            msg(write_buf.decode('utf-8'))

        def flush(self):
            pass

        def isatty(self):
            return False   


### Qiling

class QlEmuQiling:
    def __init__(self):
        self.path = get_input_file_path()
        self.rootfs = None
        self.ql = None
        self.status = None
        self.exit_addr = None
        self.baseaddr = None

    def start(self):
        qlstdin = QlEmuMisc.QLStdIO('stdin', sys.__stdin__.fileno())
        qlstdout = QlEmuMisc.QLStdIO('stdout', sys.__stdout__.fileno())
        qlstderr = QlEmuMisc.QLStdIO('stderr', sys.__stderr__.fileno())
        self.ql = Qiling(filename=[self.path], rootfs=self.rootfs, output="debug", stdin=qlstdin, stdout=qlstdout, stderr=qlstderr)
        self.exit_addr = self.ql.os.exit_point
        if self.ql.archbit == 32:
            self.baseaddr = int(self.ql.profile.get("OS32", "load_address"), 16)
        elif self.ql.archbit == 64:
            self.baseaddr = int(self.ql.profile.get("OS64", "load_address"), 16)

    def run(self, begin=None, end=None):
        self.ql.run(begin, end)

    def set_reg(self):
        reglist = QlEmuMisc.get_reg_map(self.ql)
        regs = [ [ row, int(self.ql.reg.read(row)), ql_get_arch_bits(self.ql.archtype) ] for row in reglist ]
        regs_len = len(regs)
        RegDig = QlEmuRegDialog(regs)
        if RegDig.show():
            for idx, val in enumerate(RegDig.items[0:regs_len-1]):
                self.ql.reg.write(reglist[idx], val[1])
            return True
        else:
            return False

    def save(self):
        savedlg = QlEmuSaveDialog()
        savedlg.Compile()

        if savedlg.Execute() != 1:
            return False

        savepath = savedlg.path_name.value

        self.ql.save(reg=True, mem=True, cpu_context=True, snapshot=savepath)
        print('Save to ' + savepath)
        return True
    
    def load(self):
        loaddlg = QlEmuLoadDialog()
        loaddlg.Compile()

        if loaddlg.Execute() != 1:
            return False

        loadname = loaddlg.file_name.value

        self.ql.restore(snapshot=loadname)
        print('Restore from ' + loadname)
        return True

    def remove_ql(self):
        if self.ql is not None:
            del self.ql
            self.ql = None

### Plugin

class QlEmuPlugin(plugin_t, UI_Hooks):
    ### Ida Plugin Data

    popup_menu_hook = None

    flags = PLUGIN_KEEP
    comment = ""

    help = "Qiling Emulator"
    wanted_name = "Qiling Emulator"
    wanted_hotkey = ""

    ### View Data

    qlemuregview = None
    qlemustackview = None
    qlemumemview = {}

    def __init__(self):
        super(QlEmuPlugin, self).__init__()
        self.plugin_name = "Qiling Emulator"
        self.qlemu = None
        self.ql = None
        self.stepflag = True
        self.stephook = None
        self.qlinit = False
        self.lastaddr = None
        self.userobj = None
        self.customscriptpath = None

    ### Main Framework

    def init(self):
        # init data
        print('---------------------------------------------------------------------------------------')
        print('Qiling Emulator Plugin For IDA, by Qiling Team. Version {0}, 2020'.format(QLVERSION))
        print('Based on Qiling v{0}'.format(QLVERSION))
        print('Find more information about Qiling at https://qiling.io')
        print('---------------------------------------------------------------------------------------')
        self.qlemu = QlEmuQiling()
        self.ql_hook_ui_actions()
        return PLUGIN_KEEP

    def run(self, arg = 0):
        self.ql_register_menu_actions()
        self.ql_attach_main_menu_actions()

    def term(self):
        self.qlemu.remove_ql()
        self.ql_unhook_ui_actions()
        self.ql_detach_main_menu_actions()
        self.ql_unregister_menu_actions()

    ### Actions

    def ql_start(self):
        if self.qlemu is None:
            self.qlemu = QlEmuQiling()
        if self.ql_set_rootfs():
            print('Set rootfs success')
            show_wait_box("Qiling is processing ...")
            try:
                self.qlemu.start()
                self.qlinit = True
            finally:
                hide_wait_box()
                print("Qiling initialized done")
        self.ql_load_user_script()

    def ql_load_user_script(self):
        if self.qlinit:
            self.ql_get_user_script()
        else:
            print('Please setup Qiling first')
    def ql_reload_user_script(self):
        if self.qlinit:
            self.ql_get_user_script(True)
        else:
            print('Please setup Qiling first')

    def ql_continue(self):
        if self.qlinit:
            userhook = None
            pathhook = self.qlemu.ql.hook_code(self.ql_path_hook)
            if self.userobj is not None:
                userhook = self.userobj.ql_continue_hook_add(self.qlemu.ql)
            if self.qlemu.status is not None:
                self.qlemu.ql.restore(self.qlemu.status)
                show_wait_box("Qiling is processing ...")
                try:
                    self.qlemu.run(begin=self.qlemu.ql.reg.arch_pc, end=self.qlemu.exit_addr)
                finally:
                    hide_wait_box()
            else:
                show_wait_box("Qiling is processing ...")
                try:
                    self.qlemu.run()
                finally:
                    hide_wait_box()
            self.qlemu.ql.hook_del(pathhook)
            if userhook is not None:
                self.qlemu.ql.hook_del(userhook)
            self.ql_update_views(self.qlemu.ql.reg.arch_pc, self.qlemu.ql)
        else:
            print('Please setup Qiling first')

    def ql_run_to_here(self):
        if self.qlinit:
            curr_addr = get_screen_ea()
            untillhook = self.qlemu.ql.hook_code(self.ql_untill_hook)
            if self.qlemu.status is not None:
                self.qlemu.ql.restore(self.qlemu.status)
                show_wait_box("Qiling is processing ...")
                try:
                    self.qlemu.run(begin=self.qlemu.ql.reg.arch_pc, end=curr_addr + self.qlemu.baseaddr)
                finally:
                    hide_wait_box()
            else:
                show_wait_box("Qiling is processing ...")
                try:
                    self.qlemu.run(end=curr_addr + self.qlemu.baseaddr)
                finally:
                    hide_wait_box()
            
            set_color(curr_addr, CIC_ITEM, 0x00B3CBFF)
            self.qlemu.ql.hook_del(untillhook)
            self.qlemu.status = self.qlemu.ql.save()
            self.ql_update_views(self.qlemu.ql.reg.arch_pc, self.qlemu.ql)
        else:
            print('Please setup Qiling first')

    def ql_step(self):
        if self.qlinit:
            userhook = None
            self.stepflag = True
            self.qlemu.ql.restore(saved_states=self.qlemu.status)
            self.stephook = self.qlemu.ql.hook_code(callback=self.ql_step_hook)
            if self.userobj is not None:
                userhook = self.userobj.ql_step_hook_add(self.qlemu.ql)            
            self.qlemu.run(begin=self.qlemu.ql.reg.arch_pc, end=self.qlemu.exit_addr)
            if userhook is not None:
                self.qlemu.ql.hook_del(userhook)
            self.ql_update_views(self.qlemu.ql.reg.arch_pc, self.qlemu.ql)
        else:
            print('Please setup Qiling first')

    def ql_save(self):
        if self.qlinit:
            if self.qlemu.save() != True:
                print('ERROR: Save failed')
        else:
            print('Please setup Qiling first')

    def ql_load(self):
        if self.qlinit:
            if self.qlemu.load() != True:
                print('ERROR: Load failed')
        else:
            print('Please setup Qiling first')

    def ql_chang_reg(self):
        if self.qlinit:
            self.qlemu.set_reg()
            self.ql_update_views(self.qlemu.ql.reg.arch_pc, self.qlemu.ql)
            self.qlemu.status = self.qlemu.ql.save()
        else:
            print('Please setup Qiling first')       

    def ql_reset(self):
        if self.qlinit:
            self.ql_close()
            self.qlemu = QlEmuQiling()
            self.ql_start()
        else:
            print('Please setup Qiling first')

    def ql_close(self):
        if self.qlinit:
            heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
            for i in heads:
                set_color(i, CIC_ITEM, 0xFFFFFF)
            self.qlemu.remove_ql()
            del self.qlemu
            self.qlemu = None
            self.qlinit = False
            print('Qiling closed')
        else:
            print('Qiling is not started')

    def ql_show_reg_view(self):
        if self.qlinit:
            if self.qlemuregview is None:
                self.qlemuregview = QlEmuRegView(self)
                QlEmuRegView(self)
                self.qlemuregview.Create()
                self.qlemuregview.SetReg(self.qlemu.ql.reg.arch_pc, self.qlemu.ql)
                self.qlemuregview.Show()
                self.qlemuregview.Refresh()
        else:
            print('Please start Qiling first')

    def ql_show_stack_view(self):
        if self.qlinit:
            if self.qlemustackview is None:
                self.qlemustackview = QlEmuStackView(self)
                self.qlemustackview.Create()
                self.qlemustackview.SetStack(self.qlemu.ql)
                self.qlemustackview.Show()
                self.qlemustackview.Refresh()
        else:
            print('Please Start Qiling First')

    def ql_show_mem_view(self, addr=get_screen_ea(), size=0x10):
        if self.qlinit:
            memdialog = QlEmuMemDialog()
            memdialog.Compile()
            memdialog.mem_addr.value = addr
            memdialog.mem_size.value = size
            ok = memdialog.Execute()
            if ok == 1:
                mem_addr = memdialog.mem_addr.value - self.qlemu.baseaddr
                mem_size = memdialog.mem_size.value
                mem_cmnt = memdialog.mem_cmnt.value

                if mem_addr not in self.qlemumemview:
                    if not self.qlemu.ql.mem.is_mapped(mem_addr, mem_size):
                        ok = ask_yn(1, "Memory [%X:%X] is not mapped!\nDo you want to map it?\n   YES - Load Binary\n   NO - Fill page with zeroes\n   Cancel - Close dialog" % (mem_addr, mem_addr + mem_size))
                        if ok == 0:
                            self.qlemu.ql.mem.map(mem_addr, mem_size)
                            self.qlemu.ql.mem.write(self.qlemu.ql.mem.align(mem_addr), b"\x00"*mem_size)
                        elif ok == 1:
                            # TODO: map_binary
                            return
                        else:
                            return
                    self.qlemumemview[mem_addr] = QlEmuMemView(self, mem_addr, mem_size)
                    if mem_cmnt == []:
                        self.qlemumemview[mem_addr].Create("QL Memory")
                    else:
                        self.qlemumemview[mem_addr].Create("QL Memory [ " + mem_cmnt + " ]")
                    self.qlemumemview[mem_addr].SetMem(self.qlemu.ql)
                self.qlemumemview[mem_addr].Show()
                self.qlemumemview[mem_addr].Refresh() 
        else:
            print('Please start Qiling first')

    def ql_unload_plugin(self):
        heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
        for i in heads:
            set_color(i, CIC_ITEM, 0xFFFFFF)
        self.ql_close()
        self.ql_detach_main_menu_actions()
        self.ql_unregister_menu_actions()
        print('Unload successed')

    def ql_menu_null(self):
        pass

    def ql_about(self):
        self.aboutdlg = QlEmuAboutDialog(QLVERSION)
        self.aboutdlg.Execute()
        self.aboutdlg.Free()

    def ql_check_update(self):
        (r, content) = QlEmuMisc.url_download(QilingGithubVersion)
        content = to_string(content)
        if r == 0:
            # find stable version
            sig = '__version__'
            begin = content.find(sig.encode())+len(sig)
            version_stable = content[begin+4:begin+20].decode().split('\n')[0].replace('\"', '').replace(' ', '').replace('+', '')

            # compare with the current version
            if version_stable == QLVERSION:
                self.updatedlg = QlEmuUpdateDialog(QLVERSION, "Good, you are already on the latest stable version!")
                self.updatedlg.Execute()
                self.updatedlg.Free()
            else:
                self.updatedlg = QlEmuUpdateDialog(QLVERSION, "Download latest stable version {0} from https://github.com/qilingframework/qiling/blob/master/qiling/extensions/idaplugin".format(version_stable))
                self.updatedlg.Execute()
                self.updatedlg.Free()
        else:
            # fail to download
            warning("ERROR: Qiling failed to connect to internet (Github). Try again later.")
            print("Qiling: FAILED to connect to Github to check for latest update. Try again later.")
 
    ### Hook

    def ql_step_hook(self, ql, addr, size):
        self.stepflag = not self.stepflag
        addr = addr - self.qlemu.baseaddr
        if self.stepflag:
            set_color(addr, CIC_ITEM, 0x00FFD700)
            self.ql_update_views(self.qlemu.ql.reg.arch_pc, ql)
            self.qlemu.status = ql.save()
            ql.os.stop()
            self.qlemu.ql.hook_del(self.stephook)
            jumpto(addr)

    def ql_path_hook(self, ql, addr, size):
        addr = addr - self.qlemu.baseaddr
        set_color(addr, CIC_ITEM, 0x007FFFAA)
        bp_count = get_bpt_qty()
        bp_list = []
        if bp_count > 0:
            for num in range(0, bp_count):
                bp_list.append(get_bpt_ea(num))
            if addr in bp_list and addr != self.lastaddr:
                self.qlemu.status = ql.save()
                ql.os.stop()
                self.lastaddr = addr
                jumpto(addr)

    def ql_untill_hook(self, ql, addr, size):
        addr = addr - self.qlemu.baseaddr
        set_color(addr, CIC_ITEM, 0x00B3CBFF)

    ### User Scripts

    def ql_get_user_script(self, is_reload=False):
        def get_user_scripts_obj(scriptpath:str, classname:str, is_reload:bool):
            try:
                import sys
                import importlib

                modulepath,filename = os.path.split(scriptpath)
                scriptname,_ = os.path.splitext(filename)

                sys.path.append(modulepath)
                module = importlib.import_module(scriptname)

                if is_reload:
                    importlib.reload(module)
                cls = getattr(module, classname)
                return cls()
            except:
                return None

        self.userobj = get_user_scripts_obj(self.customscriptpath, 'QL_CUSTOM_SCRIPT', is_reload)
        if self.userobj is not None:
            if is_reload:
                print('User Script Reload')
            else:
                print('User Script Load')
        else:
            print('There Is No User Scripts')

    ### Dialog

    def ql_set_rootfs(self):
        setupdlg = QlEmuSetupDialog()
        setupdlg.Compile()

        if setupdlg.Execute() != 1:
            return False

        rootfspath = setupdlg.path_name.value
        customscript = setupdlg.script_name.value

        if customscript is not None:
            self.customscriptpath = customscript

        if self.qlemu is not None:
            self.qlemu.rootfs = rootfspath
            return True
        return False    

    ### Menu

    menuitems = []

    def ql_register_new_action(self, act_name, act_text, act_handler, shortcut, tooltip, icon):
        new_action = action_desc_t(
            act_name,       # The action name. This acts like an ID and must be unique
            act_text,       # The action text.
            act_handler,    # The action handler.
            shortcut,       # Optional: the action shortcut
            tooltip,        # Optional: the action tooltip (available in menus/toolbar)
            icon)           # Optional: the action icon (shows when in menus/toolbars)
        register_action(new_action)

    def ql_handle_menu_action(self, action):
        [x.handler() for x in self.menuitems if x.action == action]

    def ql_register_menu_actions(self):
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":start",             self.ql_start,                 "Setup",                      "Setup",                     None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":reloaduserscripts", self.ql_reload_user_script,      "Reload User Scripts",        "Reload User Scripts",       None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   True   ))        
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":runtohere",         self.ql_run_to_here,             "Execute Till",               "Execute Till",              None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":runfromhere",       self.ql_continue,              "Continue",                   "Continue",                  None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":step",              self.ql_step,                  "Step",                       "Step (CTRL+SHIFT+F9)",      "CTRL+SHIFT+F9",        True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":changreg",          self.ql_chang_reg,              "Edit Register",              "Edit Register",             None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":reset",             self.ql_reset,                 "Restart",                    "Restart Qiling",            None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":close",             self.ql_close,                 "Close",                      "Close Qiling",              None,                   False  ))
        self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":reg view",          self.ql_show_reg_view,           "View Register",              "View Register",             None,                   True   ))     
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":stack view",        self.ql_show_stack_view,         "View Stack",                 "View Stack",                None,                   True   ))  
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":memory view",       self.ql_show_mem_view,           "View Memory",                "View Memory",               None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":save",              self.ql_save,                  "Save Snapshot",              "Save Snapshot",             None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":load",              self.ql_load,                  "Load Snapshot",              "Load Snapshot",             None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   True   ))
        if UseAsScript:
            self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":unload",            self.ql_unload_plugin,           "Unload Plugin",              "Unload Plugin",             None,                   False  ))
            self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   False  ))  
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":about",             self.ql_about,                 "About",                      "About",                     None,                   False  ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":checkupdate",       self.ql_check_update,           "Check Update",               "Check Update",              None,                   False  ))

        for item in self.menuitems:
            self.ql_register_new_action(item.action, item.title, QlEmuMisc.menu_action_handler(self, item.action), item.shortcut, item.tooltip,  -1)

    def ql_unregister_menu_actions(self):
        for item in self.menuitems:
            unregister_action(item.action)

    def ql_attach_main_menu_actions(self):
        for item in self.menuitems:
            attach_action_to_menu("Edit/Plugins/" + self.plugin_name + "/" + item.title, item.action, SETMENU_APP)

    def ql_detach_main_menu_actions(self):
        for item in self.menuitems:
            detach_action_from_menu("Edit/Plugins/" + self.plugin_name + "/" + item.title, item.action)

    ### POPUP MENU

    def ql_hook_ui_actions(self):
        self.popup_menu_hook = self
        self.popup_menu_hook.hook()

    def ql_unhook_ui_actions(self):
        if self.popup_menu_hook != None:
            self.popup_menu_hook.unhook()

    # IDA 7.x

    def finish_populating_widget_popup(self, widget, popup_handle):
        if get_widget_type(widget) == BWN_DISASM:
            for item in self.menuitems:
                if item.popup:
                    attach_action_to_popup(widget, popup_handle, item.action, self.plugin_name + "/")

    ### Close View

    def ql_close_reg_view(self):
        self.qlemuregview = None

    def ql_close_stack_view(self):
        self.qlemustackview = None
    
    def ql_close_mem_view(self, viewid):
        del self.qlemumemview[viewid]

    def ql_close_all_views(self):
        if self.qlemuregview is not None:
            self.qlemuregview.Close()
        if self.qlemustackview is not None:
            self.qlemustackview.Close()
        
        for viewid in self.qlemumemview:
            self.qlemumemview[viewid].Close()
            self.qlemumemview = None

    def ql_update_views(self, addr, ql):
        if self.qlemuregview is not None:
            self.qlemuregview.SetReg(addr - self.qlemu.baseaddr, ql)

        if self.qlemustackview is not None:
            self.qlemustackview.SetStack(self.qlemu.ql)

        for id in self.qlemumemview:
            self.qlemumemview[id].SetMem(self.qlemu.ql)


def PLUGIN_ENTRY():
    qlEmu = QlEmuPlugin()
    return qlEmu

if UseAsScript:
    if __name__ == "__main__":
        qlEmu = QlEmuPlugin()
        qlEmu.init()
        qlEmu.run()

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

UseAsScript = True
RELEASE = True
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


### View Class
class QLEmuRegView(simplecustviewer_t):
    def __init__(self, owner):
        super(QLEmuRegView, self).__init__()
        self.hooks = None

    def Create(self):
        title = "QL Reg View"
        if not simplecustviewer_t.Create(self, title):
            return False

        self.menu_update = 1

        class Hooks(UI_Hooks):
            class PopupActionHandler(action_handler_t):
                def __init__(self, owner, menu_id):
                    action_handler_t.__init__(self)
                    self.owner = owner
                    self.menu_id = menu_id

                def activate(self, ctx):
                    self.owner.OnPopupMenu(self.menu_id)

                def update(self, ctx):
                    return AST_ENABLE_ALWAYS

            def __init__(self, form):
                UI_Hooks.__init__(self)
                self.form = form

            def finish_populating_widget_popup(self, widget, popup):
                if self.form.title == get_widget_title(widget):
                    attach_dynamic_action_to_popup(widget, popup, action_desc_t(None, "Change Reg", self.PopupActionHandler(self.form, self.form.menu_update),  None, None, -1))     
        
        if self.hooks is None:
            self.hooks = Hooks(self)
            self.hooks.hook()

        return True

    def SetReg(self, addr, ql:Qiling):
        arch = ql.arch
        if arch == "":
            return
        
        #clear
        self.ClearLines()

        view_title = COLSTR("Reg value at { ", SCOLOR_AUTOCMT)
        view_title += COLSTR("0x%X: " % addr, SCOLOR_DREF)
        # TODO: Add disass should be better
        view_title += COLSTR(" }", SCOLOR_AUTOCMT)
        self.AddLine(view_title)
        self.AddLine("")

        reglist = QLEmuMisc.get_reg_map(ql, arch)
        lines = len(reglist)
        line = ""
        for reg in reglist:
            cols = 3
            while cols:
                line += COLSTR(" %4s: " % str(reg), SCOLOR_REG)
                regvalue = ql.reg.read(reg)
                if arch in [QL_ARCH.X8664, QL_ARCH.ARM64]:
                    value_format = "0x%.16X"
                else:
                    value_format = "0x%.8X"
                line += COLSTR(str(value_format % regvalue), SCOLOR_NUMBER)
                # TODO: ljust will looks better
                cols -= 1
            self.AddLine(line)
            line = ''
        self.AddLine(line)
        self.Refresh()


    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_update:
            self.owner.qlchangreg()

    def OnClose(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None


class QLEmuMisc:
    MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])
    class menu_action_handler(action_handler_t):
        def __init__(self, handler, action):
            action_handler_t.__init__(self)
            self.action_handler = handler
            self.action_type = action

        def activate(self, ctx):
            if ctx.form_type == BWN_DISASM:
                self.action_handler.handle_menu_action(self.action_type)
            return 1

        # This action is always available.
        def update(self, ctx):
            return AST_ENABLE_ALWAYS

    @staticmethod
    def get_reg_map(ql:Qiling, arch):
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

class QLEmuQiling:
    def __init__(self):
        self.path = get_input_file_path()
        self.rootfs = "C:\\Users\\abeok\\Desktop\\Qiling\\qiling\\examples\\rootfs\\arm_linux"  # FIXME
        self.ql = None

    def start(self):
        print('start ql')
        self.ql = Qiling(filename=[self.path], rootfs=self.rootfs)

    def run(self, begin=None, end=None):
        self.ql.run(begin, end)

    def save(self):
        self.ql.save(reg=True, mem=True, cpu_context=True, snapshot='./qlEmu_save.bin')
    
    def load(self):
        self.ql.restore(snapshot='./qlEmu_save.bin')

    def get_ql(self):
        return self.ql

    def remove_ql(self):
        if self.ql is not None:
            del self.ql
            self.ql = None


class QLEmuPlugin(plugin_t, UI_Hooks):
    ### ida plugin data
    popup_menu_hook = None

    flags = PLUGIN_KEEP # PLUGIN_HIDE
    comment = ""

    help = "Qiling emulator"
    wanted_name = "qlEmu"
    wanted_hotkey = ""

    ### view data
    qlemuregview = None

    def __init__(self):
        super(QLEmuPlugin, self).__init__()
        self.plugin_name = "qlEmu"
        self.qlemu = None
        self.ql = None
        # self.init()

    ### Main Framework

    def init(self):
        # init data
        print('init qlEmu plugin')
        self.register_menu_actions()
        self.hook_ui_actions()
        return PLUGIN_KEEP

    def run(self, arg):
        print('run with arg: '+ arg)

    def run(self, arg = 0):
        print('run')
        self.qlemu = QLEmuQiling()
        self.ql = None
        self.register_menu_actions()
        self.attach_main_menu_actions()

    def term(self):
        self.qlemu.remove_ql()
        self.unhook_ui_actions()
        self.detach_main_menu_actions()
        self.unregister_menu_actions()
        print('term')

    ### Actions

    def qlstart(self):
        self.qlemu.start()
        self.ql = self.qlemu.get_ql()

    def qlrun(self):
        self.qlemu.run()

    def qlsave(self):
        self.qlemu.save()
    
    def qlload(self):
        self.qlemu.load()

    def qlchangreg(self):
        # TODO
        pass

    def qlshowregview(self):
        if self.qlemuregview is None:
            self.regview = QLEmuRegView(self)
            self.regview.Create()
            self.regview.SetReg(self.ql.reg.arch_pc, self.ql)
            self.regview.Show()
            self.regview.Refresh()

    def unload_plugin(self):
        if self.ql is not None:
            self.ql = None
            self.qlemu.remove_ql()
        self.detach_main_menu_actions()
        self.unregister_menu_actions()
        print('unload success')    

    ### Menu
    menuitems = []

    def register_new_action(self, act_name, act_text, act_handler, shortcut, tooltip, icon):
        new_action = action_desc_t(
            act_name,       # The action name. This acts like an ID and must be unique
            act_text,       # The action text.
            act_handler,    # The action handler.
            shortcut,       # Optional: the action shortcut
            tooltip,        # Optional: the action tooltip (available in menus/toolbar)
            icon)           # Optional: the action icon (shows when in menus/toolbars)
        register_action(new_action)

    def handle_menu_action(self, action):
        [x.handler() for x in self.menuitems if x.action == action]

    def register_menu_actions(self):
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":start",             self.qlstart,                 "Start Qiling",               "Start Qiling",              None,                   True   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":run",               self.qlrun,                   "Run Qiling",                 "Run Qiling",                None,                   True   ))
        
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":reg view",          self.qlshowregview,           "Reg View",                   "Reg View",                  None,                   True   ))     
        
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":save",              self.qlsave,                  "Save Status",                "Save Status",               None,                   True   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":load",              self.qlload,                  "Load Status",                "Load Status",               None,                   True   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":unload",            self.unload_plugin,           "Unload Plugin",              "Unload Plugin",             None,                   False   ))

        for item in self.menuitems:
            self.register_new_action(item.action, item.title, QLEmuMisc.menu_action_handler(self, item.action), item.shortcut, item.tooltip,  -1)

    def unregister_menu_actions(self):
        for item in self.menuitems:
            unregister_action(item.action)

    def attach_main_menu_actions(self):
        for item in self.menuitems:
            attach_action_to_menu("Edit/Plugins/" + self.plugin_name + "/" + item.title, item.action, SETMENU_APP)

    def detach_main_menu_actions(self):
        for item in self.menuitems:
            detach_action_from_menu("Edit/Plugins/" + self.plugin_name + "/" + item.title, item.action)

    ### POPUP MENU

    def hook_ui_actions(self):
        self.popup_menu_hook = self
        self.popup_menu_hook.hook()
        print('hook')

    def unhook_ui_actions(self):
        if self.popup_menu_hook != None:
            self.popup_menu_hook.unhook()

    # IDA 7.x
    def finish_populating_widget_popup(self, widget, popup_handle):
        if get_widget_type(widget) == BWN_DISASM:
            for item in self.menuitems:
                if item.popup:
                    attach_action_to_popup(widget, popup_handle, item.action, self.plugin_name + "/")

    ### close view
    def close_reg_view(self):
        self.qlemuregview = None
    
    def update_views(self, addr, ql):
        if self.qlemuregview is not None:
            self.qlemuregview.SetReg(addr, ql)

        


def PLUGIN_ENTRY():
    return QLEmuPlugin()

if UseAsScript:
    if __name__ == "__main__":
        qlEmu = QLEmuPlugin()
        qlEmu.init()
        qlEmu.run()

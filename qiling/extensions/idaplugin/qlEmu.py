import collections

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
    # Qiling
    from qiling import *
else:
    import sys
    sys.path.append("./idapython3")
    from idapython3 import *

    from qiling import *

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

class QLEmuQiling:
    path = get_input_file_path()
    rootfs = None  # FIXME
    ql = None

    def init(self):
        self.path = path
        self.rootfs = rootfs
        self.ql = ql

    def start(self):
        self.ql = Qiling(path=[self.path], rootfs=self.rootfs)

    def run(self, begin=None, end=None):
        self.ql.run(begin, end)

    def save(self):
        self.ql.save(reg=True, mem=True, cpu_context=True, snapshot='./qlEmu_save.bin')
    
    def load(self):
        self.ql.restore(snapshot='./qlEmu_save.bin')

    def get_ql(self):
        return self.ql

    def remove_ql(self):
        del self.ql


class QLEmuPlugin(plugin_t, UI_Hooks):
    ### ida plugin data
    popup_menu_hook = None

    flags = PLUGIN_KEEP # PLUGIN_HIDE
    comment = ""

    help = "Qiling emulator"
    wanted_name = "qlEmu"
    wanted_hotkey = ""

    def __init__(self):
        super(QLEmuPlugin, self).__init__()
        self.plugin_name = "qlEmu"
        self.qlemu = None

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
        self.register_menu_actions()
        self.attach_main_menu_actions()
        self.qlemu = QLEmuQiling()

    def term(self):
        self.qlemu.remove_ql()
        self.unhook_ui_actions()
        self.detach_main_menu_actions()
        self.unregister_menu_actions()
        print('term')

    ### Actions

    def qlstart(self):
        self.qlemu.start()

    def qlrun(self):
        self.qlemu.run()

    def qlsave(self):
        self.qlemu.save()
    
    def qlload(self):
        self.qlemu.load()

    def unload_plugin(self):
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
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":start",             self.qlstart,                 "Start Qiling",               "Start Qiling",              None,                   False   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":run",               self.qlrun,                   "Run Qiling",                 "Run Qiling",                None,                   False   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":save",              self.qlsave,                  "Save Status",                "Save Status",               None,                   False   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":load",              self.qlload,                  "Load Status",                "Load Status",               None,                   False   ))
        self.menuitems.append(QLEmuMisc.MenuItem(self.plugin_name + ":unload",            self.unload_plugin,         "Unload Plugin",              "Unload Plugin",             None,                   False   ))

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

    # --- POPUP MENU

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
                    attach_action_to_popup(widget, popup_handle, item.action, self.plugin_name + "/")


def PLUGIN_ENTRY():
    return QLEmuPlugin()

if UseAsScript:
    if __name__ == "__main__":
        qlEmu = QLEmuPlugin()
        qlEmu.init()
        qlEmu.run()

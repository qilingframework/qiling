# Cross Platform and Multi Architecture Advanced Binary Emulation Framework Plugin For IDA
# Built on top of Unicorn emulator (www.unicorn-engine.org)
# Learn how to use? Please visit https://docs.qiling.io/en/latest/ida/

# Plugin Author: kabeor <kabeor@qiling.io>

UseAsScript = True
RELEASE = True

import sys
import collections
import time
import re

# Qiling
from qiling import *
from qiling.const import *

from qiling.extensions.idaplugin.ida import IDA
from qiling.extensions.idaplugin.dialogs import *
from qiling.extensions.idaplugin.memview import *
from qiling.extensions.idaplugin.regview import *
from qiling.extensions.idaplugin.stackview import *
from qiling.extensions.idaplugin.utils import *
from enum import Enum

### Plugin

class QlEmuPlugin(plugin_t, UI_Hooks):
    ### Ida Plugin Data

    popup_menu_hook = None

    flags = PLUGIN_HIDE
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
        self.is_change_addr = -1
        self.userobj = None
        self.customscriptpath = None
        self.bb_mapping = {}

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
        print(f"Register actions.")
        self.ql_register_menu_actions()
        self.ql_attach_main_menu_actions()

    def ready_to_run(self):
        print(f"UI Ready, register our menu actions.")
        self.run()

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
                self.lastaddr = None
            finally:
                hide_wait_box()
                print("Qiling initialized done")
        if self.customscriptpath is not None:
            self.ql_load_user_script()
            self.userobj.custom_prepare(self.qlemu.ql)

    def ql_load_user_script(self):
        if self.qlinit :
            self.ql_get_user_script(is_reload=True, is_start=True)
        else:
            print('Please setup Qiling first')

    def ql_reload_user_script(self):
        if self.qlinit:
            self.ql_get_user_script(is_reload=True)
        else:
            print('Please setup Qiling first')

    def ql_continue(self):
        if self.qlinit:
            userhook = None
            pathhook = self.qlemu.ql.hook_code(self.ql_path_hook)
            if self.userobj is not None:
                userhook = self.userobj.custom_continue(self.qlemu.ql)
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
            if userhook and userhook is not None:
                for hook in userhook:
                    self.qlemu.ql.hook_del(hook)
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
                    self.qlemu.run(begin=self.qlemu.ql.reg.arch_pc, end=curr_addr+self.qlemu.baseaddr-get_imagebase())
                finally:
                    hide_wait_box()
            else:
                show_wait_box("Qiling is processing ...")
                try:
                    self.qlemu.run(end=curr_addr+self.qlemu.baseaddr-get_imagebase())
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
                userhook = self.userobj.custom_step(self.qlemu.ql, self.stepflag)
            self.qlemu.run(begin=self.qlemu.ql.reg.arch_pc, end=self.qlemu.exit_addr)
            if userhook and userhook is not None:
                for hook in userhook:
                    self.qlemu.ql.hook_del(hook)
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
                mem_addr = memdialog.mem_addr.value - self.qlemu.baseaddr + get_imagebase()
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
        content = content.decode("utf-8")
        if r == 0:
            try:
                version_stable = re.findall(r"\"([\d\.]+)\"", content)[0]
            except (TypeError, IndexError):
                warning("ERROR: Failed to find version string from response.")
                print("ERROR: Failed to find version string from response.")

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
    
    def _remove_from_bb_lists(self, bbid):
        if bbid in self.real_blocks:
            self.real_blocks.remove(bbid)
        elif bbid in self.fake_blocks:
            self.fake_blocks.remove(bbid)
        elif bbid in self.retn_blocks:
            self.retn_blocks.remove(bbid)

    def ql_mark_real(self):
        cur_addr = IDA.get_current_address()
        cur_block = IDA.get_block(cur_addr)
        self._remove_from_bb_lists(cur_block.id)
        self.real_blocks.append(cur_block.id)
        IDA.color_block(cur_block, Colors.Green.value)

    def ql_mark_fake(self):
        cur_addr = IDA.get_current_address()
        cur_block = IDA.get_block(cur_addr)
        self._remove_from_bb_lists(cur_block.id)
        self.fake_blocks.append(cur_block.id)
        IDA.color_block(cur_block, Colors.Gray.value)

    def ql_mark_retn(self):
        cur_addr = IDA.get_current_address()
        cur_block = IDA.get_block(cur_addr)
        self._remove_from_bb_lists(cur_block.id)
        self.retn_blocks.append(cur_block.id)
        IDA.color_block(cur_block, Colors.Pink.value)

    def _guide_hook(self, ql, addr, data):
        print(f"Executing: {hex(addr)}")
        start_bb_id = self.hook_data['startbb']
        cur_bb = IDA.get_block(addr)
        if "force" in self.hook_data and addr in self.hook_data['force']:
            if self.hook_data['force'][addr]:
                reg1 = IDA.print_operand(addr, 0)
                reg2 = IDA.print_operand(addr, 1)
                reg2_val = ql.reg.__getattribute__(reg2)
                ql.reg.__setattr__(reg1, reg2_val)
            else:
                pass
            ins_size = IDA.get_instruction_size(addr)
            ql.reg.arch_pc += ins_size
        # TODO: Maybe we can detect whether the program will access unmapped
        #       here so that we won't map the memory.
        next_ins = IDA.get_instruction(addr)
        if "call" in next_ins:
            ql.reg.arch_pc += IDA.get_instruction_size(addr)
            return
        if start_bb_id == cur_bb.id:
            return
        if cur_bb.id in self.real_blocks or cur_bb.id in self.retn_blocks:
            if cur_bb.id not in self.paths[start_bb_id]:
                self.paths[start_bb_id].append(cur_bb.id)
            ql.emu_stop()

    def _skip_unmapped_rw(self, ql, type, addr, size, value):
        map_addr = ql.mem.align(addr)
        map_size = ql.mem.align(size)
        if not ql.mem.is_mapped(map_addr, map_size):
            print(f"Invalid memory R/W, trying to map {hex(map_size)} at {hex(map_addr)}")
            ql.mem.map(map_addr, map_size)
            ql.mem.write(map_addr, b'\x00'*map_size)
        return True

    def _find_branch_in_real_block(self, bb):
        paddr = bb.start_ea
        while paddr < bb.end_ea:
            ins = IDA.get_instruction(paddr)
            sz = IDA.get_instruction_size(paddr)
            if ins.lower().startswith("cmov"):
                return paddr
            paddr += sz
        return None

    def _paths_str(self):
        r = ""
        for bbid, succs in self.paths.items():
            if len(succs) == 1:
                r += f"{self._block_str(bbid)} -> {self._block_str(succs[0])}\n"
            elif len(succs) == 2:
                r += f"{self._block_str(bbid)} --(force jump)--> {self._block_str(succs[0])}\n"
                r += f"|----(skip jump)----> {self._block_str(succs[1])}\n"
        return r

    def _search_path(self):
        self.paths = {bbid: [] for bbid in self.bb_mapping.keys()}
        reals = [self.first_block, *self.real_blocks]
        self.deflatqlemu = QlEmuQiling() 
        self.deflatqlemu.rootfs = self.qlemu.rootfs
        self.deflatqlemu.start()
        ql = self.deflatqlemu.ql
        self.hook_data = None
        ql.hook_code(self._guide_hook)
        ql.hook_mem_read_invalid(self._skip_unmapped_rw)
        ql.hook_mem_write_invalid(self._skip_unmapped_rw)
        ql.hook_mem_unmapped(self._skip_unmapped_rw)
        for bbid in reals:
            bb = self.bb_mapping[bbid]
            braddr = self._find_branch_in_real_block(bb)
            self.hook_data = {
                "startbb": bbid
            }
            if braddr is None:
                ql.run(begin=bb.start_ea)
            else:
                self.hook_data['force'] = {braddr: True}
                ql.run(begin=bb.start_ea)
                self.hook_data['force'] = {braddr: False}
                ql.run(begin=bb.start_ea)
        del self.deflatqlemu
        self.deflatqlemu = None
        print(self._paths_str())

    def _patch_codes(self):
        if len(self.paths[self.first_block]) != 1:
            print(f"Error: found wrong ways in first block: {self._block_str(self.bb_mapping[self.first_block])}, should be 1 path but get {len(self.paths[self.first_block])}, exit.")
            return
        print("NOP dispatcher block")
        dispatcher_bb = self.bb_mapping[self.dispatcher]
        IDA.fill_block(dispatcher_bb, b'\x00')
        first_jmp_addr = dispatcher_bb.start_ea
        instr_to_assemble = f"jmp {self.bb_mapping[self.paths[self.first_block][0]].start_ea:x}h"
        print(f"Assemble {instr_to_assemble} at {hex(first_jmp_addr)}")
        IDA.assemble(first_jmp_addr, 0, first_jmp_addr, True, instr_to_assemble)
        for bbid in self.real_blocks:
            bb = self.bb_mapping[bbid]
            braddr = self._find_branch_in_real_block(bb)
            if braddr is None:
                last_instr_address = IDA.get_prev_head(bb.end_ea)
                print(f"Patch NOP from {hex(last_instr_address)} to {hex(bb.end_ea)}")
                IDA.fill_bytes(last_instr_address, bb.end_ea, b'\x00')
                if len(self.paths[bbid]) != 1:
                    print(f"Warning: found wrong ways in block: {self._block_str(bb)}, should be 1 path but get {len(self.paths[bbid])}")
                    continue
                instr_to_assemble = f"jmp {self.bb_mapping[self.paths[bbid][0]].start_ea:x}h"
                print(f"Assemble {instr_to_assemble} at {hex(last_instr_address)}")
                IDA.assemble(last_instr_address, 0, last_instr_address, True, instr_to_assemble)
                IDA.perform_analysis(bb.start_ea, bb.end_ea)
            else:
                if len(self.paths[bbid]) != 2:
                    print(f"Warning: found wrong ways in block: {self._block_str(bb)}, should be 2 paths but get {len(self.paths[bbid])}")
                    continue
                cmov_instr = IDA.get_instruction(braddr).lower()
                print(f"Patch NOP from {hex(braddr)} to {hex(bb.end_ea)}")
                IDA.fill_bytes(braddr, bb.end_ea, b'\x00')
                jmp_instr = f"j{cmov_instr[4:]}"
                instr_to_assemble = f"{jmp_instr} {self.bb_mapping[self.paths[bbid][0]].start_ea:x}h"
                print(f"Assemble {instr_to_assemble} at {hex(braddr)}")
                IDA.assemble(braddr, 0, braddr, True, instr_to_assemble)
                IDA.perform_analysis(bb.start_ea, bb.end_ea)
                time.sleep(0.5)
                next_instr_address = IDA.get_instruction_size(braddr) + braddr
                instr_to_assemble = f"jmp {self.bb_mapping[self.paths[bbid][1]].start_ea:x}h"      
                print(f"Assemble {instr_to_assemble} at {hex(next_instr_address)}")
                IDA.assemble(next_instr_address, 0, next_instr_address, True, instr_to_assemble)
                IDA.perform_analysis(bb.start_ea, bb.end_ea)
        for bbid in self.fake_blocks:
            bb = self.bb_mapping[bbid]
            print(f"Patch NOP for block: {self._block_str(bb)}")
            IDA.fill_block(bb, b'\x00')
        print(f"Patch NOP for pre_dispatcher.")
        bb = self.bb_mapping[self.pre_dispatcher]
        IDA.fill_block(bb, b'\x00')
    
    def ql_deflat(self):
        if len(self.bb_mapping) == 0:
            self.ql_parse_blocks_for_deobf()
        self._search_path()
        self._patch_codes()
        IDA.perform_analysis(self.deflat_func.start_ea, self.deflat_func.end_ea)

    def _block_str(self, bb):
        if type(bb) is int:
            bb = self.bb_mapping[bb]
        return f"Block id: {bb.id}, start_address: {bb.start_ea:x}, end_address: {bb.end_ea:x}, type: {bb.type}"

    def ql_parse_blocks_for_deobf(self):
        cur_addr = IDA.get_current_address()
        flowchart = IDA.get_flowchart(cur_addr)
        self.deflat_func = IDA.get_function(cur_addr)
        self.bb_mapping = {bb.id:bb for bb in flowchart}
        if flowchart is None:
            return
        bb_count = {}
        for bb in flowchart:
            for succ in bb.succs():
                if succ.id not in bb_count:
                    bb_count[succ.id] = 0
                bb_count[succ.id] += 1
        max_ref_bb_id = None
        max_ref = 0
        for bb_id, ref in bb_count.items():
            if ref > max_ref:
                max_ref = ref
                max_ref_bb_id = bb_id
        self.pre_dispatcher = max_ref_bb_id
        try:
            self.dispatcher = list(self.bb_mapping[self.pre_dispatcher].succs())[0].id
            self.first_block = flowchart[0].id
        except IndexError:
            print("Fail to get dispatcher and first_block.")
            return
        self.real_blocks = []
        self.fake_blocks = []
        self.retn_blocks = []
        for bb in flowchart:
            if self.pre_dispatcher in [b.id for b in bb.succs()] and IDA.get_instructions_count(bb.start_ea, bb.end_ea) > 1:
                self.real_blocks.append(bb.id)
            elif IDA.block_is_terminating(bb):
                self.retn_blocks.append(bb.id)
            elif bb.id != self.first_block and bb.id != self.pre_dispatcher and bb.id != self.dispatcher:
                self.fake_blocks.append(bb.id)
        for bbid in self.real_blocks:
            IDA.color_block(self.bb_mapping[bbid], Colors.Green.value)
        for bbid in self.fake_blocks:
            IDA.color_block(self.bb_mapping[bbid], Colors.Gray.value)
        for bbid in self.retn_blocks:
            IDA.color_block(self.bb_mapping[bbid], Colors.Pink.value)
        IDA.color_block(self.bb_mapping[self.dispatcher], Colors.Blue.value)
        IDA.color_block(self.bb_mapping[self.pre_dispatcher], Colors.Blue.value)
        IDA.color_block(self.bb_mapping[self.first_block], Colors.Beige.value)
        print(f"First block: {self._block_str(self.first_block)}")
        print(f"Dispatcher: {self._block_str(self.dispatcher)}")
        print(f"Pre dispatcher: {self._block_str(self.pre_dispatcher)}")
        tp = '\n'.join(map(self._block_str, self.real_blocks))
        print(f"Real blocks:\n{tp}")
        tp = '\n'.join(map(self._block_str, self.fake_blocks))
        print(f"Fake blocks:\n{tp}")
        tp = '\n'.join(map(self._block_str, self.retn_blocks))
        print(f"Return blocks:\n{tp}")
        print(f"Auto analysis finished, please check whether the result is correct.")
        print(f"You may change the property of each block manually if necessary.")


    ### Hook

    def ql_step_hook(self, ql, addr, size):
        self.stepflag = not self.stepflag
        addr = addr - self.qlemu.baseaddr + get_imagebase()
        if self.stepflag:
            set_color(addr, CIC_ITEM, 0x00FFD700)
            self.ql_update_views(self.qlemu.ql.reg.arch_pc, ql)
            self.qlemu.status = ql.save()
            ql.os.stop()
            self.qlemu.ql.hook_del(self.stephook)
            jumpto(addr)

    def ql_path_hook(self, ql, addr, size):
        addr = addr - self.qlemu.baseaddr + get_imagebase()
        set_color(addr, CIC_ITEM, 0x007FFFAA)
        bp_count = get_bpt_qty()
        bp_list = []
        if bp_count > 0:
            for num in range(0, bp_count):
                bp_list.append(get_bpt_ea(num))

            if addr in bp_list and (addr != self.lastaddr or self.is_change_addr>1):
                self.qlemu.status = ql.save()
                ql.os.stop()
                self.lastaddr = addr
                self.is_change_addr = -1
                jumpto(addr)

            self.is_change_addr += 1
            

    def ql_untill_hook(self, ql, addr, size):
        addr = addr - self.qlemu.baseaddr + get_imagebase()
        set_color(addr, CIC_ITEM, 0x00B3CBFF)

    ### User Scripts

    def ql_get_user_script(self, is_reload=False, is_start=False):
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

        self.userobj = get_user_scripts_obj(self.customscriptpath, 'QILING_IDA', is_reload)
        if self.userobj is not None:
            if is_reload and not is_start:
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

        if customscript != '':
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
        self.menuitems.append(QlEmuMisc.MenuItem("-",                                     self.ql_menu_null,              "",                           None,                        None,                   True   ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":parseblocks",       self.ql_parse_blocks_for_deobf,           "Auto Analysis For Deflat",               "Auto Analysis For Deflat",              None,                   True  ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":markreal",       self.ql_mark_real,           "Mark as Real Block",               "Mark as Real Block",              None,                   True  ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":markfake",       self.ql_mark_fake,           "Mark as Fake Block",               "Mark as Fake Block",              None,                   True  ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":markretn",       self.ql_mark_retn,           "Mark as Return Block",               "Mark as Return Block",              None,                   True  ))
        self.menuitems.append(QlEmuMisc.MenuItem(self.plugin_name + ":deflat",       self.ql_deflat,           "Deflat",               "Deflat",              None,                   True  ))

        for item in self.menuitems:
            if item.action == "-":
                continue
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
            self.qlemuregview.SetReg(addr, ql)

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

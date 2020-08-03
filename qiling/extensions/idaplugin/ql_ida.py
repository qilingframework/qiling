from .ida import IDA
from qiling import Qiling
from qiling.const import arch_map, QL_ARCH, QL_OS
from unicorn import *
from copy import deepcopy

call_instructions = ["call", "bl", "blx", "blr", "blx", "blr", "blxeq", "bleq", "blreq", "j", "jr", "jalr", "jal"]

class QLIDA:
    def __init__(self, ql):
        self._ql = ql

    @property
    def ql(self):
        return self._ql

    def _skip_instruction(self, ql):
        pc = ql.reg.arch_pc
        ql.reg.arch_pc += IDA.get_instruction_size(pc)
        ql.reg.arch_sp += IDA.get_frame_sp_delta(pc + IDA.get_instruction_size(pc))


    def _override_registers(self, registers):
        for reg, val in registers.items():
            self.ql.reg.__setattr__(reg, val)

    def run(self, begin=1, end=0, registers={}, instruction_hook=None, call_hook=None, memaccess_hook=None, hook_data=None, timeout=0, count=0):
        self._override_registers(registers)
        if instruction_hook:
            self.ql.hook_code(instruction_hook, hook_data)
        if memaccess_hook:
            self.ql.ql_hook(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memaccess_hook, hook_data)
        self.ql.run(begin=begin, end=end, timeout=timeout, count=count)

    def run_from_cursor(self, *args, **kwargs):
        addr = IDA.get_current_address()
        self.run(begin=addr, *args, **kwargs)

    def run_selection(self, *args, **kwargs):
        _, begin, end = IDA.get_last_selection()
        self.run(begin=begin, end=end, *args, **kwargs)

    def _retrieve_argv(self, ql):
        # https://en.wikipedia.org/wiki/X86_calling_conventions
        if ql.archtype == QL_ARCH.X86:
            return [ql.arch.stack_read(4*i) for i in range(5)]
        elif ql.archtype == QL_ARCH.X8664:
            if ql.ostype in [QL_OS.LINUX, QL_OS.MACOS]:
                return [
                    ql.reg.rdi,
                    ql.reg.rsi,
                    ql.reg.rdx,
                    ql.reg.rcx,
                    ql.reg.r8,
                    ql.reg.r9
                ]
            elif ql.ostype == QL_OS.WINDOWS:
                return [
                    ql.reg.rcx,
                    ql.reg.rdx,
                    ql.reg.r8,
                    ql.reg.r9
                ]
        elif ql.archtype == QL_ARCH.ARM:
            return [
                ql.reg.r0,
                ql.reg.r1,
                ql.reg.r2,
                ql.reg.r3
            ]
        elif ql.archtype == QL_ARCH.ARM64:
            return [
                ql.reg.x0,
                ql.reg.x1,
                ql.reg.x2,
                ql.reg.x3,
                ql.reg.x4,
                ql.reg.x5,
                ql.reg.x6,
                ql.reg.x7
            ]
        elif ql.archtype == QL_ARCH.MIPS:
            return [
                ql.reg.a0,
                ql.reg.a1,
                ql.reg.a2,
                ql.reg.a3
            ]
        return None

    def _force_jump_cb(self, ql, addr, size, cbs):
        self._ida_dprint(f"Executing: {hex(addr)}")
        path = self.current_path
        path_idx = self.path_idx
        bbstart = path[path_idx].start_ea
        bbend = path[path_idx].end_ea
        targethitted  = cbs[0]
        callhitted = cbs[1]

        # Where is our pc?
        if addr == bbstart and self.entered is True:
            if path_idx < len(path) - 1:
                ql.reg.arch_pc = path[path_idx+1].start_ea
                self.path_idx += 1
                self.entered = False
                self._ida_dprint(f"Going to jump out of loop: {hex(addr)}.")
                return
            else:
                self._ida_dprint(f"Target missed in the last loop block: {hex(addr)}.")
                ql.emu_stop()
                return
        elif addr < bbstart or addr > bbend:
            self._ida_dprint(f"We lost our pc, let's force it to go to the next block")
            if path_idx >= len(path) - 1:
                self._ida_dprint(f"Target missed out of block: {hex(addr)}.")
                ql.emu_stop()
                return
            ql.reg.arch_pc = path[path_idx+1].start_ea
            self.path_idx +=1
            self.entered = False
            return
        
        # Okay we should in the middle of the block!
        # Test if we are the first time to enter this block.        
        if addr == bbstart:
            self.entered = True

        # We reach our target. Tell the user to handle it and stop emulation.
        # TODO: Remove visited targets every time.
        if addr in self.target_xrefs:
            self._ida_dprint(f"Target reached: {hex(addr)}")
            if targethitted:
                targethitted(self, addr, size, cbs)
            ql.emu_stop()
            return
        
        # Skip calls.
        if IDA.get_instruction(addr).lower() in call_instructions:
            self._ida_dprint(f"Call reached: {hex(addr)}")
            argv = self._retrieve_argv(ql)
            self._ida_dprint(f"argv: {' '.join(map(hex, argv))}")
            if callhitted:
                callhitted(self, addr, size, cbs)
            self._skip_instruction(ql)
            return


    def _search_paths(self, xref):
        def _dfs_impl(cur, path, depth=0):
            path.append(cur.id)
            if cur.id == target_bb.id:
                paths.append(deepcopy(path))
                return True
            if cur.id in end_bbs_ids:
                return False
            for bb in cur.succs():
                if bb.id in path:
                    continue
                _dfs_impl(bb, path, depth+1)
                path.pop()
        target_bb = IDA.get_block(xref)
        start_bb = IDA.get_starting_block(xref)
        end_bbs = IDA.get_terminating_blocks(xref)
        end_bbs_ids = [bb.id for bb in end_bbs]
        paths = []
        path = []
        _dfs_impl(start_bb, path)
        # deepcopy can't work with SwigPyObjects
        paths_bbs = []
        flowchart = IDA.get_flowchart(xref)
        for path in paths:
            path_bbs = []
            for bbid in path:
                for bb in flowchart:
                    if bb.id == bbid:
                        path_bbs.append(bb)
            paths_bbs.append(path_bbs)
        return paths_bbs

    def _ida_dprint(self, s):
        self.ql.nprint(f"[ida] {s}\n")

    def _debug_print_path(self, path):
        if len(path) == 0:
            s = "Empty path."
        else:
            s = f"Path: {hex(path[0].start_ea)}"
            for bb in path[1:]:
                s += f" => {hex(bb.start_ea)}"
        self._ida_dprint(s)

    def run_from_xrefs_functions(self, addr, targethitted=None, callhitted=None, *args, **kwargs): 
        xrefsto = IDA.get_xrefsto(addr)
        target_xrefs = [xref for xref in xrefsto if IDA.get_function(xref) is not None and IDA.get_instruction(xref).lower() in call_instructions]
        self.target_xrefs = target_xrefs
        for xref in target_xrefs:
            paths = self._search_paths(xref)
            for path in paths:
                self._debug_print_path(path)
                self._ida_dprint(f"Our targets: {' '.join(map(hex, self.target_xrefs))}")
                if len(path) == 0:
                    continue
                self.path_idx = 0
                self.entered = False
                self.current_path = path
                self.ql.hook_code(self._force_jump_cb, [targethitted, callhitted])
                self.run(begin=path[0].start_ea, *args, **kwargs)
                self.ql.clear_hooks()
                self.ql.emu_stop()

    def run_through_function(self, addr, targethitted=None, callhitted = None, *args, **kwargs):
        target_addrs = [ IDA.get_prev_head(bb.end_ea) for bb in IDA.get_terminating_blocks(addr)]
        self._ida_dprint(f"Function target ends: {' '.join(map(hex, target_addrs))}")
        for addr in target_addrs:
            self.target_xrefs = [addr]
            paths = self._search_paths(addr)
            for path in paths:
                self._debug_print_path(path)
                self._ida_dprint(f"Our target: {hex(addr)}")
                if len(path) == 0:
                    continue
                self.path_idx = 0
                self.entered = False
                self.current_path = path
                self.ql.hook_code(self._force_jump_cb, [targethitted, callhitted])
                self.run(begin=path[0].start_ea, *args, **kwargs)
                self.ql.clear_hooks()
                self.ql.emu_stop()

    @staticmethod
    def create_qida(fname=[IDA.get_input_file_path()], *args, **kwargs):
        return QLIDA(Qiling(fname, *args, **kwargs))
    
    @staticmethod
    def get_arch():
        return arch_map[IDA.get_ql_arch_string()]
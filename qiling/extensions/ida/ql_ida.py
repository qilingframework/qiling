from .ida import IDA
from qiling import Qiling
from qiling.const import arch_map
from unicorn import *
from copy import deepcopy

class QLIDA:
    def __init__(self, ql):
        self._ql = ql

    @property
    def ql(self):
        return self._ql

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

    def _force_jump_cb(self, ql, addr, size, path):
        self._ida_dprint(f"Executing: {hex(addr)}")

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
        self.ql.dprint(1, f"[ida] s\n")

    def _debug_print_path(self, path):
        if len(path) == 0:
            s = "Empty path."
        else:
            s = f"Path: {hex(path[0].start_ea)}"
            for bb in path[1:]:
                s += f" => {hex(bb.start_ea)}"
        self._ida_dprint(s)

    def run_from_xrefs_functions(self, addr, *args, **kwargs):
        call_instructions = ["call", "jmp", "bl", "blx", "b", "blr", "j", "jr", "jalr", "jal", "bgtz", "beq", "bne", "blez"]
        xrefsto = IDA.get_xrefsto(addr)
        target_xrefs = [xref for xref in xrefsto if IDA.get_function(xref) is not None and IDA.get_instruction(xref).lower() in call_instructions]
        for xref in target_xrefs:
            paths = self._search_paths(xref)
            for path in paths:
                self._debug_print_path(path)
                self.ql.hook_code(self._force_jump_cb, path)
                self.run(*args, **kwargs)



    @staticmethod
    def create_qida(fname=[IDA.get_input_file_path()], *args, **kwargs):
        return QLIDA(Qiling(fname, *args, **kwargs))
    
    @staticmethod
    def get_arch():
        return arch_map[IDA.get_ql_arch_string()]
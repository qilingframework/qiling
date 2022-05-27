#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping, Tuple

from capstone import CsInsn

from qiling import Qiling
from qiling.const import QL_ARCH

from .context import Context
from .misc import read_int

from .render import (
        ContextRenderX86,
        ContextRenderARM,
        ContextRenderCORTEX_M,
        ContextRenderMIPS
        )

from .branch_predictor import (
        BranchPredictorX86,
        BranchPredictorARM,
        BranchPredictorCORTEX_M,
        BranchPredictorMIPS,
        )

from .const import color, QDB_MSG

    

def qdb_print(msgtype: QDB_MSG, msg: str) -> None:
    """
    color printing
    """

    def print_error(msg):
        return f"{color.RED}[!] {msg}{color.END}"

    def print_info(msg):
        return f"{color.CYAN}[+] {msg}{color.END}"

    color_coated = {
            QDB_MSG.ERROR: print_error,
            QDB_MSG.INFO : print_info,
            }.get(msgtype)(msg)

    print(color_coated)


"""

    helper functions for setting proper branch predictor and context render depending on different arch

"""

def setup_branch_predictor(ql):
    """
    setup BranchPredictor correspondingly
    """

    return {
            QL_ARCH.X86: BranchPredictorX86,
            QL_ARCH.ARM: BranchPredictorARM,
            QL_ARCH.CORTEX_M: BranchPredictorCORTEX_M,
            QL_ARCH.MIPS: BranchPredictorMIPS,
            }.get(ql.arch.type)(ql)

def setup_context_render(ql, predictor):
    """
    setup context render correspondingly
    """

    return {
            QL_ARCH.X86: ContextRenderX86,
            QL_ARCH.ARM: ContextRenderARM,
            QL_ARCH.CORTEX_M: ContextRenderCORTEX_M,
            QL_ARCH.MIPS: ContextRenderMIPS,
            }.get(ql.arch.type)(ql, predictor)

def run_qdb_script(qdb, filename: str) -> None:
    with open(filename) as fd:
        for line in iter(fd.readline, ""):

            # skip commented and empty line 
            if line.startswith("#") or line == "\n":
                continue

            cmd, arg, _ = qdb.parseline(line)
            func = getattr(qdb, f"do_{cmd}")
            if arg:
                func(arg)
            else:
                func()


"""

    For supporting Qdb features like:
    1. record/replay debugging
    2. memory access in gdb-style

"""

class SnapshotManager:
    """
    for functioning differential snapshot
    """

    class State:
        """
        internal container for storing raw state from qiling
        """

        def __init__(self, saved_state):
            self.reg, self.ram = SnapshotManager.transform(saved_state)

    class DiffedState:
        """
        internal container for storing diffed state
        """

        def __init__(self, diffed_st):
            self.reg, self.ram = diffed_st

    @staticmethod
    def transform(st):
        """
        transform saved context into binary set
        """

        reg = st["reg"] if "reg" in st else st[0]

        if "mem" not in st:
            return (reg, st[1])

        ram = []
        for mem_seg in st["mem"]["ram"]:
            lbound, ubound, perms, label, raw_bytes = mem_seg
            rb_set = {(idx, val) for idx, val in enumerate(raw_bytes)}
            ram.append((lbound, ubound, perms, label, rb_set))

        return (reg, ram)

    def __init__(self, ql):
        self.ql = ql
        self.layers = []

    def _save(self) -> State:
        """
        acquire current State by wrapping saved context from ql.save()
        """

        return self.State(self.ql.save())

    def diff_reg(self, prev_reg, cur_reg):
        """
        diff two register values
        """

        diffed = filter(lambda t: t[0] != t[1], zip(prev_reg.items(), cur_reg.items()))
        return {prev[0]: prev[1] for prev, _ in diffed}

    def diff_ram(self, prev_ram, cur_ram):
        """
        diff two ram data if needed
        """

        if any((cur_ram is None, prev_ram is None, prev_ram == cur_ram)):
            return

        ram = []
        paired = zip(prev_ram, cur_ram)
        for each in paired:
            # lbound, ubound, perm, label, data
            *prev_others, prev_rb_set = each[0]
            *cur_others, cur_rb_set = each[1]

            if prev_others == cur_others and cur_rb_set != prev_rb_set:
                diff_set = prev_rb_set - cur_rb_set
            else:
                continue

            ram.append((*cur_others, diff_set))

        return ram

    def diff(self, before_st, after_st):
        """
        diff between previous and current state
        """

        # prev_st = self.layers.pop()
        diffed_reg = self.diff_reg(before_st.reg, after_st.reg)
        diffed_ram = self.diff_ram(before_st.ram, after_st.ram)
        # diffed_reg = self.diff_reg(prev_st.reg, cur_st.reg)
        # diffed_ram = self.diff_ram(prev_st.ram, cur_st.ram)
        return self.DiffedState((diffed_reg, diffed_ram))

    def snapshot(func):
        """
        decorator function for saving differential context on certian qdb command
        """

        def magic(self, *args, **kwargs):
            if self.rr:
                # save State before execution
                p_st = self.rr._save()

                # certian execution to be snapshot
                func(self, *args, **kwargs)

                # save State after execution
                q_st = self.rr._save()

                # merge two saved States into a DiffedState
                st = self.rr.diff(p_st, q_st)
                self.rr.layers.append(st)
            else:
                func(self, *args, **kwargs)

        return magic

    def restore(self):
        """
        helper function for restoring running state from an existing incremental snapshot
        """

        prev_st = self.layers.pop()
        cur_st = self._save()

        for reg_name, reg_value in prev_st.reg.items():
            cur_st.reg[reg_name] = reg_value

        to_be_restored = {"reg": cur_st.reg}

        if getattr(prev_st, "ram", None) and prev_st.ram != cur_st.ram:

            ram = []
            # lbound, ubound, perm, label, data
            for each in prev_st.ram:
                *prev_others, prev_rb_set = each
                for *cur_others, cur_rb_set in cur_st.ram:
                    if prev_others == cur_others:
                        cur_rb_dict = dict(cur_rb_set)
                        for idx, val in prev_rb_set:
                            cur_rb_dict[idx] = val

                        bs = bytes(dict(sorted(cur_rb_dict.items())).values())
                        ram.append((*cur_others, bs))

            to_be_restored.update({"mem": {"ram": ram, "mmio": {}}})

        self.ql.restore(to_be_restored)




if __name__ == "__main__":
    pass

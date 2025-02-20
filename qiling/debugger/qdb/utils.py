#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import TYPE_CHECKING, Callable, Dict, Mapping, Tuple, Type

from capstone import CsInsn

from qiling.const import QL_ARCH

from .render import (
    ContextRender,
    ContextRenderX86,
    ContextRenderX8664,
    ContextRenderARM,
    ContextRenderCORTEX_M,
    ContextRenderMIPS
)

from .branch_predictor import (
    BranchPredictor,
    BranchPredictorX86,
    BranchPredictorX8664,
    BranchPredictorARM,
    BranchPredictorCORTEX_M,
    BranchPredictorMIPS,
)

from .const import color, QDB_MSG


if TYPE_CHECKING:
    from qiling import Qiling
    from .qdb import QlQdb


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


def setup_address_marker():

    class Marker:
        """provide the ability to mark an address as a more easier rememberable alias
        """

        def __init__(self):
            self._mark_list = {}

        def get_symbol(self, sym):
            """
            get the mapped address to a symbol if it's in the mark_list
            """

            return self._mark_list.get(sym, None)

        @property
        def mark_list(self):
            """
            get a list about what we marked
            """

            return self._mark_list.items()

        def gen_sym_name(self):
            """
            generating symbol name automatically
            """

            sym_name, idx = "sym0", 0
            while sym_name in self._mark_list:
                idx += 1
                sym_name = f"sym{idx}"

            return sym_name

        def mark_only_loc(self, loc):
            """
            mark when location provided only
            """

            sym_name = self.gen_sym_name()
            self.mark(sym_name, loc)
            return sym_name

        def mark(self, sym: str, loc: int):
            """
            mark loc as sym
            """

            if sym not in self.mark_list:
                self._mark_list.update({sym: loc})
            else:
                return f"dumplicated symbol name: {sym} at address: 0x{loc:08x}"

    return Marker()


# helper functions for setting proper branch predictor and context render depending on different arch
def setup_branch_predictor(ql: Qiling) -> BranchPredictor:
    """Setup BranchPredictor according to arch.
    """

    preds: Dict[QL_ARCH, Type[BranchPredictor]] = {
        QL_ARCH.X86:      BranchPredictorX86,
        QL_ARCH.X8664:    BranchPredictorX8664,
        QL_ARCH.ARM:      BranchPredictorARM,
        QL_ARCH.CORTEX_M: BranchPredictorCORTEX_M,
        QL_ARCH.MIPS:     BranchPredictorMIPS
    }

    p = preds[ql.arch.type]

    return p(ql)

def setup_context_render(ql: Qiling, predictor: BranchPredictor) -> ContextRender:
    """Setup context render according to arch.
    """

    rends: Dict[QL_ARCH, Type[ContextRender]] = {
        QL_ARCH.X86:      ContextRenderX86,
        QL_ARCH.X8664:    ContextRenderX8664,
        QL_ARCH.ARM:      ContextRenderARM,
        QL_ARCH.CORTEX_M: ContextRenderCORTEX_M,
        QL_ARCH.MIPS:     ContextRenderMIPS
    }

    r = rends[ql.arch.type]

    return r(ql, predictor)

def run_qdb_script(qdb: QlQdb, filename: str) -> None:
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


class SnapshotManager:
    """for functioning differential snapshot

    Supports Qdb features like:
    1. record/replay debugging
    2. memory access in gdb-style
    """

    class State:
        """
        internal container for storing raw state from qiling
        """

        def __init__(self, saved_state):
            self.reg, self.ram, self.xreg = SnapshotManager.transform(saved_state)

    class DiffedState:
        """
        internal container for storing diffed state
        """

        def __init__(self, diffed_st):
            self.reg, self.ram, self.xreg = diffed_st

    @staticmethod
    def transform(st):
        """
        transform saved context into binary set
        """

        reg  = st.get("reg", {})
        mem  = st.get("mem", [])
        xreg = st.get("cpr") or st.get("msr") or {}

        ram = []
        for mem_seg in mem["ram"]:
            lbound, ubound, perms, label, raw_bytes = mem_seg
            rb_set = {(idx, val) for idx, val in enumerate(raw_bytes)}
            ram.append((lbound, ubound, perms, label, rb_set))

        return (reg, ram, xreg)

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
        diffed_xreg = self.diff_reg(before_st.xreg, after_st.xreg)
        # diffed_reg = self.diff_reg(prev_st.reg, cur_st.reg)
        # diffed_ram = self.diff_ram(prev_st.ram, cur_st.ram)
        return self.DiffedState((diffed_reg, diffed_ram, diffed_xreg))

    def snapshot(func):
        """
        decorator function for saving differential context on certian qdb command
        """

        def magic(self: QlQdb, *args, **kwargs):
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

        for reg_name, reg_value in prev_st.xreg.items():
            cur_st.xreg[reg_name] = reg_value

        to_be_restored = {
            "reg": cur_st.reg,

            # though we have arch-specific context to restore, we want to keep this arch-agnostic.
            # one way to work around that is to include 'xreg' both as msr (intel) and cpr (arm).
            # only the relevant one will be picked up while the other one will be discarded
            "msr": cur_st.xreg,
            "cpr": cur_st.xreg
        }

        # FIXME: not sure how this one even works. while curr_st is a fresh qiling snapshot,
        # prev_st is a DiffedState which does not hold a complete state but only a diff between
        # two points which seem to be unrelated here.
        #
        # this code only patches current memory content with the diff between points a and b while
        # we may be already be at point c.
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

            to_be_restored["mem"] = {
                "ram": ram,
                "mmio": {}
            }

        self.ql.restore(to_be_restored)

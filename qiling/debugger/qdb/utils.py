#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping
import math

from qiling.const import QL_ARCH

from .misc import try_read

from .frontend import (
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


"""

    helper functions for setting proper branch predictor and context render depending on different arch

"""

def setup_branch_predictor(ql: Qiling) -> BranchPredictor:
    """
    setup BranchPredictor correspondingly
    """

    return {
            QL_ARCH.X86: BranchPredictorX86,
            QL_ARCH.ARM: BranchPredictorARM,
            QL_ARCH.ARM_THUMB: BranchPredictorARM,
            QL_ARCH.CORTEX_M: BranchPredictorCORTEX_M,
            QL_ARCH.MIPS: BranchPredictorMIPS,
            }.get(ql.archtype)(ql)

def setup_context_render(ql: Qiling, predictor: BranchPredictor) -> ContextRender:
    """
    setup context render correspondingly
    """

    return {
            QL_ARCH.X86: ContextRenderX86,
            QL_ARCH.ARM: ContextRenderARM,
            QL_ARCH.ARM_THUMB: ContextRenderARM,
            QL_ARCH.CORTEX_M: ContextRenderCORTEX_M,
            QL_ARCH.MIPS: ContextRenderMIPS,
            }.get(ql.archtype)(ql, predictor)



"""

    For supporting Qdb features like:
    1. record/replay debugging
    2. memory access in gdb-style

"""

class Manager(object):
    """
    base class for Manager
    """
    def __init__(self, ql):
        self.ql = ql

class SnapshotManager(Manager):
    """
    for functioning differential snapshot
    """

    class State(object):
        """
        internal container for storing raw state from qiling
        """

        def __init__(self, saved_state):
            self.reg, self.ram = SnapshotManager.transform(saved_state)

    class DiffedState(object):
        """
        internal container for storing diffed state
        """

        def __init__(self, diffed_st):
            self.reg, self.ram = diffed_st

    @classmethod
    def transform(cls, st):
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
        super().__init__(ql)
        self.layers = []

    def _save(self) -> State():
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

    def diff(self, cur_st):
        """
        diff between previous and current state
        """

        prev_st = self.layers.pop()
        diffed_reg = self.diff_reg(prev_st.reg, cur_st.reg)
        diffed_ram = self.diff_ram(prev_st.ram, cur_st.ram)
        return self.DiffedState((diffed_reg, diffed_ram))

    def save(self):
        """
        helper function for saving differential context
        """

        st = self._save()

        if len(self.layers) > 0 and isinstance(self.layers[-1], self.State):
            # merge two context_save to be a diffed state
            st = self.diff(st)

        self.layers.append(st)

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

class MemoryManager(Manager):
    """
    memory manager for handing memory access 
    """

    def __init__(self, ql):
        super().__init__(ql)

        self.DEFAULT_FMT = ('x', 4, 1)

        self.FORMAT_LETTER = {
                "o", # octal
                "x", # hex
                "d", # decimal
                "u", # unsigned decimal
                "t", # binary
                "f", # float
                "a", # address
                "i", # instruction
                "c", # char
                "s", # string
                "z", # hex, zero padded on the left
                }

        self.SIZE_LETTER = {
            "b": 1, # 1-byte, byte
            "h": 2, # 2-byte, halfword
            "w": 4, # 4-byte, word
            "g": 8, # 8-byte, giant
            }

    def extract_count(self, t):
        return "".join([s for s in t if s.isdigit()])

    def get_fmt(self, text):

        f, s, c = self.DEFAULT_FMT
        if self.extract_count(text):
            c = int(self.extract_count(text))

        for char in text.strip(str(c)):
            if char in self.SIZE_LETTER.keys():
                s = self.SIZE_LETTER.get(char)

            elif char in self.FORMAT_LETTER:
                f = char

        return (f, s, c)

    def unpack(self, bs: bytes, sz: int) -> int:
        return {
                1: lambda x: x[0],
                2: self.ql.unpack16,
                4: self.ql.unpack32,
                8: self.ql.unpack64,
                }.get(sz)(bs)

    def parse(self, line: str):
        args = line.split()

        if line.startswith("/"):  # followed by format letter and size letter

            fmt, *rest = line.strip("/").split()

            rest = "".join(rest)

            fmt = self.get_fmt(fmt)

        elif len(args) == 1:  # only address
            rest = args[0]
            fmt = DEFAULT_FMT

        else:
            rest = args

        if self.ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            rest = rest.replace("fp", "r11")

        elif self.ql.archtype == QL_ARCH.MIPS:
            rest = rest.replace("fp", "s8")


        # for supporting addition of register with constant value
        elems = rest.split("+")
        elems = [elem.strip("$") for elem in elems]

        items = []

        for elem in elems:
            if elem in self.ql.reg.register_mapping.keys():
                if (value := getattr(self.ql.reg, elem, None)):
                    items.append(value)
            else:
                items.append(read_int(elem))

        addr = sum(items)

        ft, sz, ct = fmt

        if ft == "i":

            for offset in range(addr, addr+ct*4, 4):
                line = disasm(self.ql, offset)
                if line:
                    print(f"0x{line.address:x}: {line.mnemonic}\t{line.op_str}")

            print()

        else:
            lines = 1 if ct <= 4 else math.ceil(ct / 4)

            mem_read = []
            for offset in range(ct):
                # append data if read successfully, otherwise return error message
                if (data := try_read(self.ql, addr+(offset*sz), sz))[0] is not None:
                    mem_read.append(data[0])

                else:
                    return data[1]

            for line in range(lines):
                offset = line * sz * 4
                print(f"0x{addr+offset:x}:\t", end="")

                idx = line * self.ql.pointersize
                for each in mem_read[idx:idx+self.ql.pointersize]:
                    data = self.unpack(each, sz)
                    prefix = "0x" if ft in ("x", "a") else ""
                    pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                    ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")
                    print(f"{prefix}{data:{pad}{ft}}\t", end="")

                print()

        return True

    def read(self, address: int, size: int):
        self.ql.read(address, size)



if __name__ == "__main__":
    pass

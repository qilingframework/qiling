#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Mapping, Optional, Tuple, Type, TypeVar, Union

from qiling.const import QL_ARCH

from .render import (
    ContextRender,
    ContextRenderX86,
    ContextRenderX64,
    ContextRenderARM,
    ContextRenderCORTEX_M,
    ContextRenderMIPS
)

from .branch_predictor import (
    BranchPredictor,
    BranchPredictorX86,
    BranchPredictorX64,
    BranchPredictorARM,
    BranchPredictorCORTEX_M,
    BranchPredictorMIPS,
)

from .const import color, QDB_MSG


if TYPE_CHECKING:
    from qiling import Qiling
    from .qdb import QlQdb


_K = TypeVar('_K')
_V = TypeVar('_V')


def qdb_print(level: QDB_MSG, msg: str) -> None:
    """Log printing.
    """

    decorations = {
        QDB_MSG.ERROR: ('!', color.RED),
        QDB_MSG.INFO : ('+', color.CYAN),
    }

    tag, col = decorations[level]

    print(f'{col}[{tag}] {msg}{color.END}')


class Marker:
    """provide the ability to mark an address as a more easier rememberable alias
    """

    def __init__(self):
        self._mark_list: Dict[str, int] = {}

    def get_address(self, sym: str) -> Optional[int]:
        """
        get the mapped address to a symbol if it's in the mark_list
        """

        return self._mark_list.get(sym)

    @property
    def mark_list(self):
        """
        get a list about what we marked
        """

        return self._mark_list.items()

    def gen_sym_name(self) -> str:
        """
        generating symbol name automatically
        """

        syms = len(self._mark_list)

        # find the next available 'sym#'
        return next((f'sym{i}' for i in range(syms) if f'sym{i}' not in self._mark_list), f'sym{syms}')

    def mark(self, loc: int, sym: Optional[str] = None) -> str:
        """
        mark loc as sym
        """

        sym = sym or self.gen_sym_name()

        if sym in self._mark_list:
            return ''

        self._mark_list[sym] = loc

        return sym


# helper functions for setting proper branch predictor and context render depending on different arch
def setup_branch_predictor(ql: Qiling) -> BranchPredictor:
    """Setup BranchPredictor according to arch.
    """

    preds: Dict[QL_ARCH, Type[BranchPredictor]] = {
        QL_ARCH.X86:      BranchPredictorX86,
        QL_ARCH.X8664:    BranchPredictorX64,
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
        QL_ARCH.X8664:    ContextRenderX64,
        QL_ARCH.ARM:      ContextRenderARM,
        QL_ARCH.CORTEX_M: ContextRenderCORTEX_M,
        QL_ARCH.MIPS:     ContextRenderMIPS
    }

    r = rends[ql.arch.type]

    return r(ql, predictor)


class MemDiff(Enum):
    ADD = '+'
    REM = '-'
    MOD = '*'


RamKey = Tuple[int, int]
RamVal = Tuple[int, str, bytes]

RamDiffKey = Tuple[int, int]
RamDiffVal = Tuple[MemDiff, Tuple[int, str, Union[bytes, Tuple]]]


class DiffedState:
    """
    internal container for storing diffed state
    """

    def __init__(self, reg, xreg, ram, loader):
        self.reg: Dict[str, int] = reg
        self.xreg: Dict[str, int] = xreg
        self.ram: Dict[RamDiffKey, RamDiffVal] = ram
        self.loader: Dict[str, Any] = loader


class State:
    """
    internal container for storing raw state from qiling
    """

    def __init__(self, saved: Mapping[str, Mapping]):
        self.reg: Dict[str, int] = saved.get("reg") or {}
        self.xreg: Dict[str, int] = saved.get("cpr") or saved.get("msr") or {}

        mem = saved.get("mem") or {}
        ram = mem.get("ram") or []

        # saved ram lists might not match in order, we turn them into dicts to work around
        # that. in these dicts every memory content is mapped to its memory entry's properties
        self.ram: Dict[RamKey, RamVal] = {(lbound, ubound): (perms, label, data) for lbound, ubound, perms, label, data in ram}

        self.loader: Dict[str, Any] = saved.get('loader') or {}

    @staticmethod
    def __dict_diff(d0: Mapping[_K, _V], d1: Mapping[_K, _V]) -> Dict[_K, _V]:
        return {k: v for k, v in d0.items() if v != d1.get(k)}

    def _diff_reg(self, other: State) -> Dict[str, int]:
        return State.__dict_diff(self.reg, other.reg)

    def _diff_xreg(self, other: State) -> Dict[str, int]:
        return State.__dict_diff(self.xreg, other.xreg)

    def _diff_ram(self, other: State) -> Dict[RamDiffKey, RamDiffVal]:
        ram0 = self.ram
        ram1 = other.ram

        ram_diff: Dict[RamDiffKey, RamDiffVal] = {}

        removed  = [rng for rng in ram0 if rng not in ram1]
        added    = [rng for rng in ram1 if rng not in ram0]
        modified = [rng for rng in ram0 if rng in ram1 and ram0[rng] != ram1[rng]]

        # memory regions that got removed should be re-added
        for rng in removed:
            ram_diff[rng] = (MemDiff.ADD, ram0[rng])

        # memory regions that got added should be removed
        for rng in added:
            _, label, _ = ram1[rng]

            # though we discard data as it is not required anymore, label is still required
            # to determine the method of removing the region: brk, mmap, or ordinary map
            ram_diff[rng] = (MemDiff.REM, (-1, label, b''))

        # memory regions that fot modified should be reverted back
        for rng in modified:
            perms0, label0, data0 = ram0[rng]
            perms1, label1, data1 = ram1[rng]

            perms = -1 if perms0 == perms1 else perms0

            assert label0 == label1, 'memory region label changed unexpectedly'
            assert len(data0) == len(data1), 'memory contents differ in size'

            # scan both data chunks and keep the index and byte value of the unmatched ones.
            # if memory contents are identical, this will result in an empty tuple
            data_diff = tuple((i, b0) for i, (b0, b1) in enumerate(zip(data0, data1)) if b0 != b1)

            ram_diff[rng] = (MemDiff.MOD, (perms, label0, data_diff))

        # <DEBUG>
        # for rng, (opcode, diff) in sorted(ram_diff.items()):
        #     lbound, ubound = rng
        #     perms, label, data = diff
        #
        #     print(f'{opcode.name} {lbound:010x} - {ubound:010x} {perms:03b} {label:24s} ~{len(data)}')
        # </DEBUG>

        return ram_diff

    def diff(self, other: State) -> DiffedState:
        """Diff between previous and current state.
        """

        return DiffedState(
            self._diff_reg(other),
            self._diff_xreg(other),
            self._diff_ram(other),
            self.loader
        )


class SnapshotManager:
    """Differential snapshot object.
    """

    def __init__(self, ql: Qiling):
        self.ql = ql
        self.layers: List[DiffedState] = []

    def save(self) -> State:
        """
        acquire current State by wrapping saved context from ql.save()
        """

        return State(self.ql.save(reg=True, mem=True, loader=True))

    @staticmethod
    def snapshot(func: Callable) -> Callable:
        """
        decorator function for saving differential context on certian qdb command
        """

        def magic(self: QlQdb, *args, **kwargs):
            if self.rr:
                # save State before execution
                before = self.rr.save()

                # certian execution to be snapshot
                func(self, *args, **kwargs)

                # save State after execution
                after = self.rr.save()

                # merge two saved States into a DiffedState
                self.rr.layers.append(before.diff(after))
            else:
                func(self, *args, **kwargs)

        return magic

    def restore(self):
        """
        helper function for restoring running state from an existing incremental snapshot
        """

        prev_st = self.layers.pop()  # DiffedState
        curr_st = self.save()        # State, expected to be identical to 'after' State in snapshot method

        curr_st.reg.update(prev_st.reg)
        curr_st.xreg.update(prev_st.xreg)

        if prev_st.ram:
            diff_ram = prev_st.ram
            curr_ram = curr_st.ram

            # we must begin by removing unwanted memory regions, otherwise we would not be able to
            # add new ones in case they overlap. here we iterate over the diff dictionary but handle
            # only remove opcodes
            for rng, (opcode, props) in diff_ram.items():
                lbound, ubound = rng
                size = ubound - lbound

                if opcode is MemDiff.REM:
                    # NOTE: it doesn't seem like distinguishing between brk, mmap, mmap annonymous
                    # and regular maps is actually required
                    self.ql.mem.unmap(lbound, size)

            # doind a second pass, but this time handling add and modify opcodes
            for rng, (opcode, props) in diff_ram.items():
                lbound, ubound = rng
                perms, label, data = props
                size = ubound - lbound

                if opcode is MemDiff.ADD:
                    # TODO: distinguish between brk, mmap, mmap annonymous and regular maps

                    self.ql.mem.map(lbound, size, perms, label)
                    self.ql.mem.write(lbound, data)

                elif opcode is MemDiff.MOD:
                    if perms != -1:
                        self.ql.mem.protect(lbound, size, perms)

                    # is there a diff for this memory range?
                    if data:
                        # get current memory content
                        _, _, curr_data = curr_ram[rng]
                        curr_data = bytearray(curr_data)

                        # patch with existing diff
                        for i, b in data:
                            curr_data[i] = b

                        # write patched data
                        self.ql.mem.write(lbound, bytes(curr_data))

        self.ql.restore({
            'reg': curr_st.reg,

            # though we have arch-specific context to restore, we want to keep this arch-agnostic.
            # one way to work around that is to include 'xreg' both as msr (intel) and cpr (arm).
            # only the relevant one will be picked up while the other one will be discarded
            'msr': curr_st.xreg,
            'cpr': curr_st.xreg,

            'loader': prev_st.loader
        })

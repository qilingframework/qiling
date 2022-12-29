#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional

from qiling import Qiling

# this code is partially based on uDbg
# @see: https://github.com/iGio90/uDdbg

PROMPT = r'gdb>'


class QlGdbUtils:
    def __init__(self, ql: Qiling, entry_point: int, exit_point: int):
        self.ql = ql

        self.exit_point = exit_point
        self.swbp = set()
        self.last_bp = None

        def __entry_point_hook(ql: Qiling):
            ql.hook_del(ep_hret)
            ql.hook_code(self.dbg_hook)

            ql.log.info(f'{PROMPT} stopped at entry point: {ql.arch.regs.arch_pc:#x}')
            ql.stop()

        # set a one-time hook to be dispatched upon reaching program entry point.
        # that hook will be used to set up the breakpoint handling hook
        ep_hret = ql.hook_address(__entry_point_hook, entry_point)

    def dbg_hook(self, ql: Qiling, address: int, size: int):
        if getattr(ql.arch, 'is_thumb', False):
            address |= 1

        # resuming emulation after hitting a breakpoint will re-enter this hook.
        # avoid an endless hooking loop by detecting and skipping this case
        if address == self.last_bp:
            self.last_bp = None

        elif address in self.swbp:
            self.last_bp = address

            ql.log.info(f'{PROMPT} breakpoint hit, stopped at {address:#x}')
            ql.stop()

    def bp_insert(self, addr: int, size: int):
        targets = set(addr + i for i in range(size or 1))

        if targets.intersection(self.swbp):
            return False

        for bp in targets:
            self.swbp.add(bp)

        self.ql.log.info(f'{PROMPT} breakpoint added at {addr:#x}')

        return True

    def bp_remove(self, addr: int, size: int) -> bool:
        targets = set(addr + i for i in range(size or 1))

        if not targets.issubset(self.swbp):
            return False

        for bp in targets:
            self.swbp.remove(bp)

        self.ql.log.info(f'{PROMPT} breakpoint removed from {addr:#x}')

        return True

    def resume_emu(self, address: Optional[int] = None, steps: int = 0):
        if address is None:
            address = self.ql.arch.regs.arch_pc

        if getattr(self.ql.arch, 'is_thumb', False):
            address |= 0b1

        op = f'stepping {steps} instructions' if steps else 'resuming'
        self.ql.log.info(f'{PROMPT} {op} from {address:#x}')

        self.ql.emu_start(address, self.exit_point, count=steps)

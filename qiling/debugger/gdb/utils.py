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
    # how often (in guest instructions) the run hook polls the client socket for
    # an async interrupt. small enough to feel instant, large enough that the
    # extra non-blocking socket check does not dominate the per-instruction hook.
    INTR_POLL_INTERVAL = 200

    def __init__(self, ql: Qiling, entry_point: int, exit_point: int):
        self.ql = ql

        self.exit_point = exit_point
        self.swbp = set()
        self.last_bp = None
        self._need_flush_tb = False

        # async-interrupt support: `check_interrupt` is a callable installed by the
        # gdb stub that returns True when the client sent a break (ctrl-c / \x03)
        # while the target was running. `interrupted` records that the last resume
        # stopped for that reason (rather than a breakpoint or normal exit).
        self.check_interrupt = None
        self.interrupted = False
        self._poll_counter = 0

        def __entry_point_hook(ql: Qiling):
            ql.hook_del(ep_hret)
            ql.hook_code(self.dbg_hook)
            self._need_flush_tb = True

            ql.log.info(f'{PROMPT} stopped at entry point: {ql.arch.regs.arch_pc:#x}')
            ql.stop()

        # set a one-time hook to be dispatched upon reaching program entry point.
        # that hook will be used to set up the breakpoint handling hook
        ep_hret = ql.hook_address(__entry_point_hook, entry_point)

    def flush_tb(self):
        """Flush Unicorn translation blocks after GDB hook or breakpoint updates."""
        flush_tb = getattr(self.ql.uc, 'ctl_flush_tb', None)

        if flush_tb is not None:
            flush_tb()

    def dbg_hook(self, ql: Qiling, address: int, size: int):
        if getattr(ql.arch, 'is_thumb', False):
            address |= 1

        # poll for an async interrupt from the client (gdb sends a bare \x03 while
        # the target is running). throttled so the socket check stays off the hot
        # path. this is the only way to break into a free-running guest, since the
        # stub's packet loop is blocked inside emu_start until the target stops.
        if self.check_interrupt is not None:
            self._poll_counter += 1

            if self._poll_counter >= self.INTR_POLL_INTERVAL:
                self._poll_counter = 0

                if self.check_interrupt():
                    self.interrupted = True
                    self.last_bp = None

                    ql.log.info(f'{PROMPT} interrupted by client, stopped at {address:#x}')
                    ql.stop()
                    return

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

        self._need_flush_tb = True

        self.ql.log.info(f'{PROMPT} breakpoint added at {addr:#x}')

        return True

    def bp_remove(self, addr: int, size: int) -> bool:
        targets = set(addr + i for i in range(size or 1))

        if not targets.issubset(self.swbp):
            return False

        for bp in targets:
            self.swbp.remove(bp)

        self._need_flush_tb = True

        self.ql.log.info(f'{PROMPT} breakpoint removed from {addr:#x}')

        return True

    def resume_emu(self, address: Optional[int] = None, steps: int = 0):
        if address is None:
            address = self.ql.arch.regs.arch_pc

        if getattr(self.ql.arch, 'is_thumb', False):
            address |= 0b1

        if self._need_flush_tb:
            self.flush_tb()
            self._need_flush_tb = False

        op = f'stepping {steps} instructions' if steps else 'resuming'
        self.ql.log.info(f'{PROMPT} {op} from {address:#x}')

        # clear any pending interrupt state from a previous resume
        self.interrupted = False
        self._poll_counter = 0

        self.ql.emu_start(address, self.exit_point, count=steps)

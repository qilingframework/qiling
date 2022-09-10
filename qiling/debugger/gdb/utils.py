#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional

from qiling import Qiling
from qiling.const import QL_ARCH

# this code is partially based on uDbg
# @see: https://github.com/iGio90/uDdbg

PROMPT = r'gdb>'

class QlGdbUtils:
    def __init__(self, ql: Qiling, entry_point: int, exit_point: int):
        self.ql = ql

        self.exit_point = exit_point
        self.bp_list = []
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
        if ql.arch.type == QL_ARCH.ARM and ql.arch.is_thumb:
            address += 1

        # resuming emulation after hitting a breakpoint will re-enter this hook.
        # avoid an endless hooking loop by detecting and skipping this case
        if address == self.last_bp:
            self.last_bp = None

        elif address in self.bp_list:
            self.last_bp = address

            ql.log.info(f'{PROMPT} breakpoint hit, stopped at {address:#x}')
            ql.stop()

        # # TODO: not sure what this is about
        # if address + size == self.exit_point:
        #     ql.log.debug(f'{PROMPT} emulation entrypoint at {self.entry_point:#x}')
        #     ql.log.debug(f'{PROMPT} emulation exitpoint at {self.exit_point:#x}')


    def bp_insert(self, addr: int):
        if addr not in self.bp_list:
            self.bp_list.append(addr)
            self.ql.log.info(f'{PROMPT} breakpoint added at {addr:#x}')


    def bp_remove(self, addr: int):
        self.bp_list.remove(addr)
        self.ql.log.info(f'{PROMPT} breakpoint removed from {addr:#x}')


    def resume_emu(self, address: Optional[int] = None, steps: int = 0):
        if address is None:
            address = self.ql.arch.regs.arch_pc

        if self.ql.arch.type == QL_ARCH.ARM and self.ql.arch.is_thumb:
            address += 1

        op = f'stepping {steps} instructions' if steps else 'resuming'
        self.ql.log.info(f'{PROMPT} {op} from {address:#x}')

        self.ql.emu_start(address, self.exit_point, count=steps)

#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_ARCH

PROMPT = r'gdb>'

class QlGdbUtils:
    def __init__(self):
        self.ql: Qiling

        self.current_address = 0x0
        self.current_address_size = 0x0
        self.last_bp = 0x0
        self.entry_point = None
        self.exit_point = None
        self.soft_bp = False
        self.has_soft_bp = False
        self.bp_list = []
        # self.mapping = []
        self.breakpoint_count = 0x0
        self.skip_bp_count = 0x0


    def initialize(self, ql: Qiling, hook_address: int, exit_point: int, mappings=[]):
        self.ql = ql

        if ql.baremetal:
            self.current_address = self.entry_point
        else:
            self.current_address = self.entry_point = ql.os.entry_point

        self.exit_point = exit_point
        # self.mapping = mappings

        def __entry_point_hook(ql: Qiling):
            ql.hook_del(ep_hret)
            ql.hook_code(self.dbg_hook)
            ql.stop()

            ql.log.info(f'{PROMPT} Stop at entry point: {ql.arch.regs.arch_pc:#x}')

        ep_hret = ql.hook_address(__entry_point_hook, hook_address)


    def dbg_hook(self, ql: Qiling, address: int, size: int):
        """Modified this function for qiling.gdbserver by kabeor from https://github.com/iGio90/uDdbg
        """

        try:
            if ql.archtype == QL_ARCH.ARM:
                if ql.arch.is_thumb:
                    address += 1

            # self.mapping.append([(hex(address))])
            self.current_address = address
            hit_soft_bp = False

            if self.soft_bp == True:
                self.soft_bp = False
                hit_soft_bp = True

            # Breakpoints are always added without the LSB, even in Thumb, so they should be checked like this as well
            if ((address & ~1) in self.bp_list and (address & ~1) != self.last_bp) or self.has_soft_bp == True:
                if self.skip_bp_count > 0:
                    self.skip_bp_count -= 1
                else:
                    self.breakpoint_count += 1
                    ql.stop()
                    self.last_bp = address
                    ql.log.info(f'{PROMPT} Breakpoint found, stop at address: {address:#x}')

            elif address == self.last_bp:
                self.last_bp = 0x0

            self.has_soft_bp = hit_soft_bp

            if self.current_address + size == self.exit_point:
                ql.log.debug(f'{PROMPT} emulation entrypoint at {self.entry_point:#x}')
                ql.log.debug(f'{PROMPT} emulation exitpoint at {self.exit_point:#x}')

        except KeyboardInterrupt:
            ql.log.info(f'{PROMPT} Paused at {address:#x}, instruction size = {size:d}')
            ql.stop()

        except:
            raise


    def bp_insert(self, addr: int):
        if addr not in self.bp_list:
            self.bp_list.append(addr)
            self.ql.log.info(f'{PROMPT} Breakpoint added at: {addr:#x}')


    def bp_remove(self, addr: int, type = None, len = None):
        self.bp_list.remove(addr)
        self.ql.log.info(f'{PROMPT} Breakpoint removed at: {addr:#x}')


    def resume_emu(self, address: int = None, skip_bp: int = 0):
        """Modified this function for qiling.gdbserver by kabeor from https://github.com/iGio90/uDdbg
        """

        if address is not None:
            if self.ql.archtype == QL_ARCH.ARM:
                if self.ql.arch.is_thumb:
                    address += 1

            self.current_address = address

        self.skip_bp_count = skip_bp

        if self.exit_point is not None:
            self.ql.log.info(f'{PROMPT} Resume at: {self.current_address:#x}')
            self.ql.emu_start(self.current_address, self.exit_point)

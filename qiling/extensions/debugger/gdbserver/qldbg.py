#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn import *
from qiling.const import *

class Qldbg(object):
    def __init__(self):
        self.current_address = 0x0
        self.current_address_size = 0x0
        self.last_bp = 0x0
        self.ql = None
        self.entry_point = None
        self.exit_point = None
        self.soft_bp = False
        self.has_soft_bp = False
        self.bp_list = []
        self.mapping = []
        self.breakpoint_count = 0x0
        self.skip_bp_count = 0x0


    def initialize(self, ql, exit_point=None, mappings=None):
        self.ql = ql
        self.current_address = self.entry_point = self.ql.os.entry_point
        self.exit_point = exit_point
        self.mapping = mappings
        self.ql.hook_code(self.dbg_hook)


    def dbg_hook(self, ql, address, size):
        """
        Modified this function for qiling.gdbserver by kabeor from https://github.com/iGio90/uDdbg
        """
        try:
            if self.ql.archtype == QL_ARCH.ARM:
                mode = self.ql.arch.check_thumb()
                if mode == UC_MODE_THUMB:
                    address = address + 1

            self.mapping.append([(hex(address))])
            self.current_address = address
            hit_soft_bp = False

            if self.soft_bp == True:
                self.soft_bp = False
                hit_soft_bp = True

            if (address in self.bp_list and address != self.last_bp) or self.has_soft_bp == True:
                if self.skip_bp_count > 0:
                    self.skip_bp_count -= 1
                else:
                    self.breakpoint_count += 1
                    self.ql.os.stop()
                    self.last_bp = address
                    self.ql.nprint("gdb> Breakpoint found, stop at address: 0x%x" % address)
                          
            elif address == self.last_bp:
                self.last_bp = 0x0

            self.has_soft_bp = hit_soft_bp
            
            if self.current_address + size == self.exit_point:
                self.ql.dprint(D_INFO, "gdb> emulation entrypoint at 0x%x" % (self.entry_point))
                self.ql.dprint(D_INFO, "gdb> emulation exitpoint at 0x%x" % (self.exit_point))
        
        except KeyboardInterrupt as ex:
            self.ql.nprint("gdb> Paused at 0x%x, instruction size = %u" % (address, size))
            self.ql.os.stop()
        except:
            raise    


    def bp_insert(self, addr):
        if addr not in self.bp_list:
            self.bp_list.append(addr)
            self.ql.nprint('gdb> Breakpoint added at: 0x%x' % addr)


    def bp_remove(self, addr, type = None, len = None):
        self.bp_list.remove(addr)
        self.ql.nprint('gdb> Breakpoint removed at: 0x%x' % addr)


    def resume_emu(self, address=None, skip_bp=0):
        """
        Modified this function for qiling.gdbserver by kabeor from https://github.com/iGio90/uDdbg
        """

        if address is not None:
            if self.ql.archtype == QL_ARCH.ARM:
                mode = self.ql.arch.check_thumb()
                if mode == UC_MODE_THUMB:
                    address += 1
            self.current_address = address

        self.skip_bp_count = skip_bp
        if self.exit_point is not None:
            self.ql.nprint('gdb> Resume at: 0x%x' % self.current_address)
            self.ql.emu_start(self.current_address, self.exit_point)

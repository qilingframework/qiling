import types, os

from unicorn import *
from qiling.os.os import QlOs
from qiling.os.utils import PathUtils


class QlOsDos(QlOs):
    def __init__(self, ql):
        super(QlOsDos, self).__init__(ql)
        self.ql = ql
        self.hook_syscall()
        self.handle_next = 0
        self.dos_handles = {}

    def set_flag(self, fl):
        self.ql.reg.ef = self.ql.reg.ef | fl
    
    def clear_flag(self, fl):
        self.ql.reg.ef = self.ql.reg.ed & (~fl)
    
    def test_flags(self, fl):
        return self.ql.reg.ef & fl == fl

    def set_cf(self):
        self.set_flag(0x1)

    def clear_cf(self):
        self.clear_flag(0x1)

    def calculate_address(self, sg, reg):
        return sg*16 + reg

    def read_dos_string(self, addr):
        str_address = addr
        s = ""
        while True:
            ch = chr(self.ql.mem.read(str_address, 1)[0])
            if ch == '$':
                break
            s += ch
            str_address += 1
        return s

    def read_dos_string_from_ds_dx(self):
        return self.read_dos_string(self.calculate_address(self.ql.reg.ds, self.ql.reg.dx))

    def hook_syscall(self):
        def cb(ql, intno, user_data=None):
            ah = self.ql.reg.ah
            # http://spike.scu.edu.au/~barry/interrupts.html
            # http://www2.ift.ulaval.ca/~marchand/ift17583/dosints.pdf
            if intno == 0x21:
                if ah == 0x4C:
                    self.ql.uc.emu_stop()
                elif ah == 0x2 or ah == 0x6:
                    ch = chr(self.ql.reg.dl)
                    self.ql.reg.al = self.ql.reg.dl
                    ql.nprint(ch)
                elif ah == 0x9:
                    s = self.read_dos_string_from_ds_dx()
                    ql.nprint(s)
                elif ah == 0x3C:
                    # fileattr ignored
                    fname = self.read_dos_string_from_ds_dx()
                    f = open(PathUtils.convert_for_native_os(self.ql.rootfs, self.ql.cur_path, fname), "wb")
                    self.dos_handles[self.handle_next] = f
                    self.ql.reg.ax = self.handle_next
                    self.handle_next += 1
                    self.clear_cf()
                elif ah == 0x3d:
                    fname = self.read_dos_string_from_ds_dx()
                    f = open(PathUtils.convert_for_native_os(self.ql.rootfs, self.ql.cur_path, fname), "rb")
                    self.dos_handles[self.handle_next] = f
                    self.ql.reg.ax = self.handle_next
                    self.handle_next += 1
                    self.clear_cf()
                elif ah == 0x3e:
                    hd = self.ql.reg.bx
                    if hd not in self.dos_handles:
                        self.ql.reg.ax = 0x6
                        self.set_cf()
                    else:
                        f = self.dos_handles[hd]
                        f.close()
                        del self.dos_handles[hd]
                        self.clear_cf()
                elif ah == 0x3f:
                    hd = self.ql.reg.bx
                    if hd not in self.dos_handles:
                        self.ql.reg.ax = 0x6
                        self.set_cf()
                    else:
                        f = self.dos_handles[hd]
                        buffer = self.calculate_address(self.ql.reg.ds, self.ql.reg.dx)
                        sz = self.ql.reg.cx
                        rd = f.read(sz)
                        ql.mem.write(buffer, rd)
                        self.clear_cf()
                        self.ql.reg.ax = len(rd)
                elif ah == 0x40:
                    hd = self.ql.reg.bx
                    if hd not in self.dos_handles:
                        self.ql.reg.ax = 0x6
                        self.set_cf()
                    else:
                        f = self.dos_handles[hd]
                        buffer = self.calculate_address(self.ql.reg.ds, self.ql.reg.dx)
                        sz = self.ql.reg.cx
                        rd = self.ql.mem.read(buffer, sz)
                        f.write(bytes(rd))
                        self.clear_cf()
                        self.ql.reg.ax = len(rd)
                elif ah == 0x41:
                    fname = self.read_dos_string_from_ds_dx()
                    real_path = PathUtils.convert_for_native_os(self.ql.rootfs, self.ql.cur_path, fname)
                    try:
                        os.remove(real_path)
                        self.clear_cf()
                    except OSError:
                        self.ql.reg.ax = 0x5
                        self.set_cf()
                elif ah == 0x43:
                    self.ql.reg.cx = 0xFFFF
                    self.clear_cf()
                else:
                    raise NotImplementedError()
            else:
                raise NotImplementedError()
        self.ql.hook_intr(cb)

    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.elf_entry = self.ql.entry_point
        else:
            self.ql.entry_point = self.ql.loader.start_address
        if not self.ql.shellcoder:
            try:
                self.ql.emu_start(self.ql.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
            except UcError:
                self.emu_error()
                raise

            if self.ql.internal_exception != None:
                raise self.ql.internal_exception 
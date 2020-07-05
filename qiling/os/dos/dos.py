import types

from unicorn import *

from qiling.os.os import QlOs

class QlOsDos(QlOs):
    def __init__(self, ql):
        super(QlOsDos, self).__init__(ql)
        self.ql = ql
        self.hook_syscall()

    def hook_syscall(self):
        def cb(ql, intno, user_data=None):
            ah = self.ql.reg.ah
            if intno == 0x21:
                if ah == 0x4C:
                    self.ql.uc.emu_stop()
                elif ah == 0x9:
                    ds = self.ql.reg.ds
                    dx = self.ql.reg.dx
                    str_address = ds*16 + dx
                    s = ""
                    while True:
                        ch = chr(self.ql.mem.read(str_address, 1)[0])
                        if ch == '$':
                            break
                        s += ch
                        str_address += 1
                    print(s)
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
                self.ql.reg.write("ds", self.ql.loader.cs)
                self.ql.reg.write("es", self.ql.loader.cs)
                self.ql.reg.write("ss", self.ql.loader.cs)
                self.ql.reg.write("ip", self.ql.loader.ip)
                self.ql.emu_start(self.ql.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
            except UcError:
                self.emu_error()
                raise
        
            if self.ql.internal_exception != None:
                raise self.ql.internal_exception
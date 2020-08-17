from unicorn import *
from unicorn.x86_const import *

from struct import pack

from .arch import QlArch
from .x86_const import *
from qiling.const import *
from qiling.exception import *

class QlArchA8086(QlArch):
    def __init__(self, ql):
        super(QlArchA8086, self).__init__(ql)
        arch_8086_register_mappings = [
            reg_map_8, reg_map_16, reg_map_misc
        ]

        for reg_maper in arch_8086_register_mappings:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.create_reverse_mapping()

    def stack_push(self, value):
        self.ql.reg.sp -= 4
        self.ql.mem.write(self.ql.reg.sp , self.ql.pack32(value))
        return self.ql.reg.esp


    def stack_pop(self):
        data = self.ql.unpack32(self.ql.mem.read(self.ql.reg.sp, 4))
        self.ql.reg.sp += 4
        return data


    def stack_read(self, offset):
        return self.ql.unpack32(self.ql.mem.read(self.ql.reg.sp+offset, 4))


    def stack_write(self, offset, data):
        return self.ql.mem.write(self.ql.reg.sp + offset, self.ql.pack32(data))

    def get_init_uc(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_16)  
        return uc 
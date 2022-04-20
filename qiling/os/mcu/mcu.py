#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.os import QlOs
from qiling.arch.arm import QlArchARM


class QlOsMcu(QlOs):
    def __init__(self, ql):
        super(QlOsMcu, self).__init__(ql)

        self.runable = True
        self.grain_size = 1

    def stop(self):
        self.ql.emu_stop()
        self.runable = False

    def run(self):
        self.runable = True
        
        count = self.ql.count or 0
        end = self.ql.exit_point or -1

        while self.runable:
            current_address = self.ql.arch.regs.arch_pc
            if isinstance(self.ql.arch, QlArchARM):
                current_address |= int(self.ql.arch.is_thumb)

            if current_address == end:
                break
            
            inst_num = min(self.grain_size, count)
            self.ql.emu_start(current_address, 0, count=inst_num)
            self.ql.hw.step()

            count -= inst_num
            
            if count == 0:
                break

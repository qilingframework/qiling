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
        self.fast_mode = False

    def stop(self):
        if self.fast_mode:
            pass
        
        else:
            self.ql.emu_stop()
            self.runable = False

    def run(self):        
        count = self.ql.count or 0
        end = self.ql.exit_point or -1

        if self.fast_mode:
            pass
        
        else:
            self.runable = True
            while self.runable:
                current_address = self.ql.arch.regs.arch_pc
                if isinstance(self.ql.arch, QlArchARM):
                    current_address |= int(self.ql.arch.is_thumb)

                if current_address == end:
                    break
                
                self.ql.emu_start(current_address, 0, count=1)
                self.ql.hw.step()

                count -= 1
                
                if count == 0:
                    break

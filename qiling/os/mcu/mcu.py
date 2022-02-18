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

    def step(self):
        self.ql.emu_start(self.ql.arch.get_pc(), 0, count=1)
        self.ql.hw.step()

    def stop(self):
        self.ql.emu_stop()
        self.runable = False

    def run(self):
        self.runable = True
        
        count = self.ql.count
        end = self.ql.exit_point if self.ql.exit_point is not None else -1

        if isinstance(self.ql.arch, QlArchARM):
            end |= self.ql.arch.thumb
        
        while self.runable and \
                self.ql.arch.get_pc() != end: 

            self.step()
            count -= 1
            
            if count == 0:
                break

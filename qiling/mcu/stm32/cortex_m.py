from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS

from ..mcu import QlMcu
from .exceptions.manager import ExceptionManager


class STM32CortexMCore(QlMcu):
    def __init__(self, ql):
        super().__init__(ql, UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)

        ## Exception Model
        self.emgr = ExceptionManager(self)

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        self.mapinfo = {
            'sram'      : (0x20000000, 0x20020000),
            'system'    : (0x1FFF0000, 0x1FFF7800),            
            'flash'     : (0x08000000, 0x08080000),             
            'peripheral': (0x40000000, 0x40100000),
            'core_perip': (0xE0000000, 0xE0100000),
        }

    def setup(self):
        for begin, end in self.mapinfo.values():
            self.mem.map(begin, end - begin)

    def reset(self):
        if self.BOOT[0] == 0:
            self.boot_space = self.mapinfo['flash'][0]
        elif self.BOOT[1] == 0:
            self.boot_space = self.mapinfo['system'][0]
        elif self.BOOT[1] == 1:
            self.boot_space = self.mapinfo['sram'][0]

        self.reg.write('lr', 0xffffffff)
        self.reg.write('msp', self.mem.read_ptr(self.boot_space))
        self.reg.write('pc', self.mem.read_ptr(self.boot_space + 0x4))
        
    def step(self):
        self.emgr.interrupt()
        self.emu_start(self.pc | 1, 0, count=1)

    def run(self, count=-1):        
        while count != 0:
            self.step()
            count -= 1

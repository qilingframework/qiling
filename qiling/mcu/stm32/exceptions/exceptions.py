from qiling.mcu.mcu import QlMcu
from .const import ETYPE

class CoreException:
    def __init__(self, 
            mcu: QlMcu,
            number: int,
            IRQn: int,
            type: ETYPE,
            priority: int,
            offset: int):
        self.mcu = mcu

        self.number   = number
        self.IRQn     = IRQn
        self.type     = ETYPE.UNKNOWN
        self.priority = priority
        self.offset   = offset

    def prepare(self):
        address = self.mcu.boot_space + self.offset
        entry = self.mcu.mem.read_ptr(address)

        self.EXC_RETURN = 0xFFFFFFF9
        self.mcu.reg.write('pc', entry)
        self.mcu.reg.write('lr', self.EXC_RETURN)

    def save_context(self):
        self.context = self.mcu.context_save()

    def restore_context(self):
        self.mcu.context_restore(self.context)

    def handle(self):
        self.save_context()
        self.prepare()
        try:
            self.mcu.emu_start(self.pc | 1, self.EXC_RETURN)
        except:
            pass
        
        self.restore_context()

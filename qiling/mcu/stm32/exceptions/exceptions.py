from unicorn.unicorn import UcError
from qiling.arch.arch import QlArch
from .const import ETYPE

class CoreException:
    def __init__(self, 
            arch: QlArch,
            number: int,
            IRQn: int,
            etype: ETYPE,
            priority: int,
            offset: int):
        self.arch = arch

        self.number   = number
        self.IRQn     = IRQn
        self.etype    = etype
        self.priority = priority
        self.offset   = offset

    def prepare(self):
        address = self.arch.boot_space + self.offset
        entry = self.arch.mem.read_ptr(address)

        self.EXC_RETURN = 0xFFFFFFF9
        self.arch.ql.reg.write('pc', entry)
        self.arch.ql.reg.write('lr', self.EXC_RETURN)

    def save_context(self):
        self.context = self.arch.context_save()

    def restore_context(self):
        self.arch.context_restore(self.context)

    def handle(self):
        self.save_context()
        self.prepare()
        try:
            ## FIXME: Why unicorn try fetch last instruction
            self.arch.ql.uc.emu_start(self.arch.get_pc(), self.EXC_RETURN)            
        except UcError:
            pass
        
        
        self.restore_context()

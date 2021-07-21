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

        self.reg_context = ['ipsr', 'pc', 'lr', 'r12', 'r3', 'r2', 'r1', 'r0']

    def update_regs(self):
        address = self.arch.ql.loader.boot_space + self.offset
        entry = self.arch.mem.read_ptr(address)

        self.EXC_RETURN = 0xFFFFFFF9
        self.arch.ql.reg.write('pc', entry)
        self.arch.ql.reg.write('lr', self.EXC_RETURN)

    def save_regs(self):
        for reg in self.reg_context:
            self.arch.stack_push(self.arch.ql.reg.read(reg))

    def restore_regs(self):
        for reg in self.reg_context[::-1]:
            self.arch.ql.reg.write(reg, self.arch.stack_pop())

    def handle(self):
        self.save_regs()
        self.update_regs()
        try:
            ## FIXME: Why unicorn try fetch last instruction
            self.arch.ql.emu_start(self.arch.get_pc(), self.EXC_RETURN)            
        except UcError:
            pass
                
        self.restore_regs()

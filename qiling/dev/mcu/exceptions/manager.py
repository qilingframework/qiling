from unicorn.unicorn import UcError

class ExceptionManager:
    def __init__(self, ql):
        self.ql = ql
                
        self.interrupt_signal = [0] * 256
        self.reg_context = ['ipsr', 'pc', 'lr', 'r12', 'r3', 'r2', 'r1', 'r0']

    def send_interrupt(self, isr_number):
        self.interrupt_signal[isr_number] = 1

    def handle_interupt(self, offset):
        self.ql.log.debug('Enter Interrupt')
        address = self.ql.arch.boot_space + offset
        entry = self.ql.mem.read_ptr(address)

        self.EXC_RETURN = 0xFFFFFFF9
        self.ql.reg.write('pc', entry)
        self.ql.reg.write('lr', self.EXC_RETURN)

        try:
            self.ql.emu_start(self.ql.arch.get_pc(), self.EXC_RETURN)            
        except UcError:
            pass

        self.ql.log.debug('Exit Interrupt')

    def save_regs(self):
        for reg in self.reg_context:
            self.ql.arch.stack_push(self.ql.reg.read(reg))

    def restore_regs(self):
        for reg in self.reg_context[::-1]:
            self.ql.reg.write(reg, self.ql.arch.stack_pop())

    def interrupt(self):
        self.save_regs()
        for isr_number in range(256):
            if self.interrupt_signal[isr_number] == 1:
                self.handle_interupt(isr_number << 2) 
                self.interrupt_signal[isr_number] = 0

        self.restore_regs()

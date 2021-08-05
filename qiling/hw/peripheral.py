from qiling.hw.core.register import PeripheralRegister


class QlPeripheral:
    def __init__(self, ql, tag, **kwargs):
        self.ql = ql
        self.tag = tag
        self.registers = {}

    def step(self):
        pass

    def add_register(self, base_addr, offset, name, reset_value=0x0):
        register = PeripheralRegister(self.ql, base_addr, offset, name, reset_value)
        self.registers[name] = register
        return register

    def add_field(self, register:PeripheralRegister, name, offset, width, access_mode=None):
        return register.add_field(name, offset, width, access_mode)

    ### Read/Write Peripheral Memory
    def read(self, offset, size) -> int:
        self.ql.log.warning('[%s] Read [0x%08x:%d]' % (self.tag, offset, size))
        return 0

    def write(self, offset, size, value):
        self.ql.log.warning('[%s] Write [0x%08x:%d] = %08x' % (self.tag, offset, size, value))

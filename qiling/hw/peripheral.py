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
        if size in [1, 2, 4, 8]:
            real_addr = self.ql.hw.base_addr(self.tag) + offset
            data = self.ql.mem.read(real_addr, size)
            return int.from_bytes(data, byteorder='little', signed=False)
        
        return 0

    def write(self, offset, size, value):
        if size in [1, 2, 4, 8]:
            real_addr = self.ql.hw.base_addr(self.tag) + offset
            self.ql.mem.write(real_addr, (value).to_bytes(size, byteorder='little', signed=False))
        else:
            raise ValueError

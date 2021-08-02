from qiling.hw.core.register import PeripheralRegister


class QlPeripheral:
    def __init__(self, ql, tag):
        self.ql = ql
        self.tag = tag
        self.registers = []

    def step(self):
        pass

    def add_register(self, base_addr, offset, name):
        register = PeripheralRegister(self.ql, base_addr, offset, name)
        self.registers.append(register)
        return register

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

from qiling.hw.core.register import PeripheralRegister


class QlPeripheral:
    def __init__(self, ql, base_addr):
        self.ql = ql
        self.base_addr = base_addr
        self._tag = ''
        self.registers = []

    def step(self):
        pass

    def add_register(self, base_addr, offset, name):
        register = PeripheralRegister(self.ql, base_addr, offset, name)
        self.registers.append(register)
        return register

    ### Read/Write Peripheral Memory
    def read(self, offset, size) -> bytes:
        # if size in [1, 2, 4, 8]:
        #     real_addr = self.base_addr + offset
        #     data = self.ql.mem.read(real_addr, size)
        #     return bytes(data)
        
        return 0

    def write(self, offset, size, value):
        pass
        # if size in [1, 2, 4, 8]:
        #     real_addr = self.base_addr + offset
        #     self.ql.mem.write(real_addr, self.pack(size, value))
        # else:
        #     raise ValueError

    ### Utils
    def pack(self, size, data):
        return {
                1: self.ql.pack8,
                2: self.ql.pack16,
                4: self.ql.pack32,
                8: self.ql.pack64,
                }.get(size)(data)

    def packs(self, size, data):
        return {
                1: self.ql.pack8s,
                2: self.ql.pack16s,
                4: self.ql.pack32s,
                8: self.ql.pack64s,
                }.get(size)(data)

    def unpack(self, size, data):
        return {
                1: self.ql.unpack8,
                2: self.ql.unpack16,
                4: self.ql.unpack32,
                8: self.ql.unpack64,
                }.get(size)(data)

    def unpacks(self, size, data):
        return {
                1: self.ql.unpack8s,
                2: self.ql.unpack16s,
                4: self.ql.unpack32s,
                8: self.ql.unpack64s,
                }.get(size)(data)
from qiling.hw.core.register_field import *



class PeripheralRegister:
    def __init__(self, base_addr, offset, name) -> None:
        self.base_addr = base_addr
        self.offset = offset
        self.name = name

        self.field = []
    
    def add_field(self, name, offset, width, access_mode):
        new_field = PeripheralRegisterField(name, offset, width, access_mode)
        self.field.append(new_field)

    def add_fields(self):
        pass
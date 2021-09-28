from qiling.hw.core.register_field import *


class PeripheralRegister:
    def __init__(self, ql, base_addr, offset, name, reset_value=0) -> None:
        self.ql = ql
        self.base_addr = base_addr
        self.offset = offset
        self.name = name
        self.reset_value = reset_value

        self.fields = {}
    
    def add_field(self, name, offset, width, access_mode):
        new_field = PeripheralRegisterField(name, offset, width, access_mode)
        self.fields[name] = new_field
        return new_field

    def add_fields(self):
        pass

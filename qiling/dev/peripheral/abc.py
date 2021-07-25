from abc import ABC


class BytePeripheralABC(ABC):
    pass


class WordPeripheralABC(ABC):
    pass


class DoubleWordPeripheralABC(ABC):
    pass


class PeripheralRegisterABC(ABC):
    def __init__(self, max_length, reset_value) -> None:
        self.register_field = []
        self.tags = []

        self.max_length = max_length
        self.reset_value = reset_value

    def flag_field(self, offset: int, mode: enumerate):
        pass


### looks no need for stm32f4 now.
    # def value_field(self):
    #     pass

    # def enum_field(self):
    #     pass
###


    def read(self, addr: int, size: int) -> bytearray:
        return self.ql.uc.mem_read(addr, size)
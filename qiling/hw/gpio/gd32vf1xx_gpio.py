import ctypes

from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxGpio(QlPeripheral):
    class Type(ctypes.Structure):
        """ General-purpose I/Os 
        """

        _fields_ = [
            ("CTL0" , ctypes.c_uint32), # Address offset: 0x0, port control register 0
            ("CTL1" , ctypes.c_uint32), # Address offset: 0x04, port control register 1
            ("ISTAT", ctypes.c_uint32), # Address offset: 0x08, Port input status register
            ("OCTL" , ctypes.c_uint32), # Address offset: 0x0C, Port output control register
            ("BOP"  , ctypes.c_uint32), # Address offset: 0x10, Port bit operate register
            ("BC"   , ctypes.c_uint32), # Address offset: 0x14, Port bit clear register
            ("LOCK" , ctypes.c_uint32), # Address offset: 0x18, GPIO port configuration lock register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.gpio = self.struct(
            CTL0  =  0x44444444,
            CTL1  =  0x44444444,
            ISTAT =  0x00000000,
            OCTL  =  0x00000000,
            BOP   =  0x00000000,
            BC    =  0x00000000,
            LOCK  =  0x00000000,
        )


#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxRcu(QlPeripheral):
    class Type(ctypes.Structure):
        """ Reset and clock unit 
        """

        _fields_ = [
            ("CTL"    , ctypes.c_uint32), # Address offset: 0x0, Control register
            ("CFG0"   , ctypes.c_uint32), # Address offset: 0x04, Clock configuration register 0 (RCU_CFG0)
            ("INT"    , ctypes.c_uint32), # Address offset: 0x08, Clock interrupt register (RCU_INT)
            ("APB2RST", ctypes.c_uint32), # Address offset: 0x0C, APB2 reset register (RCU_APB2RST)
            ("APB1RST", ctypes.c_uint32), # Address offset: 0x10, APB1 reset register (RCU_APB1RST)
            ("AHBEN"  , ctypes.c_uint32), # Address offset: 0x14, AHB enable register
            ("APB2EN" , ctypes.c_uint32), # Address offset: 0x18, APB2 clock enable register (RCU_APB2EN)
            ("APB1EN" , ctypes.c_uint32), # Address offset: 0x1C, APB1 clock enable register (RCU_APB1EN)
            ("BDCTL"  , ctypes.c_uint32), # Address offset: 0x20, Backup domain control register (RCU_BDCTL)
            ("RSTSCK" , ctypes.c_uint32), # Address offset: 0x24, Reset source /clock register (RCU_RSTSCK)
            ("AHBRST" , ctypes.c_uint32), # Address offset: 0x28, AHB reset register
            ("CFG1"   , ctypes.c_uint32), # Address offset: 0x2C, Clock Configuration register 1
            ("DSV"    , ctypes.c_uint32), # Address offset: 0x34, Deep sleep mode Voltage register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.rcu = self.struct(
            CTL     =  0x00000083,
            CFG0    =  0x00000000,
            INT     =  0x00000000,
            APB2RST =  0x00000000,
            APB1RST =  0x00000000,
            AHBEN   =  0x00000014,
            APB2EN  =  0x00000000,
            APB1EN  =  0x00000000,
            BDCTL   =  0x00000018,
            RSTSCK  =  0x0c000000,
            AHBRST  =  0x00000000,
            CFG1    =  0x00000000,
            DSV     =  0x00000000,
        )

        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.rcu) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.rcu) + offset, data, size)

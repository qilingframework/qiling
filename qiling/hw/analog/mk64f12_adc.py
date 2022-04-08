#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.mk64f12_adc import SC1, SC3


class MK64F12Adc(QlPeripheral):
    class Type(ctypes.Structure):
        """ Analog-to-Digital Converter """  
        _fields_ = [
            ("SC1" , ctypes.c_uint32 * 2), # ADC Status and Control Registers 1
            ("CFG1", ctypes.c_uint32), # ADC Configuration Register 1
            ("CFG2", ctypes.c_uint32), # ADC Configuration Register 2
            ("R1"  , ctypes.c_uint32), # ADC Data Result Register 1
            ("R2"  , ctypes.c_uint32), # ADC Data Result Register 2
            ("CV1" , ctypes.c_uint32), # Compare Value Registers 1
            ("CV2" , ctypes.c_uint32), # Compare Value Registers 2
            ("SC2" , ctypes.c_uint32), # Status and Control Register 2
            ("SC3" , ctypes.c_uint32), # Status and Control Register 3
            ("OFS" , ctypes.c_uint32), # ADC Offset Correction Register
            ("PG"  , ctypes.c_uint32), # ADC Plus-Side Gain Register
            ("MG"  , ctypes.c_uint32), # ADC Minus-Side Gain Register
            ("CLPD", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("CLPS", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("CLP4", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("CLP3", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("CLP2", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("CLP1", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("CLP0", ctypes.c_uint32), # ADC Plus-Side General Calibration Value Register
            ("RESERVED0", ctypes.c_uint32),
            ("CLMD", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
            ("CLMS", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
            ("CLM4", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
            ("CLM3", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
            ("CLM2", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
            ("CLM1", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
            ("CLM0", ctypes.c_uint32), # ADC Minus-Side General Calibration Value Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.intn = intn
        self.instance = self.struct(
            R1 = 0x7ff,
            R2 = 0x7ff,
        )

    @QlPeripheral.monitor()
    def write(self, offset, size, value):
        if offset == self.struct.SC1.offset:
            return

        else:
            self.raw_write(offset, size, value)

        if offset == self.struct.SC3.offset:
            if value & SC3.CAL:
                self.instance.SC3 &= ~SC3.CAL
                self.instance.SC1[0] |= SC1.COCO
                self.instance.SC1[1] |= SC1.COCO
            
            if value & SC3.CALF:
                self.instance.SC3 &= ~SC3.CALF

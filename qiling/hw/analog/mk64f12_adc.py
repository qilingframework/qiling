#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Adc(QlPeripheral):
    class Type(ctypes.Structure):
        """ Analog-to-Digital Converter """  
        _fields_ = [
            ("SC1" , ctypes.c_uint32), # ADC Status and Control Registers 1
            ("CFG1", ctypes.c_uint32), # ADC Configuration Register 1
            ("CFG2", ctypes.c_uint32), # ADC Configuration Register 2
            ("R"   , ctypes.c_uint32), # ADC Data Result Register
            ("CV"  , ctypes.c_uint32), # Compare Value Registers
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

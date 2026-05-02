#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class PwmCh(ctypes.Structure):
    _fields_ = [
        ("CMR"     , ctypes.c_uint32), # (PwmCh_num Offset: 0x0) PWM Channel Mode Register
        ("CDTY"    , ctypes.c_uint32), # (PwmCh_num Offset: 0x4) PWM Channel Duty Cycle Register
        ("CDTYUPD" , ctypes.c_uint32), # (PwmCh_num Offset: 0x8) PWM Channel Duty Cycle Update Register
        ("CPRD"    , ctypes.c_uint32), # (PwmCh_num Offset: 0xC) PWM Channel Period Register
        ("CPRDUPD" , ctypes.c_uint32), # (PwmCh_num Offset: 0x10) PWM Channel Period Update Register
        ("CCNT"    , ctypes.c_uint32), # (PwmCh_num Offset: 0x14) PWM Channel Counter Register
        ("DT"      , ctypes.c_uint32), # (PwmCh_num Offset: 0x18) PWM Channel Dead Time Register
        ("DTUPD"   , ctypes.c_uint32), # (PwmCh_num Offset: 0x1C) PWM Channel Dead Time Update Register
    ]

class PwmCmp(ctypes.Structure):
    _fields_ = [
        ("CMPV"   , ctypes.c_uint32), # (PwmCmp Offset: 0x0) PWM Comparison 0 Value Register
        ("CMPVUPD", ctypes.c_uint32), # (PwmCmp Offset: 0x4) PWM Comparison 0 Value Update Register
        ("CMPM"   , ctypes.c_uint32), # (PwmCmp Offset: 0x8) PWM Comparison 0 Mode Register
        ("CMPUPD" , ctypes.c_uint32), # (PwmCmp Offset: 0xC) PWM Comparison 0 Mode Update Register
    ]

class SAM3xaPwm(QlPeripheral):
    class Type(ctypes.Structure):
        """ Pulse Width Modulation Controller """  
        _fields_ = [
            ("CLK"     , ctypes.c_uint32), # PWM Clock Register
            ("ENA"     , ctypes.c_uint32), # PWM Enable Register
            ("DIS"     , ctypes.c_uint32), # PWM Disable Register
            ("SR"      , ctypes.c_uint32), # PWM Status Register
            ("IER1"    , ctypes.c_uint32), # PWM Interrupt Enable Register 1
            ("IDR1"    , ctypes.c_uint32), # PWM Interrupt Disable Register 1
            ("IMR1"    , ctypes.c_uint32), # PWM Interrupt Mask Register 1
            ("ISR1"    , ctypes.c_uint32), # PWM Interrupt Status Register 1
            ("SCM"     , ctypes.c_uint32), # PWM Sync Channels Mode Register
            ("Reserved1", ctypes.c_uint32),
            ("SCUC"    , ctypes.c_uint32), # PWM Sync Channels Update Control Register
            ("SCUP"    , ctypes.c_uint32), # PWM Sync Channels Update Period Register
            ("SCUPUPD" , ctypes.c_uint32), # PWM Sync Channels Update Period Update Register
            ("IER2"    , ctypes.c_uint32), # PWM Interrupt Enable Register 2
            ("IDR2"    , ctypes.c_uint32), # PWM Interrupt Disable Register 2
            ("IMR2"    , ctypes.c_uint32), # PWM Interrupt Mask Register 2
            ("ISR2"    , ctypes.c_uint32), # PWM Interrupt Status Register 2
            ("OOV"     , ctypes.c_uint32), # PWM Output Override Value Register
            ("OS"      , ctypes.c_uint32), # PWM Output Selection Register
            ("OSS"     , ctypes.c_uint32), # PWM Output Selection Set Register
            ("OSC"     , ctypes.c_uint32), # PWM Output Selection Clear Register
            ("OSSUPD"  , ctypes.c_uint32), # PWM Output Selection Set Update Register
            ("OSCUPD"  , ctypes.c_uint32), # PWM Output Selection Clear Update Register
            ("FMR"     , ctypes.c_uint32), # PWM Fault Mode Register
            ("FSR"     , ctypes.c_uint32), # PWM Fault Status Register
            ("FCR"     , ctypes.c_uint32), # PWM Fault Clear Register
            ("FPV"     , ctypes.c_uint32), # PWM Fault Protection Value Register
            ("FPE1"    , ctypes.c_uint32), # PWM Fault Protection Enable Register 1
            ("FPE2"    , ctypes.c_uint32), # PWM Fault Protection Enable Register 2
            ("Reserved2",ctypes.c_uint32 * 2),                        
            ("ELMR"    , ctypes.c_uint32 * 2), # PWM Event Line 0 Mode Register
            ("Reserved3",ctypes.c_uint32 * 11),
            ("SMMR"    , ctypes.c_uint32), # PWM Stepper Motor Mode Register
            ("Reserved3",ctypes.c_uint32 * 12),
            ("WPCR"    , ctypes.c_uint32), # PWM Write Protect Control Register
            ("WPSR"    , ctypes.c_uint32), # PWM Write Protect Status Register
            ("Reserved5",ctypes.c_uint32 * 7),
            ("TPR"     , ctypes.c_uint32), # Transmit Pointer Register
            ("TCR"     , ctypes.c_uint32), # Transmit Counter Register
            ("Reserved6",ctypes.c_uint32 * 2),
            ("TNPR"    , ctypes.c_uint32), # Transmit Next Pointer Register
            ("TNCR"    , ctypes.c_uint32), # Transmit Next Counter Register
            ("PTCR"    , ctypes.c_uint32), # Transfer Control Register
            ("PTSR"    , ctypes.c_uint32), # Transfer Status Register
            ("Reserved7",ctypes.c_uint32 * 2),
            ("CMP"      ,PwmCmp * 8),
            ("Reserved8",ctypes.c_uint32 * 20),
            ("CHNUM"    ,PwmCh * 8),
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.intn = intn

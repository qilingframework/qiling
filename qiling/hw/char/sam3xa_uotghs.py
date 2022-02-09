#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes


from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.peripheral import QlPeripheral

from qiling.hw.const.sam3xa_uotghs import CTRL, SR


class UotghsDevdma(ctypes.Structure):
    _fields_ = [
        ("DEVDMANXTDSC", ctypes.c_uint32),
        ("DEVDMAADDRESS", ctypes.c_uint32),
        ("DEVDMACONTROL", ctypes.c_uint32),
        ("DEVDMASTATUS", ctypes.c_uint32),
    ]

class UotghsHstdma(ctypes.Structure):
    _fields_ = [
        ("HSTDMANXTDSC", ctypes.c_uint32),
        ("HSTDMAADDRESS", ctypes.c_uint32),
        ("HSTDMACONTROL", ctypes.c_uint32),
        ("HSTDMASTATUS", ctypes.c_uint32),
    ]

class SAM3xaUotghs(QlConnectivityPeripheral):
    """ USB On-The-Go Interface """
    class Type(ctypes.Structure):
        _fields_ = [
            ("DEVCTRL"   , ctypes.c_uint32),      # (Uotghs Offset: 0x0000) Device General Control Register
            ("DEVISR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0004) Device Global Interrupt Status Register
            ("DEVICR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0008) Device Global Interrupt Clear Register
            ("DEVIFR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x000C) Device Global Interrupt Set Register
            ("DEVIMR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0010) Device Global Interrupt Mask Register
            ("DEVIDR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0014) Device Global Interrupt Disable Register
            ("DEVIER"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0018) Device Global Interrupt Enable Register
            ("DEVEPT"    , ctypes.c_uint32),      # (Uotghs Offset: 0x001C) Device Endpoint Register
            ("DEVFNUM"   , ctypes.c_uint32),      # (Uotghs Offset: 0x0020) Device Frame Number Register
            ("Reserved1" , ctypes.c_uint32 * 55), # 
            ("DEVEPTCFG" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x100) Device Endpoint Configuration Register (n = 0)
            ("Reserved2" , ctypes.c_uint32 * 2),  # 
            ("DEVEPTISR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x130) Device Endpoint Status Register (n = 0)
            ("Reserved3" , ctypes.c_uint32 * 2),  # 
            ("DEVEPTICR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x160) Device Endpoint Clear Register (n = 0)
            ("Reserved4" , ctypes.c_uint32 * 2),  # 
            ("DEVEPTIFR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x190) Device Endpoint Set Register (n = 0)
            ("Reserved5" , ctypes.c_uint32 * 2),  # 
            ("DEVEPTIMR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x1C0) Device Endpoint Mask Register (n = 0)
            ("Reserved6" , ctypes.c_uint32 * 2),  # 
            ("DEVEPTIER" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x1F0) Device Endpoint Enable Register (n = 0)
            ("Reserved7" , ctypes.c_uint32 * 2),  # 
            ("DEVEPTIDR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x220) Device Endpoint Disable Register (n = 0)
            ("Reserved8" , ctypes.c_uint32 * 50), # 
            ("DEVDMA"    , UotghsDevdma * 7),     # (Uotghs Offset: 0x310) n = 1 .. 7
            ("Reserved9" , ctypes.c_uint32 * 32), # 
            ("HSTCTRL"   , ctypes.c_uint32),      # (Uotghs Offset: 0x0400) Host General Control Register
            ("HSTISR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0404) Host Global Interrupt Status Register
            ("HSTICR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0408) Host Global Interrupt Clear Register
            ("HSTIFR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x040C) Host Global Interrupt Set Register
            ("HSTIMR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0410) Host Global Interrupt Mask Register
            ("HSTIDR"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0414) Host Global Interrupt Disable Register
            ("HSTIER"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0418) Host Global Interrupt Enable Register
            ("HSTPIP"    , ctypes.c_uint32),      # (Uotghs Offset: 0x0041C) Host Pipe Register
            ("HSTFNUM"   , ctypes.c_uint32),      # (Uotghs Offset: 0x0420) Host Frame Number Register
            ("HSTADDR1"  , ctypes.c_uint32),      # (Uotghs Offset: 0x0424) Host Address 1 Register
            ("HSTADDR2"  , ctypes.c_uint32),      # (Uotghs Offset: 0x0428) Host Address 2 Register
            ("HSTADDR3"  , ctypes.c_uint32),      # (Uotghs Offset: 0x042C) Host Address 3 Register
            ("Reserved10", ctypes.c_uint32 * 52), # 
            ("HSTPIPCFG" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x500) Host Pipe Configuration Register (n = 0)
            ("Reserved11", ctypes.c_uint32 * 2),  # 
            ("HSTPIPISR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x530) Host Pipe Status Register (n = 0)
            ("Reserved12", ctypes.c_uint32 * 2),  # 
            ("HSTPIPICR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x560) Host Pipe Clear Register (n = 0)
            ("Reserved13", ctypes.c_uint32 * 2),  # 
            ("HSTPIPIFR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x590) Host Pipe Set Register (n = 0)
            ("Reserved14", ctypes.c_uint32 * 2),  # 
            ("HSTPIPIMR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x5C0) Host Pipe Mask Register (n = 0)
            ("Reserved15", ctypes.c_uint32 * 2),  # 
            ("HSTPIPIER" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x5F0) Host Pipe Enable Register (n = 0)
            ("Reserved16", ctypes.c_uint32 * 2),  # 
            ("HSTPIPIDR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x620) Host Pipe Disable Register (n = 0)
            ("Reserved17", ctypes.c_uint32 * 2),  # 
            ("HSTPIPINRQ", ctypes.c_uint32 * 10), # (Uotghs Offset: 0x650) Host Pipe IN Request Register (n = 0)
            ("Reserved18", ctypes.c_uint32 * 2),  # 
            ("HSTPIPERR" , ctypes.c_uint32 * 10), # (Uotghs Offset: 0x680) Host Pipe Error Register (n = 0)
            ("Reserved19", ctypes.c_uint32 * 26), # 
            ("HSTDMA"    , UotghsHstdma * 7),     # (Uotghs Offset: 0x710) n = 1 .. 7
            ("Reserved20", ctypes.c_uint32 * 32), # 
            ("CTRL"      , ctypes.c_uint32),      # (Uotghs Offset: 0x0800) General Control Register
            ("SR"        , ctypes.c_uint32),      # (Uotghs Offset: 0x0804) General Status Register
            ("SCR"       , ctypes.c_uint32),      # (Uotghs Offset: 0x0808) General Status Clear Register
            ("SFR"       , ctypes.c_uint32),      # (Uotghs Offset: 0x080C) General Status Set Register
            ("Reserved21", ctypes.c_uint32 * 7),  # 
            ("FSM"       , ctypes.c_uint32),      # (Uotghs Offset: 0x082C) General Finite State Machine Register
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.uotghs = self.struct()
        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.uotghs) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.CTRL.offset:
            if value & CTRL.OTGPADE == 0:
                self.uotghs.SR |= SR.CLKUSABLE

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.uotghs) + offset, data, size)

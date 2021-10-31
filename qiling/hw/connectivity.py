#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
import queue

from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral


class QlConnectivityPeripheral(QlPeripheral):
    class Type(ctypes.Structure):
        """ Define the reigister fields of peripheral.

            Example:
                fields_ = [
                    ('SR'  , ctypes.c_uint32),
                    ('DR'  , ctypes.c_uint32),
                    ('BRR' , ctypes.c_uint32),
                    ('CR1' , ctypes.c_uint32),
                    ('CR2' , ctypes.c_uint32),
                    ('CR3' , ctypes.c_uint32),
                    ('GTPR', ctypes.c_uint32),
                ]
        """        
        _fields_ = []

    def __init__(self, ql: Qiling, label: str):
        super().__init__(ql, label)
        
        self.rtube = queue.Queue()
        self.wtube = queue.Queue()

    def send(self, data: bytes):
        """ Send data into the peripheral.
            
            Example:
                ql.hw.usart1.send(b'hello')
        """

        for byte in bytearray(data):
            self.rtube.put(byte)

    def recv(self, numb:int = 4096) -> bytes:
        """ Receive data from peripheral

            Example:
                data = ql.hw.i2c1.send()
        """
        data = bytearray()
        while not self.wtube.empty() and numb != 0:
            data.append(self.wtube.get())
            numb -= 1

        return bytes(data)
    
    def can_recv(self):
        return not self.rtube.empty()

    def recv_from_user(self) -> bytes:
        """ Read single byte from user input
        """
        
        return self.rtube.get()

    def send_to_user(self, data: int):
        """ send single byte to user
        """
        
        self.wtube.put(data)

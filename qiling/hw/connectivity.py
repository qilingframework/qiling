#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
import queue

from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral


class PeripheralTube(queue.Queue):
    def __init__(self):
        super().__init__()

    def readable(self) -> bool:
        return not self.empty()

    def read(self, numb:int = 4096) -> bytes:
        data = bytearray()
        for _ in range(numb):
            if not self.readable():
                break
            data.append(self.get())

        return bytes(data)

    def write(self, data: bytes):
        for byte in bytearray(data):
            self.put(byte)


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

    def __init__(self, ql: Qiling, label: str, limit:int = 1):
        super().__init__(ql, label)
        
        self.itube = PeripheralTube()
        self.otube = PeripheralTube()

        self.limit = limit
        self.device_list = []

    def has_input(self):
        return self.itube.readable()

    def send(self, data: bytes):
        """ Send data into the peripheral.
            
            Example:
                ql.hw.usart1.send(b'hello')
        """
        self.itube.write(data)        

    def recv(self, numb:int = 4096) -> bytes:
        """ Receive data from peripheral

            Example:
                data = ql.hw.i2c1.recv()
        """
        return self.otube.read(numb)

    def send_to_user(self, data: int):
        """ send single byte to user
        """        
        self.otube.put(data)

    def recv_from_user(self) -> bytes:
        """ Read single byte from user input
        """        
        return self.itube.get()

    def connect(self, device):
        if len(self.device_list) < self.limit:
            self.device_list.append(device)

    @staticmethod
    def device_handler(func):
        """ Send one byte to all devices
        """
        def wrapper(self):            
            if len(self.device_list) > 0:                
                if self.otube.readable():
                    data = self.recv(1)
                    for device in self.device_list:
                        device.send(data)

                for device in self.device_list:
                    device.step()

            func(self)
        
        return wrapper
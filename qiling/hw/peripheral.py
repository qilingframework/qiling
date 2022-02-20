#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from typing import List, Tuple

from qiling.core import Qiling
from qiling.exception import QlErrorBase
from qiling.hw.utils.access import Access, Op


class QlPeripheralUtils:
    def __init__(self):
        self.verbose = False
        
        self.hook_read_list = []
        self.hook_write_list = []

    def watch(self):
        self.verbose = True

    def hook_read(self, callback, *args, **kwargs):
        self.hook_read_list.append((callback, args, kwargs))

    def hook_write(self, callback, *args, **kwargs):
        self.hook_write_list.append((callback, args, kwargs))

    @staticmethod
    def monitor(width=4):
        def decorator(func):
            def read(self, offset: int, size: int) -> int:
                for callback, args, kwargs in self.hook_read_list:
                    callback(self, offset, size, *args, **kwargs)

                retval = func(self, offset, size)
                if self.verbose:
                    self.ql.log.info(f'[{self.label.upper()}] [{hex(self.ql.reg.pc)}] [R] {self.find_field(offset, size):{width}s} = {hex(retval)}')
                
                return retval

            def write(self, offset: int, size: int, value: int):
                for callback, args, kwargs in self.hook_write_list:
                    callback(self, offset, size, value, *args, **kwargs)

                if self.verbose:
                    field, extra = self.find_field(offset, size), ''
                    if field.startswith('DR') and value <= 255:
                        extra = f'({repr(chr(value))})'

                    self.ql.log.info(f'[{self.label.upper()}] [{hex(self.ql.reg.pc)}] [W] {field:{width}s} = {hex(value)} {extra}')
                
                return func(self, offset, size, value)

            funcmap = {
                'read' : read,
                'write': write,
            }

            name = func.__name__
            if name in funcmap:
                return funcmap[name]

            raise QlErrorBase("Invalid peripheral decorator 'monitor'")

        return decorator

    @staticmethod
    def recorder():
        def decorator(func):
            def read(self, offset: int, size: int) -> int:
                self.history.add(Access(Op.READ, offset))
                return func(self, offset, size)

            def write(self, offset: int, size: int, value: int):
                self.history.add(Access(Op.WRITE, offset, value))
                return func(self, offset, size, value)

            funcmap = {
                'read' : read,
                'write': write,
            }

            name = func.__name__
            if name in funcmap:
                return funcmap[name]

            raise QlErrorBase("Invalid peripheral decorator 'recorder'")

        return decorator


class QlPeripheral(QlPeripheralUtils):
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
        super().__init__()

        self.ql = ql
        self.label = label
        self.struct = type(self).Type

    def step(self):
        """ Update the state of the peripheral, 
            called after each instruction is executed
        """        
        pass
    
    @QlPeripheralUtils.monitor()
    def read(self, offset: int, size: int) -> int:
        return 0

    @QlPeripheralUtils.monitor()
    def write(self, offset: int, size: int, value: int):
        pass

    def contain(self, field, offset: int, size: int) -> bool:
        return field.offset <= offset and offset + size <= field.offset + field.size

    def find_field(self, offset: int, size: int) -> str:
        """ Return field names in interval [offset: offset + size],
            the function is designed for logging and debugging.

        Returns:
            str: Field name
        """

        field_list = []
        for name, _ in self.struct._fields_:
            field = getattr(self.struct, name)
            
            lbound = max(0, offset - field.offset)
            ubound = min(offset + size  - field.offset, field.size)
            if lbound < ubound:
                if lbound == 0 and ubound == field.size:
                    field_list.append(name)
                else:
                    field_list.append(f'{name}[{lbound}:{ubound}]')
                
        return ','.join(field_list)

    @property
    def region(self) -> List[Tuple]:
        """Get the memory intervals occupyied by peripheral (base address = 0x0).

        Returns:
            List[Tuple]: Memory intervals occupyied by peripheral
        """
        return [(0, ctypes.sizeof(self.struct))]

    @property
    def size(self) -> int:
        """Calculate the memory size occupyied by peripheral.

        Returns:
            int: Size
        """        
        return sum(rbound-lbound for lbound, rbound in self.region)

    @property
    def base(self) -> int:
        """Get the base address from QlHwManager.

        Returns:
            int: Peripheral's base address
        """        
        return self.ql.hw.region[self.label][0][0]

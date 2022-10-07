#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from typing import List, Tuple

from qiling.core import Qiling
from qiling.const import QL_INTERCEPT
from qiling.exception import QlErrorBase
from qiling.hw.utils.access import Access, Action


class QlPeripheralUtils:
    def __init__(self):
        self.verbose = False
        
        self.user_read = {
            QL_INTERCEPT.ENTER: [],
            QL_INTERCEPT.CALL: [],           
            QL_INTERCEPT.EXIT: [],
        }

        self.user_write = {
            QL_INTERCEPT.ENTER: [],
            QL_INTERCEPT.CALL: [],           
            QL_INTERCEPT.EXIT: [],
        }

    def watch(self):
        self.verbose = True

    def hook_read(self, callback, user_data=None, intercept=QL_INTERCEPT.ENTER):
        hook_function = (callback, user_data)
        self.user_read[intercept].append(hook_function)
        return (0, intercept, hook_function)

    def hook_write(self, callback, user_data=None, intercept=QL_INTERCEPT.ENTER):
        hook_function = (callback, user_data)
        self.user_write[intercept].append(hook_function)
        return (1, intercept, hook_function)

    def hook_del(self, hook_struct):
        hook_type, hook_flag, hook_function = hook_struct
        mapper = self.user_read if hook_type else self.user_write
        mapper[hook_flag].remove(hook_function)

    def _hook_call(self, hook_list, access, offset, size, value=0):
        retval = None
        for callback, user_data in hook_list:
            if user_data is None:
                retval = callback(self, access, offset, size, value)
            else:
                retval = callback(self, access, offset, size, value, user_data)
                
        return retval

    @staticmethod
    def monitor(width=4):
        def decorator(func):
            def read(self, offset: int, size: int) -> int:
                self._hook_call(self.user_read[QL_INTERCEPT.ENTER], Action.READ, offset, size)

                if self.user_read[QL_INTERCEPT.CALL]:
                    retval = self._hook_call(self.user_read[QL_INTERCEPT.CALL], Action.READ, offset, size)
                else:
                    retval = func(self, offset, size)

                if self.verbose:
                    self.ql.log.info(f'[{self.label.upper()}] [{hex(self.ql.arch.regs.arch_pc)}] [R] {self.field_description(offset, size):{width}s} = {hex(retval)}')
                
                self._hook_call(self.user_read[QL_INTERCEPT.EXIT], Action.READ, offset, size)

                return retval

            def write(self, offset: int, size: int, value: int):
                self._hook_call(self.user_write[QL_INTERCEPT.ENTER], Action.WRITE, offset, size, value)

                if self.verbose:
                    field, extra = self.field_description(offset, size), ''
                    if field.startswith('DR') and value <= 255:
                        extra = f'({repr(chr(value))})'

                    self.ql.log.info(f'[{self.label.upper()}] [{hex(self.ql.arch.regs.pc)}] [W] {field:{width}s} = {hex(value)} {extra}')
                
                if self.user_write[QL_INTERCEPT.CALL]:
                    self._hook_call(self.user_write[QL_INTERCEPT.CALL], Action.WRITE, offset, size, value)
                else:
                    func(self, offset, size, value)

                self._hook_call(self.user_write[QL_INTERCEPT.EXIT], Action.WRITE, offset, size, value)

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
                self.history.add(Access(Action.READ, offset))
                return func(self, offset, size)

            def write(self, offset: int, size: int, value: int):
                self.history.add(Access(Action.WRITE, offset, value))
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
        self.instance = self.struct()

    def raw_read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.instance) + offset, size)

        return int.from_bytes(buf.raw, byteorder='little')

    def raw_write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.instance) + offset, data, size)
    
    @QlPeripheralUtils.monitor()
    def read(self, offset: int, size: int) -> int:
        return self.raw_read(offset, size)

    @QlPeripheralUtils.monitor()
    def write(self, offset: int, size: int, value: int):
        self.raw_write(offset, size, value)

    def contain(self, field, offset: int, size: int) -> bool:
        """ 
        Returns:
            bool: Whether the range [offset: offset+size] is in this field
        """
        return field.offset <= offset and offset + size <= field.offset + field.size

    def field_description(self, offset: int, size: int) -> str:
        """ Return field description in interval [offset: offset + size],
            the function is designed for logging and debugging.

        Returns:
            str: Field description
        """

        result = []

        def parse_array(struct, left, right, prefix):
            inner_struct = struct._type_
            inner_struct_size = ctypes.sizeof(inner_struct)

            for i in range(struct._length_):
                offset = inner_struct_size * i
                
                lower = max(0, left - offset)
                upper = min(right - offset, inner_struct_size)

                if lower < upper:
                    parse_struct(inner_struct, lower, upper, f'{prefix}[{i}]')

        def parse_struct(struct, left, right, prefix=''):
            if   hasattr(struct, '_length_'):
                parse_array(struct, left, right, prefix)

            elif hasattr(struct, '_fields_'):
                if prefix.endswith(']'):
                    prefix += '.'

                for name, vtype in struct._fields_:
                    field = getattr(struct, name)

                    lower = max(0, left - field.offset)
                    upper = min(right - field.offset, field.size)

                    if lower < upper:
                        parse_struct(vtype, lower, upper, prefix + name)

            else:
                if left == 0 and right == ctypes.sizeof(struct):
                    result.append(prefix)
                else:
                    result.append(f'{prefix}[{left}:{right}]')

        parse_struct(self.struct, offset, offset + size)
        return ','.join(result)

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
    
    def save(self):
        return bytes(self.instance)

    def restore(self, data):
        ctypes.memmove(ctypes.addressof(self.instance), data, len(data))

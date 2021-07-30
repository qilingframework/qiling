#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.utils import ql_get_module_function

class QlHardware:
    def __init__(self, ql):
        self.ql = ql
        self._tag = ''

    def read(self, offset, size) -> bytearray:
        if size == 4:
            return self.read_double_word(offset)
        
        if size == 2:
            return self.read_word(offset)

        if size == 1:
            return self.read_byte(offset)
        
        return b'\x00' * size

    def write(self, offset, size, value):
        if size == 4:
            return self.write_double_word(offset, value)
        
        if size == 2:
            return self.write_word(offset, value)

        if size == 1:
            return self.write_byte(offset, value)
        
        return b'\x00' * size

    def read_callback(self):
        def ql_read_cb(ql, offset, size):
            return self.read(offset)
        return ql_read_cb
    
    def write_callback(self):
        def ql_write_cb(ql, offset, size, value):
            return self.write(offset, size, value)
        return ql_write_cb    

    def read_double_word(self, offset) -> bytearray:
        return b'\x00' * 4

    def read_word(self, offset) -> bytearray:
        return b'\x00' * 2

    def read_byte(self, offset) -> bytearray:
        return b'\x00' * 1

    def write_double_word(self, offset, value):
        pass

    def write_word(self, offset, value):
        pass

    def write_byte(self, offset, value):
        pass

    def step(self):
        pass

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, value):
        self._tag = value


class QlHwManager:
    def __init__(self, ql):
        self.ql = ql

        self._entity = {}

    def add_hardware(self, hw_type, hw_name, hw_tag=None):
        """You can access the `hw_tag` by `ql.hw.hw_tag` or `ql.hw['hw_tag']`"""

        if hw_tag is None:
            hw_tag = hw_name
            
        ## underscore to camel-case
        hw_class = ''.join([token.capitalize() for token in hw_name.split('_')])

        entity = ql_get_module_function(f'qiling.hw.{hw_type}.{hw_name}', hw_class)(self.ql)
        
        entity.tag = hw_tag
        self[hw_tag] = entity
        setattr(self, hw_tag, entity)

    def items(self):
        return self._entity.items()

    def __getitem__(self, key):
        return self._entity[key]

    def __setitem__(self, key, value):
        self._entity[key] = value

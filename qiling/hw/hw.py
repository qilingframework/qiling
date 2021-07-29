#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.utils import ql_get_module_function

class QlHwManager:
    def __init__(self, ql):
        self.ql = ql

        self._entity = {}

    def create_hardware(self, hw_type, hw_name, hw_tag=None):
        """You can access the `hw_tag` by `ql.hw.hw_tag` or `ql.hw['hw_tag']`
        """

        if hw_tag is None:
            hw_tag = hw_name
            
        ## underscore to camel-case
        hw_class = ''.join([token.capitalize() for token in hw_name.split('_')])

        self[hw_tag] = ql_get_module_function(f'qiling.hw.{hw_type}.{hw_name}', hw_class)(self.ql)
        setattr(self, hw_tag, self[hw_tag])

    def __getitem__(self, key):
        return self._entity[key]

    def __setitem__(self, key, value):
        self._entity[key] = value

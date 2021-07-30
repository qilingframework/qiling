#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.utils import ql_get_module_function


class QlHwManager:
    def __init__(self, ql):
        self.ql = ql

        self._entity = {}

    def create(self, hw_name, hw_tag, hw_base):
        """You can access the `hw_tag` by `ql.hw.hw_tag` or `ql.hw['hw_tag']`"""

        entity = ql_get_module_function('qiling.hw', hw_name)(self.ql, hw_base)
        
        entity.tag = hw_tag
        self[hw_tag] = entity
        setattr(self, hw_tag, entity)

    def items(self):
        return self._entity.items()

    def __getitem__(self, key):
        return self._entity[key]

    def __setitem__(self, key, value):
        self._entity[key] = value

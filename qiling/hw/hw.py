#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.utils import ql_get_module_function


class QlHwManager:
    def __init__(self, ql):
        self.ql = ql

        self._entity = {}
        self._region = {}

    def create(self, name, tag, region):
        """You can access the `hw_tag` by `ql.hw.hw_tag` or `ql.hw['hw_tag']`"""

        if type(region) is tuple:
            region = [region]

        base = region[0][0]
        entity = ql_get_module_function('qiling.hw', name)(self.ql, base)    
        entity.tag = tag

        self._entity[tag] = entity
        self._region[tag] = region

        setattr(self, tag, entity)
    
    def find(self, addr, size):
        def check_bound(lbound, rbound):
            return lbound <= addr and addr + size <= rbound
        
        for tag in self._entity.keys():
            for lbound, rbound in self._region[tag]:
                if check_bound(lbound, rbound):
                    return self._entity[tag]

    def step(self):
        for _, entity in self._entity.items():
            entity.step()

    def __getitem__(self, key):
        return self._entity[key]

    def __setitem__(self, key, value):
        self._entity[key] = value

    def setup_mmio(self, begin, size, info=""):
        def mmio_read_cb(ql, offset, size):
            address = begin + offset
            hardware = self.find(address, size)
            if hardware:
                base = self._region[hardware.tag][0][0]
                return hardware.read(address - base, size)
            else:
                ql.log.warning('%s Read non-mapped hardware [0x%08x]' % (info, address))
                
            return 0

        def mmio_write_cb(ql, offset, size, value):
            address = begin + offset
            hardware = self.find(address, size)
            if hardware:
                base = self._region[hardware.tag][0][0]
                hardware.write(address - base, size, value)
            else:
                ql.log.warning('%s Write non-mapped hardware [0x%08x] = 0x%08x' % (info, address, value))

        self.ql.mem.map_mmio(begin, size, mmio_read_cb, mmio_write_cb, info=info)

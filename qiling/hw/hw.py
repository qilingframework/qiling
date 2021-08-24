#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.utils import ql_get_module_function
from qiling.exception import QlErrorModuleFunctionNotFound

class QlHwManager:
    def __init__(self, ql):
        self.ql = ql

        self.entity = {}
        self.region = {}        

    def create(self, name, tag, base, **kwargs):
        """You can access the `tag` by `ql.hw.tag` or `ql.hw['tag']`"""

        try:
            entity = ql_get_module_function('qiling.hw', name)(self.ql, tag, **kwargs)
            setattr(self, tag, entity)
            self.entity[tag] = entity
            self.region[tag] = [(lbound + base, rbound + base) for (lbound, rbound) in entity.region]
        except QlErrorModuleFunctionNotFound as e:
            self.ql.log.warning(f'The {name}({tag}) has not been implemented')
        
    def find(self, addr, size):
        def check_bound(lbound, rbound):
            return lbound <= addr and addr + size <= rbound
        
        for tag in self.entity.keys():
            for lbound, rbound in self.region[tag]:
                if check_bound(lbound, rbound):
                    return self.entity[tag]

    def step(self):
        for _, entity in self.entity.items():
            entity.step()

    def __getitem__(self, key):
        return self.entity[key]

    def __setitem__(self, key, value):
        self.entity[key] = value

    def setup_bitband(self, base, alias, size, info=""):
        """ reference: 
                https://github.com/qemu/qemu/blob/453d9c61dd5681159051c6e4d07e7b2633de2e70/hw/arm/armv7m.c
        """

        def bitband_addr(offset):
            return base |  (offset & 0x1ffffff) >> 5

        def bitband_read_cb(ql, offset, size):
            addr = bitband_addr(offset) & (-size)
            buf = self.ql.mem.read(addr, size)
                        
            bitpos = (offset >> 2) & ((size * 8) - 1)            
            bit = (buf[bitpos >> 3] >> (bitpos & 7)) & 1

            return bit

        def bitband_write_cb(ql, offset, size, value):
            addr = bitband_addr(base, offset) & (-size)            
            buf = self.ql.mem.read(addr, size)
            
            bitpos = (offset >> 2) & ((size * 8) - 1)
            bit = 1 << (bitpos & 7)
            if value & 1:
                buf[bitpos >> 3] |= bit
            else:
                buf[bitpos >> 3] &= ~bit

            self.ql.mem.write(addr, bytes(buf))            

        self.ql.mem.map_mmio(alias, size, bitband_read_cb, bitband_write_cb, info=info)

    def setup_mmio(self, begin, size, info=""):
        def mmio_read_cb(ql, offset, size):
            address = begin + offset                        
            hardware = self.find(address, size)
            
            if hardware:
                return hardware.read(address - hardware.base, size)
            else:
                ql.log.debug('%s Read non-mapped hardware [0x%08x]' % (info, address))
                
            return 0

        def mmio_write_cb(ql, offset, size, value):
            address = begin + offset
            hardware = self.find(address, size)

            if hardware:
                hardware.write(address - hardware.base, size, value)
            else:
                ql.log.debug('%s Write non-mapped hardware [0x%08x] = 0x%08x' % (info, address, value))

        self.ql.mem.map_mmio(begin, size, mmio_read_cb, mmio_write_cb, info=info)

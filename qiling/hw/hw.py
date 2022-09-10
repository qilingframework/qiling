#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral
from qiling.utils import ql_get_module_function
from qiling.exception import QlErrorModuleFunctionNotFound


class QlHwManager:
    def __init__(self, ql: Qiling):
        self.ql = ql

        self.entity = {}
        self.region = {}        

    def create(self, label: str, struct: "QlPeripheral"=None, base: int=None) -> "QlPeripheral":
        """ Create the peripheral accroding the label and envs.

            struct: Structure of the peripheral. Use defualt ql structure if not provide.
            base: Base address. Use defualt address if not provide.
        """
        env_struct, env_base, kwargs = self.load_env(label.upper())

        struct = env_struct if struct is None else struct
        base = env_base if base is None else base        

        try:
            
            entity = ql_get_module_function('.hw', struct)(self.ql, label, **kwargs)
            setattr(self, label, entity)
            self.entity[label] = entity
            self.region[label] = [(lbound + base, rbound + base) for (lbound, rbound) in entity.region]

            return entity
        except QlErrorModuleFunctionNotFound:
            self.ql.log.warning(f'The {struct}({label}) has not been implemented')

    def delete(self, label: str):
        """ Remove the peripheral
        """
        if label in self.entity:
            self.entity.pop(label)
            self.region.pop(label)
            delattr(self, label)

    def load_env(self, label: str):
        """ Get peripheral information (structure, base address, initialization list) from env.

        Args:
            label (str): Peripheral Label
        
        """
        args = self.ql.env[label]
        
        return args['struct'], args['base'], args.get("kwargs", {})
        
    def find(self, address: int):
        """ Find the peripheral at `address`
        """
        
        for label in self.entity.keys():
            for lbound, rbound in self.region[label]:
                if lbound <= address <= rbound:
                    return self.entity[label]

    def step(self):
        """ Update all peripheral's state 
        """
        for _, entity in self.entity.items():
            entity.step()

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
            addr = bitband_addr(offset) & (-size)            
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
        mmio = ctypes.create_string_buffer(size)        

        def mmio_read_cb(ql, offset, size):
            address = begin + offset                        
            hardware = self.find(address)
            
            if hardware:
                return hardware.read(address - hardware.base, size)
            else:
                ql.log.warning('%s Read non-mapped hardware [0x%08x]' % (info, address))                
                
                buf = ctypes.create_string_buffer(size)
                ctypes.memmove(buf, ctypes.addressof(mmio) + offset, size)
                return int.from_bytes(buf.raw, byteorder='little')

        def mmio_write_cb(ql, offset, size, value):
            address = begin + offset
            hardware = self.find(address)

            if hardware:
                hardware.write(address - hardware.base, size, value)
            else:
                ql.log.warning('%s Write non-mapped hardware [0x%08x] = 0x%08x' % (info, address, value))
                ctypes.memmove(ctypes.addressof(mmio) + offset, (value).to_bytes(size, 'little'), size)

        self.ql.mem.map_mmio(begin, size, mmio_read_cb, mmio_write_cb, info=info)

    def setup_remap(self, base, alias, size, info=""):
        def remap_read_cb(ql, offset, size):
            return int.from_bytes(ql.mem.read(alias + offset, size), 'little')

        def remap_write_cb(ql, offset, size, value):
            ql.mem.write(alias + offset, (value).to_bytes(size, 'little'))

        self.ql.mem.map_mmio(base, size, remap_read_cb, remap_write_cb, info=info)

    def show_info(self):
        self.ql.log.info(f'{"Start":8s}   {"End":8s}   {"Label":8s} {"Class"}')

        for label, region in self.region.items():
            for lbound, ubound in region:
                classname = self.entity[label].__class__.__name__
                self.ql.log.info(f'{lbound:08x} - {ubound:08x}   {label.upper():8s} {classname}')

    def __getitem__(self, key):
        return self.entity[key]

    def __setitem__(self, key, value):
        self.entity[key] = value
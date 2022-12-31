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

        self.stepable = {}    

    def create(self, label: str, struct: str=None, base: int=None, kwargs: dict={}) -> "QlPeripheral":
        """ Create the peripheral accroding the label and envs.

            struct: Structure of the peripheral. Use defualt ql structure if not provide.
            base: Base address. Use defualt address if not provide.
        """

        if struct is None:
            struct, base, kwargs = self.load_env(label.upper())

        try:
            
            entity = ql_get_module_function('qiling.hw', struct)(self.ql, label, **kwargs)
            
            self.entity[label] = entity
            if hasattr(entity, 'step'):
                self.stepable[label] = entity            

            self.region[label] = [(lbound + base, rbound + base) for (lbound, rbound) in entity.region]


            return entity
        except QlErrorModuleFunctionNotFound:
            self.ql.log.debug(f'The {struct}({label}) has not been implemented')

    def delete(self, label: str):
        """ Remove the peripheral
        """
        if label in self.entity:
            self.entity.pop(label)
            self.region.pop(label)
            if label in self.stepable:
                self.stepable.pop(label)            

    def load_env(self, label: str):
        """ Get peripheral information (structure, base address, initialization list) from env.

        Args:
            label (str): Peripheral Label
        
        """
        args = self.ql.env[label]
        
        return args['struct'], args['base'], args.get("kwargs", {})

    def load_all(self):
        for label, args in self.ql.env.items():
            if args['type'] == 'peripheral':
                self.create(label.lower(), args['struct'], args['base'], args.get("kwargs", {}))

    def find(self, address: int):
        """ Find the peripheral at `address`
        """
        
        for label in self.entity.keys():
            for lbound, rbound in self.region[label]:
                if lbound <= address < rbound:
                    return self.entity[label]

    def step(self):
        """ Update all peripheral's state 
        """
        for entity in self.stepable.values():
            entity.step()

    def setup_mmio(self, begin, size, info=""):
        mmio = ctypes.create_string_buffer(size)        

        def mmio_read_cb(ql, offset, size):
            address = begin + offset                        
            hardware = self.find(address)
            
            if hardware:
                return hardware.read(address - hardware.base, size)
            else:
                ql.log.debug('%s Read non-mapped hardware [0x%08x]' % (info, address))                
                
                buf = ctypes.create_string_buffer(size)
                ctypes.memmove(buf, ctypes.addressof(mmio) + offset, size)
                return int.from_bytes(buf.raw, byteorder='little')

        def mmio_write_cb(ql, offset, size, value):
            address = begin + offset
            hardware = self.find(address)

            if hardware:
                hardware.write(address - hardware.base, size, value)
            else:
                ql.log.debug('%s Write non-mapped hardware [0x%08x] = 0x%08x' % (info, address, value))
                ctypes.memmove(ctypes.addressof(mmio) + offset, (value).to_bytes(size, 'little'), size)

        self.ql.mem.map_mmio(begin, size, mmio_read_cb, mmio_write_cb, info=info)

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

    def __getattr__(self, key):
        return self.entity.get(key)

    def save(self):
        return {label : entity.save() for label, entity in self.entity.items()}

    def restore(self, saved_state):
        for label, data in saved_state.items():
            self.entity[label].restore(data)

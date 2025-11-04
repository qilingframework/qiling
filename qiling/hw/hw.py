#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Any, Dict, List, Optional, Tuple

from qiling import Qiling
from qiling.hw.peripheral import QlPeripheral
from qiling.utils import ql_get_module_function
from qiling.exception import QlErrorModuleFunctionNotFound


# should adhere to the QlMmioHandler interface, but not extend it directly to
# avoid potential pickling issues
class QlPripheralHandler:
    def __init__(self, hwman: "QlHwManager", base: int, size: int, label: str) -> None:
        self._hwman = hwman
        self._base = base
        self._size = size
        self._label = label

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['_hwman']  # remove non-pickleable reference

        return state

    @cached_property
    def _mmio(self) -> bytearray:
        """Get memory buffer used to back non-mapped hardware mmio regions.
        """

        return bytearray(self._size)

    def read(self, ql: Qiling, offset: int, size: int) -> int:
        address = self._base + offset
        hardware = self._hwman.find(address)

        if hardware:
            return hardware.read(address - hardware.base, size)

        else:
            ql.log.debug('[%s] read non-mapped hardware [%#010x]', self._label, address)
            return int.from_bytes(self._mmio[offset:offset + size], byteorder='little')

    def write(self, ql: Qiling, offset: int, size: int, value: int) -> None:
        address = self._base + offset
        hardware = self._hwman.find(address)

        if hardware:
            hardware.write(address - hardware.base, size, value)

        else:
            ql.log.debug('[%s] write non-mapped hardware [%#010x] = %#010x', self._label, address, value)
            self._mmio[offset:offset + size] = value.to_bytes(size, 'little')


class QlHwManager:
    def __init__(self, ql: Qiling):
        self.ql = ql

        self.entity: Dict[str, QlPeripheral] = {}
        self.region: Dict[str, List[Tuple[int, int]]] = {}

    def create(self, label: str, struct: Optional[str] = None, base: Optional[int] = None, kwargs: Optional[Dict[str, Any]] = None) -> QlPeripheral:
        """ Create the peripheral accroding the label and envs.

            struct: Structure of the peripheral. Use defualt ql structure if not provide.
            base: Base address. Use defualt address if not provide.
        """

        if struct is None:
            struct, base, kwargs = self.load_env(label.upper())

        if kwargs is None:
            kwargs = {}

        try:
            entity = ql_get_module_function('qiling.hw', struct)(self.ql, label, **kwargs)

        except QlErrorModuleFunctionNotFound:
            self.ql.log.warning(f'could not create {struct}({label}): implementation not found')

        else:
            assert isinstance(entity, QlPeripheral)
            assert isinstance(base, int)

            self.entity[label] = entity
            self.region[label] = [(lbound + base, rbound + base) for (lbound, rbound) in entity.region]

            return entity

        # FIXME: what should we do if struct is not implemented? is it OK to return None , or we fail?

    def delete(self, label: str) -> None:
        """ Remove the peripheral
        """

        if label in self.entity:
            del self.entity[label]

        if label in self.region:
            del self.region[label]

    def load_env(self, label: str) -> Tuple[str, int, Dict[str, Any]]:
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

    # TODO: this is wasteful. device mapping is known at creation time. at least we could cache lru entries
    def find(self, address: int) -> Optional[QlPeripheral]:
        """ Find the peripheral at `address`
        """

        for label in self.entity.keys():
            for lbound, rbound in self.region[label]:
                if lbound <= address < rbound:
                    return self.entity[label]

        return None

    def step(self):
        """ Update all peripheral's state
        """

        for ent in self.entity.values():
            if hasattr(ent, 'step'):
                ent.step()

    def setup_mmio(self, begin: int, size: int, info: str) -> None:
        dev = QlPripheralHandler(self, begin, size, info)

        self.ql.mem.map_mmio(begin, size, dev, info)

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
        return {
            'entity': {label: entity.save() for label, entity in self.entity.items()},
            'region': self.region
        }

    def restore(self, saved_state):
        entity = saved_state['entity']
        assert isinstance(entity, dict)

        region = saved_state['region']
        assert isinstance(region, dict)

        for label, data in entity.items():
            self.entity[label].restore(data)

        self.region = region

        # a dirty hack to rehydrate non-pickleable hwman
        # a proper fix would require a deeper refactoring to how peripherals are created and managed
        for ph in self.ql.mem.mmio_cbs.values():
            if isinstance(ph, QlPripheralHandler):
                setattr(ph, '_hwman', self)

#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import json, os
from Registry import Registry
from typing import Any, MutableMapping, Optional, Tuple, Union

from qiling import Qiling
from qiling.os.windows.const import REG_TYPES
from qiling.exception import *


# Registry Manager reads data from two places
# 1. config.json
#       if you want to modify the registry key/value, you can modify config.json
#       If there is a registry entry in config.json that needs to be read, 
#       Registry Manager will read from config.json first.
# 2. windows hive files

# Registry Manager will only write registry changes to config.json 
# and will not modify the hive file.

class RegConf:
    def __init__(self, fname: str):
        try:
            with open(fname, 'r') as infile:
                data = infile.read()
        except IOError:
            config = {}
        else:
            config = json.loads(data or '{}')

        self.conf: MutableMapping[str, dict[str, dict]] = config

    def exists(self, key: str) -> bool:
        return key in self.conf

    def create(self, key: str) -> None:
        if not self.exists(key):
            self.conf[key] = {}

    def delete(self, key: str, subkey: str) -> None:
        if self.exists(key):
            del self.conf[key][subkey]

    def read(self, key: str, subkey: str, reg_type: int) -> Tuple:
        if key in self.conf:
            subkeys = self.conf[key]

            if subkey in subkeys:
                subkey_item = subkeys[subkey]

                item_type = subkey_item['type']
                item_value = subkey_item['value']

                if item_type not in REG_TYPES:
                    raise QlErrorNotImplemented(f'Windows Registry Type {item_type} not implemented')

                return REG_TYPES[item_type], item_value

        return None, None

    def write(self, key: str, subkey: str, reg_type: int, data: Union[str, bytes, int]) -> None:
        if not self.exists(key):
            self.create(key)

        self.conf[key][subkey] = {
            'type'  : REG_TYPES[reg_type],
            'value' : data
        }

    def save(self, fname: str):
        if self.conf:
            with open(fname, 'wb') as ofile:
                data = json.dumps(self.conf)

                ofile.write(data.encode('utf-8'))


class RegHive:
    def __init__(self, hname: str):
        def __make_reg(kname: str) -> Registry.Registry:
            return Registry.Registry(os.path.join(hname, kname))

        # hkey local system
        self.hklm = {
            'SECURITY' : __make_reg('SECURITY'),
            'SAM'      : __make_reg('SAM'),
            'SOFTWARE' : __make_reg('SOFTWARE'),
            'SYSTEM'   : __make_reg('SYSTEM'),
            'HARDWARE' : __make_reg('HARDWARE')
        }

        # hkey current user
        self.hkcu = __make_reg('NTUSER.DAT')

    def __split_reg_path(self, key: str) -> Tuple[Optional[Registry.Registry], Optional[str]]:
        regsep = '\\'
        keys = key.split(regsep)

        if keys[0] == 'HKEY_LOCAL_MACHINE':
            reg = self.hklm[keys[1].upper()]
            sub = regsep.join(keys[2:])

        elif keys[0] == 'HKEY_CURRENT_USER':
            reg = self.hkcu
            sub = regsep.join(keys[1:])

        else:
            reg = None
            sub = None

        return reg, sub

    def exists(self, key: str) -> bool:
        reg, sub = self.__split_reg_path(key)

        if reg is None:
            return False

        try:
            reg.open(sub)
        except:
            return False
        else:
            return True

    def create(self, key: str) -> None:
        pass

    def delete(self, key: str, subkey: str) -> None:
        pass

    def read(self, key: str, subkey: str, reg_type: int) -> Tuple:
        reg, sub = self.__split_reg_path(key)

        if reg is None:
            raise QlErrorNotImplemented(f'registry root key not implemented')

        v_value = None
        v_type = None

        try:
            data = reg.open(sub)
        except Registry.RegistryKeyNotFoundException:
            pass
        else:
            value = next((v for v in data.values() if v.name() == subkey and reg_type in (Registry.RegNone, v.value_type())), None)

            if value:
                v_value = value.value()
                v_type = value.value_type()

        return (v_type, v_value)

    def write(self, key: str, subkey: str, reg_type: int, data: Union[str, bytes, int]) -> None:
        pass


class RegistryManager:
    def __init__(self, ql: Qiling, hivedir: str):
        self.ql = ql
        self.regdiff = os.path.join(ql.rootfs, 'registry', f'{ql.targetname}_diff.json')

        # if conf file does not exist, create its directory to enable saving later on
        if not os.path.exists(self.regdiff):
            os.makedirs(os.path.dirname(self.regdiff), 0o755, exist_ok=True)

        if not ql.code:
            if not os.path.exists(hivedir):
                raise QlErrorFileNotFound(f'Windows registry directory not found: "{hivedir}"!')

        ql.log.debug(f'Loading Windows registry hive from {hivedir}')

        try:
            self.reghive = RegHive(hivedir)
        except FileNotFoundError:
            if not ql.code:
                QlErrorFileNotFound("Windows registry hive not found")

        except Exception:
            if not ql.code:
                QlErrorFileNotFound("Windows registry hive format error")

        try:
            self.regconf = RegConf(self.regdiff)
        except json.decoder.JSONDecodeError:
            raise QlErrorJsonDecode("Windows registry JSON decode error")

    def exists(self, key: str) -> bool:
        self.access(key)

        return self.regconf.exists(key) or self.reghive.exists(key)

    def read(self, key: str, subkey: str, reg_type: int) -> Tuple:
        result = self.regconf.read(key, subkey, reg_type)

        if result == (None, None):
            result = self.reghive.read(key, subkey, reg_type)

        self.access(key, subkey, *result)

        return result

    def access(self, key: str, name: Optional[str] = None, type: Optional[int] = None, value: Any = None):
        self.ql.os.stats.log_reg_access(key, name, type, value)

    def create(self, key: str) -> None:
       self.regconf.create(key)
       self.reghive.create(key)

    def delete(self, key: str, subkey: str) -> None:
       self.regconf.delete(key, subkey)
       self.reghive.delete(key, subkey)

    def __reg_mem_read(self, data_type: int, data_addr: int, data_size: int, wide: bool) -> Optional[Union[str, bytes, int]]:
        if data_type in (Registry.RegSZ, Registry.RegExpandSZ):
            os_utils = self.ql.os.utils
            read_string = os_utils.read_wstring if wide else os_utils.read_cstring

            data = read_string(data_addr)

        elif data_type == Registry.RegDWord:
            data = self.ql.mem.read_ptr(data_addr, 4)

        elif data_type == Registry.RegQWord:
            data = self.ql.mem.read_ptr(data_addr, 8)

        elif data_type == Registry.RegBin:
            data = bytes(self.ql.mem.read(data_addr, data_size))

        else:
            data = None

        return data

    def __reg_mem_write(self, data_type: int, data_addr: int, data_val: Union[str, bytes, int], wide: bool) -> Optional[int]:
        if data_type in (Registry.RegSZ, Registry.RegExpandSZ):
            assert type(data_val) is str

            enc = 'utf-16le' if wide else 'utf-8'
            data = f'{data_val}\x00'.encode(enc)

        elif data_type == Registry.RegDWord:
            assert type(data_val) is int

            data = self.ql.pack32(data_val)

        elif data_type == Registry.RegQWord:
            assert type(data_val) is int

            data = self.ql.pack64(data_val)

        elif data_type == Registry.RegBin:
            assert type(data_val) is bytes

            data = data_val

        else:
            return None

        self.ql.mem.write(data_addr, data)

        return len(data)

    def write(self, key: str, subkey: str, reg_type: int, data_addr: int, data_size: int, wide: bool) -> None:
        data = self.__reg_mem_read(reg_type, data_addr, data_size, wide)

        if data is None:
            raise QlErrorNotImplemented(f'registry type {REG_TYPES[reg_type]} not implemented')

        self.regconf.write(key, subkey, reg_type, data)
        self.reghive.write(key, subkey, reg_type, data)

    def write_reg_value_into_mem(self, data_type: int, data_addr: int, data_val: Union[str, bytes, int], wide: bool) -> int:
        length = self.__reg_mem_write(data_type, data_addr, data_val, wide)

        if length is None:
            raise QlErrorNotImplemented(f'registry type {REG_TYPES[data_type]} not implemented')

        return length

    def save(self):
        self.regconf.save(self.regdiff)

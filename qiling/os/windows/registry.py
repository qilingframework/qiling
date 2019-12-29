#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import os
import json
import sys
from Registry import Registry
from qiling.os.windows.const import *
from qiling.exception import *

# Registry Manager reads data from two places
# 1. config.json
#       if you want to modify the registry key/value, you can modify config.json
#       If there is a registry entry in config.json that needs to be read, 
#       Registry Manager will read from config.json first.
# 2. windows hive files

# Registry Manager will only write registry changes to config.json 
# and will not modify the hive file.


class RegistryManager:
    def __init__(self, ql, hive=None, config=None):
        self.ql = ql
        rootfs = ql.rootfs
        self.registry_config = None

        # hive dir
        if hive:
            self.hive = hive
        else:
            if not ql.reg_dir:
                ql.reg_dir = "registry"
            self.hive = os.path.join(rootfs, ql.reg_dir)
            if not os.path.exists(self.hive):
                return

        # config path
        if config:
            self.config = config
        else:
            if not ql.reg_diff:
                ql.reg_diff = "config.json"

            self.config = os.path.join(rootfs, ql.reg_dir, ql.reg_diff)

        if not os.path.exists(self.config):
            self.registry_config = {}
        else:
            # read config
            # use registry config first
            self.f_config = open(self.config, "rb")
            data = self.f_config.read()
            if data == b"":
                self.registry_config = {}
                self.f_config.close()
            else:
                try:
                    self.registry_config = json.loads(data)
                except json.decoder.JSONDecodeError:
                    raise QlErrorJsonDecode("[!] Windows Registry JSON decode error")
                finally:
                    self.f_config.close()

        # hkey local system
        self.hklm = {}
        try:
            self.hklm['SAM'] = Registry.Registry(os.path.join(self.hive, 'SAM'))
            self.hklm['SECURITY'] = Registry.Registry(os.path.join(self.hive, 'SECURITY'))
            self.hklm['SOFTWARE'] = Registry.Registry(os.path.join(self.hive, 'SOFTWARE'))
            self.hklm['SYSTEM'] = Registry.Registry(os.path.join(self.hive, 'SYSTEM'))
            # hkey current user
            self.hkcu = Registry.Registry(os.path.join(self.hive, 'NTUSER.DAT'))
        except FileNotFoundError:
            QlPrintException("WARNING: Registry files not found!")
        except Exception:
            QlPrintException("WARNING: Registry files format error")

    def exists(self, key):
        if key in self.config:
            return True
        keys = key.split("\\")
        try:
            if keys[0] == "HKEY_LOCAL_MACHINE":
                reg = self.hklm[keys[1]]
                data = reg.open("\\".join(keys[2:]))
            elif keys[0] == "HKEY_CURRENT_USER":
                reg = self.hkcu
                data = reg.open("\\".join(keys[1:]))
            else:
                raise QlErrorNotImplemented("[!] Windows Registry %s not implemented" % (keys[0]))
        except Exception:
            return False
        return True

    def read(self, key, subkey, reg_type):
        # read reg conf first
        if key in self.config and subkey in self.config[key]:
            if self.config[key][subkey].type in REG_TYPES:
                return REG_TYPES[self.config[key][subkey].type], self.config[key][subkey].value
            else:
                raise QlErrorNotImplemented("[!] Windows Registry Type %s not implemented" % (self.config[key][subkey].type))

        # read hive
        reg = None
        data = None
        keys = key.split('\\')
        try:
            if keys[0] == "HKEY_LOCAL_MACHINE":
                reg = self.hklm[keys[1]]
                data = reg.open("\\".join(keys[2:]))
            elif keys[0] == "HKEY_CURRENT_USER":
                reg = self.hkcu
                data = reg.open("\\".join(keys[1:]))
            else:
                raise QlErrorNotImplemented("[!] Windows Registry %s not implemented" % (keys[0]))

            for value in data.values():
                if value.name() == subkey and (reg_type == Registry.RegNone or \
                    value.value_type() == reg_type):
                    return value.value_type(), value.value()
            return None, None
        except Registry.RegistryKeyNotFoundException:
            return None, None

    def create(self, key):
        self.registry_config[key] = dict()

    def write(self, key, subkey, reg_type, data):
        if key not in self.registry_config:
            self.create(key)
        # write registry changes to config.json
        self.registry_config[key][subkey] = {
            "type": REG_TYPES[reg_type],
            "value": data
        }

    def delete(self, key, subkey):
        del self.registry_config[key][subkey]

    @staticmethod
    def _encode_binary_value(data):
        # bytes(hex(data), 'ascii')
        # TODO
        pass

    def write_reg_value_into_mem(self, reg_value, reg_type, address):
        length = 0
        # string
        if reg_type == Registry.RegSZ or reg_type == Registry.RegExpandSZ:
            self.ql.mem_write(address, reg_value)
            length = len(reg_value)
        elif reg_type == Registry.RegBin:
            # you can set REG_BINARY like '\x00\x01\x02' in config.json
            if type(reg_value) == str:
                self.ql.mem_write(address, bytes(reg_value))
                length = len(reg_value)
            else:
                raise QlErrorNotImplemented("[!] Windows Registry Type not implemented")
        elif reg_type == Registry.RegDWord:
            data = self.ql.pack32(reg_value)
            self.ql.mem_write(address, data)
            length = len(data)
        elif reg_type == Registry.RegQWord:
            data = self.ql.pack64(reg_value)
            self.ql.mem_write(address, data)
            length = len(data)
        else:
            raise QlErrorNotImplemented("[!] Windows Registry Type write to memory %s not implemented" % (REG_TYPES[reg_type]))

        return length

    def save(self):
        # write registry config to config file
        if self.registry_config and len(self.registry_config) != 0:
            with open(self.config, "wb") as f:
                f.write(bytes(json.dumps(self.registry_config), "utf-8"))

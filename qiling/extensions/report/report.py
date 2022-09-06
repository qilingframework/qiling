#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import json

from qiling.const import *


class Report:
    def __init__(self, ql):
        self.filename = ql.argv
        self.rootfs = ql.rootfs
        self.arch = list(arch_map.keys())[list(arch_map.values()).index(ql.archtype)]
        self.os = list(os_map.keys())[list(os_map.values()).index(ql.ostype)]
        self.env = ql.env
        self.strings = set()
        for string in ql.os.utils.appeared_strings:
            strings = string.split(" ")
            self.strings |= set(strings)
        self.profile = {}
        for section in ql.profile.sections():
            self.profile.update(dict(ql.profile.items(section)))
        self.strings = list(self.strings)
        self.patches = []
        self.patches.extend(ql.patch_bin)
        self.patches.extend(ql.patch_lib)


class WindowsReport(Report):
    def __init__(self, ql):
        super().__init__(ql)
        self.dlls = ql.loader.dlls
        self.teb_address = ql.loader.TEB.base
        self.peb_address = ql.loader.PEB.base
        self.ldr_address = ql.loader.LDR.base
        self.api = ql.os.syscalls
        self.registries = {}
        for key, values in ql.os.registry_manager.accessed.items():
            self.registries[key] = values
        self.entry_point = ql.loader.entry_point
        self.import_symbols = {}
        for key, internal_dict in ql.loader.import_symbols.items():
            internal_dict["name"] = internal_dict["name"].decode("utf-8") if type(internal_dict["name"]) == bytes else \
                                    internal_dict["name"]
            self.import_symbols[key] = internal_dict
        self.export_symbols = {}
        for key, internal_dict in ql.loader.export_symbols.items():
            internal_dict["name"] = internal_dict["name"].decode("utf-8") if type(internal_dict["name"]) == bytes else \
                                    internal_dict["name"]
            self.export_symbols[key] = internal_dict
        self.cmdline = ql.loader.cmdline.decode("utf-8")


def generate_report(ql, pretty_print=False) -> dict:
    if ql.ostype == QL_OS.WINDOWS:
        report = WindowsReport(ql)
    else:
        report = Report(ql)
    res = report.__dict__
    if pretty_print:
        res = json.dumps(res, indent=10, sort_keys=True)
    return res

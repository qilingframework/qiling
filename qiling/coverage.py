#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from ctypes import Structure
from ctypes import c_uint32, c_uint16
from contextlib import contextmanager

# Adapted from https://www.ayrx.me/drcov-file-format
class bb_entry(Structure):
    _fields_ = [
        ("start",  c_uint32),
        ("size",   c_uint16),
        ("mod_id", c_uint16)
    ]

class QlCoverage():
    def __init__(self, ql, drcov_version = 2, drcov_flavor = "drcov"):
        self.ql            = ql
        self.drcov_version = drcov_version
        self.drcov_flavor  = drcov_flavor
        self.basic_blocks  = []
        self.bb_callback   = None

    @staticmethod
    def block_callback(ql, address, size, self):
        for mod_id, mod in enumerate(ql.loader.images):
            if mod.base <= address <= mod.end:
                ent = bb_entry(address - mod.base, size, mod_id)
                self.basic_blocks.append(ent)
                break

    def activate(self):
        self.bb_callback = self.ql.hook_block(self.block_callback, user_data=self)

    def deactivate(self):
        self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file):
        with open(coverage_file, "wb") as cov:
            cov.write(f"DRCOV VERSION: {self.drcov_version}\n".encode())
            cov.write(f"DRCOV FLAVOR: {self.drcov_flavor}\n".encode())
            cov.write(f"Module Table: version {self.drcov_version}, count {len(self.ql.loader.images)}\n".encode())
            cov.write("Columns: id, base, end, entry, checksum, timestamp, path\n".encode())
            for mod_id, mod in enumerate(self. ql.loader.images):
                cov.write(f"{mod_id}, {mod.base}, {mod.end}, 0, 0, 0, {mod.path}\n".encode())
            cov.write(f"BB Table: {len(self.basic_blocks)} bbs\n".encode())
            for bb in self.basic_blocks:
                cov.write(bytes(bb))

@contextmanager
def collect_coverage(ql, coverage_file):
    cov = QlCoverage(ql)
    cov.activate()
    try:
        yield
    finally:
        cov.deactivate()
        if coverage_file:
            cov.dump_coverage(coverage_file)

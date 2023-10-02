#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from collections import namedtuple
from os.path import basename

from .base import QlBaseCoverage


# Adapted from https://github.com/nccgroup/Cartographer/blob/main/EZCOV.md#coverage-data
class bb_entry(namedtuple('bb_entry', 'offset size mod_id')):
    def csvline(self):
        offset = '0x{:08x}'.format(self.offset)
        mod_id = f"[ {self.mod_id if self.mod_id is not None else ''} ]"
        return f"{offset},{self.size},{mod_id}\n"

class QlEzCoverage(QlBaseCoverage):
    """
    Collects emulated code coverage and formats it in accordance with the Cartographer Ghidra extension:
    https://github.com/nccgroup/Cartographer/blob/main/EZCOV.md

    The resulting output file can later be imported by coverage visualization tools such
    as Cartographer: https://github.com/nccgroup/Cartographer/
    """

    FORMAT_NAME = "ezcov"

    def __init__(self, ql):
        super().__init__(ql)
        self.ezcov_version = 1
        self.ezcov_flavor  = 'ezcov'
        self.basic_blocks  = []
        self.bb_callback   = None

    @staticmethod
    def block_callback(ql, address, size, self):
        mod = ql.loader.find_containing_image(address)
        if mod is not None:
            ent = bb_entry(address - mod.base, size, basename(mod.path))
            self.basic_blocks.append(ent)

    def activate(self):
        self.bb_callback = self.ql.hook_block(self.block_callback, user_data=self)

    def deactivate(self):
        self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file):
        with open(coverage_file, "w") as cov:
            cov.write(f"EZCOV VERSION: {self.ezcov_version}\n")
            cov.write("# Qiling EZCOV exporter tool\n")
            for bb in self.basic_blocks:
                cov.write(bb.csvline())
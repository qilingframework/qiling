#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import os
from typing import Any, TYPE_CHECKING, List, NamedTuple

from .base import QlBaseCoverage


if TYPE_CHECKING:
    from qiling import Qiling


# Adapted from https://github.com/nccgroup/Cartographer/blob/main/EZCOV.md#coverage-data
class bb_entry(NamedTuple):
    offset: int
    size: int
    mod_id: Any

    def as_csv(self) -> str:
        offset = f'{self.offset:#010x}'
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

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ezcov_version = 1
        self.ezcov_flavor = 'ezcov'
        self.basic_blocks: List[bb_entry]  = []
        self.bb_callback = None

    def block_callback(self, ql: Qiling, address: int, size: int):
        img = ql.loader.find_containing_image(address)

        if img is not None:
            self.basic_blocks.append(bb_entry(address - img.base, size, os.path.basename(img.path)))

    def activate(self) -> None:
        self.bb_callback = self.ql.hook_block(self.block_callback)

    def deactivate(self) -> None:
        if self.bb_callback:
            self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file: str) -> None:
        with open(coverage_file, "w") as cov:
            cov.write(f"EZCOV VERSION: {self.ezcov_version}\n")
            cov.write("# Qiling EZCOV exporter tool\n")

            cov.writelines(bb.as_csv() for bb in self.basic_blocks)

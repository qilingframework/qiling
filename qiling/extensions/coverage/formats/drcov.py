#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from ctypes import Structure, c_uint32, c_uint16
from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO, Dict, Tuple

from .base import QlBaseCoverage


if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.loader.loader import QlLoader


# Adapted from https://www.ayrx.me/drcov-file-format
class bb_entry(Structure):
    _fields_ = [
        ("start",  c_uint32),
        ("size",   c_uint16),
        ("mod_id", c_uint16)
    ]

    def __init__(self, start, size, module_id=None):
        self.start = start
        self.size = size
        self.module_id = module_id
    
    def __eq__(self, other):
        return (self.start, self.size, self.module_id) == (other.start, other.size, other.module_id)

    def __hash__(self):
        return hash((self.start, self.size, self.module_id))


class QlDrCoverage(QlBaseCoverage):
    """
    Collects emulated code coverage and formats it in accordance with the DynamoRIO based
    tool drcov: https://dynamorio.org/dynamorio_docs/page_drcov.html

    The resulting output file can later be imported by coverage visualization tools such
    as Lighthouse: https://github.com/gaasedelen/lighthouse
    """

    FORMAT_NAME = "drcov"

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.drcov_version = 2
        self.drcov_flavor = 'drcov'
        self.basic_blocks: Dict[int, bb_entry] = {}
        self.bb_callback = None

    @lru_cache(maxsize=64)
    def _get_img_base(self, loader: QlLoader, address: int) -> Tuple[int, int]:
        """Retrieve the containing image of a given address.

        Addresses are expected to be aligned to page boundary, and cached for faster retrieval.
        """

        return next((i, img.base) for i, img in enumerate(loader.images) if img.base <= address < img.end)

    def block_callback(self, ql: Qiling, address: int, size: int):
        if address not in self.basic_blocks:
            try:
                # we rely on the fact that images are allocated on page size boundary and
                # use it to speed up image retrieval. we align the basic block address to
                # page boundary, knowing basic blocks within the same page belong to the
                # same image. then we use the aligned address to retreive the containing
                # image. returned values are cached so subsequent retrievals for basic
                # blocks within the same page will return the cached value instead of
                # going through the retreival process again (up to maxsize cached pages)

                i, img_base = self._get_img_base(ql.loader, address & ~(0x1000 - 1))
            except StopIteration:
                pass
            else:
                self.basic_blocks[address] = bb_entry(address - img_base, size, i)

    def activate(self) -> None:
        self.bb_callback = self.ql.hook_block(self.block_callback)

    def deactivate(self) -> None:
        if self.bb_callback:
            self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file: str) -> None:
        def __write_line(bio: BinaryIO, line: str) -> None:
            bio.write(f'{line}\n'.encode())

        with open(coverage_file, "wb") as cov:
            __write_line(cov, f"DRCOV VERSION: {self.drcov_version}")
            __write_line(cov, f"DRCOV FLAVOR: {self.drcov_flavor}")
            __write_line(cov, f"Module Table: version {self.drcov_version}, count {len(self.ql.loader.images)}")
            __write_line(cov, "Columns: id, base, end, entry, checksum, timestamp, path")

            for mod_id, mod in enumerate(self. ql.loader.images):
                __write_line(cov, f"{mod_id}, {mod.base}, {mod.end}, 0, 0, 0, {mod.path}")

            __write_line(cov, f"BB Table: {len(self.basic_blocks)} bbs")

            for bb in self.basic_blocks.values():
                cov.write(bytes(bb))

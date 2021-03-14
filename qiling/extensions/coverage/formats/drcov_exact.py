#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .drcov import QlDrCoverage


class QlDrCoverageExact(QlDrCoverage):
    """
    Collects emulated code coverage and formats it in accordance with the DynamoRIO based
    tool drcov: https://dynamorio.org/dynamorio_docs/page_drcov.html

    The resulting output file can later be imported by coverage visualization tools such
    as Lighthouse: https://github.com/gaasedelen/lighthouse
    """

    FORMAT_NAME = "drcov_exact"

    def __init__(self, ql):
        super().__init__(ql)

    def activate(self):
        # We treat every instruction as a block on its own.
        self.bb_callback = self.ql.hook_code(self.block_callback, user_data=self)
        
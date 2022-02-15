#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from ..context import Context
from ..misc import read_int

class BranchPredictor(Context):
    """
    Base class for predictor
    """

    class Prophecy(object):
        """
        container for storing result of the predictor
        @going: indicate the certian branch will be taken or not
        @where: where will it go if going is true
        """

        def __init__(self):
            self.going = False
            self.where = None

        def __iter__(self):
            return iter((self.going, self.where))

    def __init__(self, ql):
        super().__init__(ql)

    def read_reg(self, reg_name):
        """
        read specific register value
        """

        return getattr(self.ql.reg, reg_name)

    def predict(self) -> Prophecy:
        """
        Try to predict certian branch will be taken or not based on current context
        """

        return NotImplementedError

if __name__ == "__main__":
    pass

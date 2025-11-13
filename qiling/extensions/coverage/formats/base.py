#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from qiling import Qiling


class QlBaseCoverage(ABC):
    """
    An abstract base class for concrete code coverage collectors.
    To add support for a new coverage format, just derive from this class and implement
    all the methods marked with the @abstractmethod decorator.
    """

    FORMAT_NAME: str

    def __init__(self, ql: Qiling):
        super().__init__()

        self.ql = ql

    @abstractmethod
    def activate(self) -> None:
        pass

    @abstractmethod
    def deactivate(self) -> None:
        pass

    @abstractmethod
    def dump_coverage(self, coverage_file: str) -> None:
        pass

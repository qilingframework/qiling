#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import ABC, abstractmethod

from qiling import Qiling


class QlBaseCoverage(ABC):
    """
    An abstract base class for concrete code coverage collectors.
    To add support for a new coverage format, just derive from this class and implement
    all the methods marked with the @abstractmethod decorator.
    """

    def __init__(self, ql: Qiling):
        super().__init__()

        self.ql = ql

    @property
    @staticmethod
    @abstractmethod
    def FORMAT_NAME() -> str:
        raise NotImplementedError

    @abstractmethod
    def activate(self):
        pass

    @abstractmethod
    def deactivate(self):
        pass

    @abstractmethod
    def dump_coverage(self, coverage_file: str):
        pass

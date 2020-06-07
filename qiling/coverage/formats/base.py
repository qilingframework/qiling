#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from abc import ABC, abstractmethod

class QlBaseCoverage(ABC):
    """
    An abstract base class for concrete code coverage collectors.
    To add support for a new coverage format, just derive from this class and implement
    all the methods marked with the @abstractmethod decorator.
    """
    
    def __init__(self):
        super().__init__()

    @property
    @staticmethod
    @abstractmethod
    def FORMAT_NAME():
        raise NotImplementedError

    @abstractmethod
    def activate(self):
        pass

    @abstractmethod
    def deactivate(self):
        pass

    @abstractmethod
    def dump_coverage(self, coverage_file):
        pass


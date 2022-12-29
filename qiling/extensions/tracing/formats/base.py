#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# This code structure is copied and modified from the coverage extension

from abc import ABC, abstractmethod


class QlBaseTrace(ABC):
    """
    An abstract base class for trace collectors.
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
    def dump_trace(self, trace_file):
        pass
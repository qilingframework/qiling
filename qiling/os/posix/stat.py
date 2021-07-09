#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os


class StatBase:
    def __init__(self):
        self._stat_buf = None

    # Never iterate this object!
    def __getitem__(self, key):
        if type(key) is not str:
            raise TypeError
        if not key.startswith("__") and key in dir(self._stat_buf):
            return self._stat_buf.__getattribute__(key)
        return 0

    def __getattr__(self, key):
        return self.__getitem__(key)


class Stat(StatBase):
    def __init__(self, path):
        super(Stat, self).__init__()
        self._stat_buf = os.stat(path)


class Fstat(StatBase):
    def __init__(self, fd):
        super(Fstat, self).__init__()
        self._stat_buf = os.fstat(fd)


class Lstat(StatBase):
    def __init__(self, path):
        super(Lstat, self).__init__()
        self._stat_buf = os.lstat(path)

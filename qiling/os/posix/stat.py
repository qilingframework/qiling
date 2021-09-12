#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

class StatBase:
    def __init__(self, stat: os.stat_result):
        self._stat_buf = stat

    # Never iterate this object!
    def __getitem__(self, key):
        if type(key) is not str:
            raise TypeError

        if not key.startswith("__") and hasattr(self._stat_buf, key):
            return self._stat_buf.__getattribute__(key)

        return 0

    def __getattr__(self, key):
        return self.__getitem__(key)

class Stat(StatBase):
    def __init__(self, path):
        super().__init__(os.stat(path))

class Fstat(StatBase):
    def __init__(self, fd: int):
        super().__init__(os.fstat(fd))

class Lstat(StatBase):
    def __init__(self, path):
        super().__init__(os.lstat(path))

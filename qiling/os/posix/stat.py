#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

class Stat(object):
    def __init__(self, path):
        super().__init__()
        self.path = path
        stat_buf = os.stat(self.path)
        print(stat_buf)
        for name in dir(stat_buf):
            if name.startswith('st_'):
                setattr(self, name, getattr(stat_buf, name))

class Fstat(object):
    def __init__(self, fd):
        super().__init__()
        self.fd = fd
        fstat_buf = os.fstat(self.fd)
        print(fstat_buf)
        for name in dir(fstat_buf):
            if name.startswith('st_'):
                setattr(self, name, getattr(fstat_buf, name))


class Lstat(object):
    def __init__(self, path):
        super().__init__()
        self.path = path
        lstat_buf = os.lstat(self.path)
        print(lstat_buf)
        for name in dir(lstat_buf):
            if name.startswith('st_'):
                setattr(self, name, getattr(lstat_buf, name))





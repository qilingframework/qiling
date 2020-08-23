#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import os


class Stat(object):
    def __init__(self, path):
        super().__init__()
        self.path = path

        self.st_dev = 0
        self.st_blksize = 0
        self.st_blocks = 0
        self.st_gid = 0
        self.st_ino = 0
        self.st_mode = 0
        self.st_nlink = 0
        self.st_rdev = 0
        self.st_size = 0
        self.st_uid = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0

        stat_buf = os.stat(self.path)
        for name in dir(stat_buf):
            if 'st_' in name:
                setattr(self, name, getattr(stat_buf, name))

class Fstat(object):
    def __init__(self, fd):
        super().__init__()
        self.fd = fd

        self.st_atime = 0
        self.st_blksize = 0
        self.st_blocks = 0
        self.st_ctime = 0
        self.st_dev = 0
        self.st_gid = 0
        self.st_ino = 0
        self.st_mode = 0
        self.st_mtime = 0
        self.st_nlink = 0
        self.st_rdev = 0
        self.st_size = 0
        self.st_uid = 0


        fstat_buf = os.fstat(self.fd)
        for name in dir(fstat_buf):
            if 'st_' in name:
                setattr(self, name, getattr(fstat_buf, name))


class Lstat(object):
    def __init__(self, path):
        super().__init__()
        self.path = path

        self.st_atime = 0
        self.st_blksize = 0
        self.st_blocks = 0
        self.st_ctime = 0
        self.st_dev = 0
        self.st_gid = 0
        self.st_ino = 0
        self.st_mode = 0
        self.st_mtime = 0
        self.st_nlink = 0
        self.st_rdev = 0
        self.st_size = 0
        self.st_uid = 0


        lstat_buf = os.lstat(self.fd)
        for name in dir(lstat_buf):
            if 'st_' in name:
                setattr(self, name, getattr(lstat_buf, name))





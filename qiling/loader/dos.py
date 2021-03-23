#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, traceback

from .loader import QlLoader

from qiling import Qiling
from qiling.os.disk import QlDisk

# @see: http://pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
class ComParser:
    '''Most basic COM file parser.
    '''

    def __init__(self, ql: Qiling, data: bytes) -> None:
        assert data[0:2] == b'MZ'

        nbytes  = ql.unpack16(data[2:4]) or 0x200    # number of bytes in last block; 0 means it is fully populated
        nblocks = ql.unpack16(data[4:6])             # number of blocks used
        self.size = (nblocks - 1) * 0x200 + nbytes

        self.init_ss = ql.unpack16(data[14:16])
        self.init_sp = ql.unpack16(data[16:18])
        self.init_ip = ql.unpack16(data[20:22])
        self.init_cs = ql.unpack16(data[22:24])

class QlLoaderDOS(QlLoader):
    def __init__(self, ql: Qiling):
        super(QlLoaderDOS, self).__init__(ql)
        self.ql = ql
        self.old_excepthook = sys.excepthook

    # Hack to print all exceptions if curses has been setup.
    def excepthook(self, tp, value, tb):
        if self.ql.os.stdscr is not None:
            tbmsg = "".join(traceback.format_exception(tp, value, tb))
            self.ql.log.info(f"{tbmsg}")
        self.old_excepthook(tp, value, tb)

    def run(self):
        path = self.ql.path
        profile = self.ql.profile

        # bare com file
        if path.endswith(".DOS_COM"):
            with open(path, "rb") as f:
                content = f.read()

            cs = int(profile.get("COM", "start_cs"), 0)
            ip = int(profile.get("COM", "start_ip"), 0)
            sp = int(profile.get("COM", "start_sp"), 0)
            ss = cs

            base_address = (cs << 4) + ip

        # com file with a dos header
        elif path.endswith(".DOS_EXE"):
            with open(path, "rb") as f:
                content = f.read()

            com = ComParser(self.ql, content)

            cs = com.init_cs
            ip = com.init_ip
            sp = com.init_sp
            ss = com.init_ss

            base_address = 0
            content = content[0x80:]

        elif path.endswith(".DOS_MBR"):
            with open(path, "rb") as f:
                content = f.read()

            cs = 0x0000
            ip = 0x7c00
            sp = 0xfff0
            ss = cs

            base_address = (cs << 4) + ip

            # https://en.wikipedia.org/wiki/Master_boot_record#BIOS_to_MBR_interface
            if not self.ql.os.fs_mapper.has_mapping(0x80):
                self.ql.os.fs_mapper.add_fs_mapping(0x80, QlDisk(path, 0x80))

            # 0x80 -> first drive
            self.ql.reg.dx = 0x80
        else:
            raise NotImplementedError()

        self.ql.reg.cs = cs
        self.ql.reg.ds = cs
        self.ql.reg.es = cs
        self.ql.reg.ss = ss
        self.ql.reg.ip = ip
        self.ql.reg.sp = sp

        self.stack_address = (ss << 4) + sp
        self.start_address = (cs << 4) + ip
        self.stack_size = int(profile.get("COM", "stack_size"), 0)
        self.ticks_per_second = profile.getfloat("KERNEL", "ticks_per_second")

        # map the entire system memory
        self.ql.mem.map(0, 0x100000, info="[FULL]")
        self.ql.mem.write(base_address, content)

        self.load_address = base_address
        self.ql.os.entry_point = self.start_address

        sys.excepthook = self.excepthook
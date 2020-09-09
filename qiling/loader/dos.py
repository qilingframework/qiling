#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .loader import QlLoader
import magic
import sys
import traceback
import math

class QlLoaderDOS(QlLoader):
    def __init__(self, ql):
        super(QlLoaderDOS, self).__init__(ql)
        self.ql = ql
        self.old_excepthook = sys.excepthook

    # Hack to print all exceptions if curses has been setup.
    def excepthook(self, tp, value, tb):
        if self.ql.os.stdscr is not None:
            tbmsg = "".join(traceback.format_exception(tp, value, tb))
            self.ql.nprint(f"{tbmsg}")
        self.old_excepthook(tp, value, tb)

    def _round_to_4k(self, addr):
        return round(addr / 4096) * 4096

    def _floor_to_4k(self, addr):
        return math.floor(addr / 4096) * 4096
    
    def _ceil_to_4k(self, addr):
        return math.ceil(addr / 4096) * 4096

    def run(self):
        path = self.ql.path
        ftype = magic.from_file(path)

        self.ticks_per_second = float(self.ql.profile.get("KERNEL", "ticks_per_second"))
        if ("COM" in ftype and "DOS" in ftype) or "COM" in path:
            # pure com
            self.cs = int(self.ql.profile.get("COM", "start_cs"), 16)
            self.ip = int(self.ql.profile.get("COM", "start_ip"), 16)
            self.sp = int(self.ql.profile.get("COM", "start_sp"), 16)
            self.stack_size = int(self.ql.profile.get("COM", "stack_size"), 16)
            self.ql.reg.cs = self.cs
            self.ql.reg.ds = self.cs
            self.ql.reg.es = self.cs
            self.ql.reg.ss = self.cs
            self.ql.reg.ip = self.ip
            self.ql.reg.sp = self.sp
            self.start_address = self.cs*16 + self.ip
            self.base_address = int(self.ql.profile.get("COM", "base_address"), 16)
            self.stack_address = int(self.ql.reg.ss*16 + self.ql.reg.sp)
            self.ql.mem.map(0, 0x100000, info="[FULL]")
            with open(path, "rb+") as f:
                bs = f.read()
            self.ql.mem.write(self.start_address, bs)
            self.load_address = self.base_address
            self.ql.os.entry_point = self.start_address
        elif "MBR" in ftype:
            # MBR
            self.start_address = 0x7C00
            with open(path, "rb+") as f:
                bs = f.read()
            # Map all available address.
            self.ql.mem.map(0x0, 0x100000)
            self.ql.mem.write(self.start_address, bs)
            self.cs = 0
            self.ql.reg.ds = self.cs
            self.ql.reg.es = self.cs
            self.ql.reg.ss = self.cs
            # 0x80 -> first drive.
            # https://en.wikipedia.org/wiki/Master_boot_record#BIOS_to_MBR_interface
            self.ql.reg.dx = 0x80
            self.ip = self.start_address
            self.load_address = self.start_address
            self.ql.os.entry_point = self.start_address
        elif "MS-DOS" in ftype:
            raise NotImplementedError()
            
        sys.excepthook = self.excepthook
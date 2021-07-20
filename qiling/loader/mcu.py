#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import struct

from qiling.const import *
from qiling.core import Qiling

from .loader import QlLoader

class IhexParser:
    def __init__(self, path):
        self.pc   = None
        self.base = None
        self.mem  = []
        self.segments = []

        with open(path, 'r') as f:
            for line in f.read().splitlines():
                self.parse_line(line)

            begin, end, bindata = 0, 0, b''
            for addr, data in self.mem:
                if addr != end:
                    self.add_segment(begin, end, bindata)
                    begin, end, bindata = addr, addr + len(data), data
                else:
                    bindata += data
                    end += len(data)
            self.add_segment(begin, end, bindata)            
                    
    def add_segment(self, begin, end, bindata):
        if len(bindata) > 0 and end - begin == len(bindata):
            self.segments.append((begin, end, bindata))

    def parse_line(self, line):
        size = int(line[1: 3], 16)        
        type = line[7: 9]

        addr = bytes.fromhex(line[3: 7])
        data = bytes.fromhex(line[9: 9 + size * 2])

        if type == '01':
            return
        
        if type == '04':            
            self.base = struct.unpack('>I', data + b'\x00\x00')[0]            
        elif type == '05':
            self.pc = struct.unpack('>I', data)[0]            
        elif type == '00':
            offset = struct.unpack('>I', b'\x00\x00' + addr)[0]
            self.mem.append((self.base + offset, data))

class QlLoaderMCU(QlLoader):
    def __init__(self, ql:Qiling):
        super(QlLoaderMCU, self).__init__(ql)
        
        self.ihexfile = IhexParser(self.argv[0])        
        
    def run(self):
        for begin, end, data in self.ihexfile.segments:
            self.ql.mem.write(begin, data)            

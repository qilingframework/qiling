#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import io
import struct
from elftools.elf.elffile import ELFFile

from qiling.const import *
from qiling.core import Qiling
from qiling.utils import component_setup

from .loader import QlLoader

class IhexParser:
    def __init__(self, path):
        self.pc   = None
        self.base = None
        self.mem  = []
        self.segments = []

        with open(path, 'r') as f:
            for line in f.read().splitlines():
                self.parse_line(line.strip())

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
        if len(line) < 9:
            return
        
        size = int(line[1: 3], 16)        
        type = line[7: 9]

        addr = bytes.fromhex(line[3: 7])
        data = bytes.fromhex(line[9: 9 + size * 2])

        if type == '04':            
            self.base = struct.unpack('>I', data + b'\x00\x00')[0]            
        elif type == '05':
            self.pc = struct.unpack('>I', data)[0]            
        elif type == '00':
            offset = struct.unpack('>I', b'\x00\x00' + addr)[0]
            self.mem.append((self.base + offset, data))

class QlLoaderMCU(QlLoader):
    def __init__(self, ql:Qiling):
        super().__init__(ql)   
        
        self.entry_point = 0
        self.load_address = 0
        self.filetype = self.guess_filetype()
        
        self.ql._hw = component_setup("hw", "hw", self.ql)

        if self.filetype == 'elf':
            with open(self.ql.path, 'rb') as infile:
                self.elf = ELFFile(io.BytesIO(infile.read()))
            
        elif self.filetype == 'bin':
            self.map_address = self.argv[1]

        else: # self.filetype == 'hex':
            self.ihex = IhexParser(self.ql.path)

    def guess_filetype(self):
        if self.ql.path.endswith('.elf'):
            return 'elf'            
            
        if self.ql.path.endswith('.bin'):
            return 'bin'

        if self.ql.path.endswith('.hex'):
            return 'hex'

        return 'elf'
    
    def reset(self):
        if self.filetype == 'elf':
            for segment in self.elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    self.ql.mem.write(segment['p_paddr'], segment.data())

            # TODO: load symbol table

        elif self.filetype == 'bin':
            with open(self.ql.path, 'rb') as f:
                self.ql.mem.write(self.map_address, f.read())

        else: # self.filetype == 'hex':
            for begin, _, data in self.ihex.segments:
                self.ql.mem.write(begin, data)

        
        self.ql.arch.init_context()
        self.entry_point = self.ql.reg.read('pc')

    def load_profile(self):
        self.ql.env.update(self.ql.profile)

    def load_env(self):
        for name, args in self.env.items():
            memtype = args['type']
            if memtype == 'memory':
                size = args['size']
                base = args['base']
                self.ql.mem.map(base, size, info=f'[{name}]')
                
                if name == 'FLASH':
                    self.ql.hw.setup_remap(0, base, size, info=f'[CODE]')

            if memtype == 'bitband':
                size = args['size'] * 32
                base = args['base']
                alias = args['alias']
                self.ql.hw.setup_bitband(base, alias, size, info=f'[{name}]')

            if memtype == 'mmio':
                size = args['size']
                base = args['base']
                self.ql.hw.setup_mmio(base, size, info=f'[{name}]')

            if memtype == 'core peripheral':
                self.ql.hw.create(name.lower())

    def run(self):
        self.load_profile()
        self.load_env()
        
        ## Handle interrupt from instruction execution
        self.ql.hook_intr(self.ql.arch.soft_interrupt_handler)
                
        self.reset()

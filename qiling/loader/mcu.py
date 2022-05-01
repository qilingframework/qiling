#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import io
from elftools.elf.elffile import ELFFile

from qiling.const import *
from qiling.core import Qiling
from .loader import QlLoader


class IhexParser:
    def __init__(self, path):
        self.mem  = []
        self.segments = []

        with open(path, 'r') as f:
            for line in f.read().splitlines():
                self.parse_line(line.strip())

            begin, stream = 0, b''
            for addr, data in self.mem:
                if addr != begin + len(stream):
                    self.segments.append((begin, stream))
                    begin, stream = addr, data
                
                else:
                    stream += data

            self.segments.append((begin, stream))

    def parse_line(self, line):
        if len(line) < 9:
            return
        
        desc = line[7: 9]
        size = int(line[1: 3], 16)        
        
        addr = bytes.fromhex(line[3: 7])
        data = bytes.fromhex(line[9: 9 + size * 2])        
        
        if   desc == '00': # Data
            offset = int.from_bytes(addr, byteorder='big')
            self.mem.append((self.base + offset, data))

        elif desc == '02': # Extended Segment Address
            self.base = int.from_bytes(data, byteorder='big') * 0x10

        elif desc == '04': # Extended Linear Address
            self.base = int.from_bytes(data, byteorder='big') * 0x10000
        

class QlLoaderMCU(QlLoader):
    def __init__(self, ql:Qiling):
        super().__init__(ql)   
        
        self.entry_point = 0
        self.load_address = 0
        self.filetype = self.guess_filetype()
        
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
            for segment in self.elf.iter_segments(type='PT_LOAD'):
                self.ql.mem.write(segment['p_paddr'], segment.data())

            # TODO: load symbol table

        elif self.filetype == 'bin':
            with open(self.ql.path, 'rb') as f:
                self.ql.mem.write(self.map_address, f.read())

        else: # self.filetype == 'hex':
            for begin, data in self.ihex.segments:
                self.ql.mem.write(begin, data)

        
        self.ql.arch.init_context()
        self.entry_point = self.ql.arch.regs.read('pc')

    def load_profile(self):
        self.ql.env.update(self.ql.profile)

    def load_env(self):
        for name, args in self.env.items():
            memtype = args['type']
            if memtype == 'memory':
                size = args['size']
                base = args['base']
                self.ql.mem.map(base, size, info=f'[{name}]')
            
            if memtype == 'remap':
                size = args['size']
                base = args['base']
                alias = args['alias']
                self.ql.hw.setup_remap(alias, base, size, info=f'[{name}]')

            if memtype == 'bitband':
                size = args['size'] * 32
                base = args['base']
                alias = args['alias']
                self.ql.hw.setup_bitband(base, alias, size, info=f'[{name}]')

            if memtype == 'mmio':
                size = args['size']
                base = args['base']
                self.ql.hw.setup_mmio(base, size, info=f'[{name}]')

            if memtype == 'core':
                self.ql.hw.create(name.lower())

    def run(self):
        self.load_profile()
        self.load_env()
        
        ## Handle interrupt from instruction execution
        self.ql.hook_intr(self.ql.arch.soft_interrupt_handler)
                
        self.reset()

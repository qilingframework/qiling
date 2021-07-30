#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import struct

from qiling.const import *
from qiling.core import Qiling
from qiling.hw.utils.bitbanding import alias_to_bitband

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
        super(QlLoaderMCU, self).__init__(ql)                
        self.ihexfile = IhexParser(self.argv[0])
        
        self.mapinfo = {
            'sram'      : (0x20000000, 0x20020000),
            'system'    : (0x1FFF0000, 0x1FFF7800),            
            'flash'     : (0x08000000, 0x08080000),             
            'peripheral': (0x40000000, 0x40100000),
            'core_perip': (0xE000E000, 0xE000F000),
        }

        self.perip_region = {
            'nvic': [(0xE000E100, 0xE000E4F0), (0xE000EF00, 0xE000EF04)],
            'sys_tick': [(0xE000E010, 0xE000E020)],                        
            'rcc': [(0x40023800, 0x40023C00)],
            'usart2': [(0x40004400, 0x40004800)]
        }

    def reset(self):
        if self.ql.arch.BOOT[0] == 0:
            self.ql.arch.boot_space = self.mapinfo['flash'][0]
        elif self.ql.arch.BOOT[1] == 0:
            self.ql.arch.boot_space = self.mapinfo['system'][0]
        elif self.ql.arch.BOOT[1] == 1:
            self.ql.arch.boot_space = self.mapinfo['sram'][0]

        self.ql.reg.write('lr', 0xffffffff)
        self.ql.reg.write('msp', self.ql.mem.read_ptr(self.ql.arch.boot_space))
        self.ql.reg.write('pc', self.ql.mem.read_ptr(self.ql.arch.boot_space + 0x4))

    def run(self):
        for begin, end in self.mapinfo.values():
            self.ql.mem.map(begin, end - begin)

        for begin, end, data in self.ihexfile.segments:
            self.ql.mem.write(begin, data)

        self.ql.arch.mapinfo = self.mapinfo
        self.ql.arch.perip_region = self.perip_region

        PPB_BEGIN, PPB_END = self.mapinfo['core_perip']
        PERIP_BEGIN, PERIP_END = self.mapinfo['peripheral']
        
        self.ql.hook_mem_read(self.ql.arch.perip_read_hook, begin=PPB_BEGIN, end=PPB_END)
        self.ql.hook_mem_read(self.ql.arch.perip_read_hook, begin=PERIP_BEGIN, end=PERIP_END)
        self.ql.hook_mem_write(self.ql.arch.perip_write_hook, begin=PPB_BEGIN, end=PPB_END)
        self.ql.hook_mem_write(self.ql.arch.perip_write_hook, begin=PERIP_BEGIN, end=PERIP_END)
        
        self.reset()


        # def sram_read_cb(uc, offset, size, data):
        #     print(f'\nread sram mem {hex(0x22000000+offset)}+{size} ==> {data}\n')
        #     real_addr = alias_to_bitband(0x20000000, offset)
        #     print(hex(real_addr))


        # def sram_write_cb(uc, offset, size, value, data):
        #     print(f'\nwrite sram mem {hex(0x22000000+offset)}+{size} {value} ==> {data}\n')
        #     real_addr = alias_to_bitband(0x20000000, offset)
        #     print(hex(real_addr))

        def peripheral_read_cb(uc, offset, size, data):
            print(f'\nread peripheral mem {hex(0x42000000+offset)}+{size} ==> {data}\n')
            real_addr = alias_to_bitband(0x40000000, offset)
            print(hex(real_addr))

        def peripheral_write_cb(uc, offset, size, value, data):
            print(f'\nwrite peripheral mem {hex(0x42000000+offset)}+{size} {value} ==> {data}\n')
            real_addr = alias_to_bitband(0x40000000, offset)
            print(hex(real_addr))
        
        # FIXME: SystemError: null argument to internal routine
        # self.ql.mem.mmio_map(0x22000000, 0x2000000, sram_read_cb, sram_write_cb, None, None) 
        self.ql.mem.mmio_map(0x42000000, 0x2000000, peripheral_read_cb, peripheral_write_cb, None, None)   

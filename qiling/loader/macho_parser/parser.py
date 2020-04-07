#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .header import *
from .loadcommand import *
from .data import *
from .const import *
from .utils import *
from struct import unpack

class MachoParser:
    
    # arch = "x8664" or "x86" 
    def __init__(self, ql, path, arch= None):
        self.ql = ql
        self.binary_file = self.readFile(path)
        self.raw_data = self.binary_file
        self.arch = ql.arch
        self.parseFile()
        self.page_zero_size = 0
        self.header_address = 0x0
        for seg in self.segments:
            # find page zero
            if seg.vm_address == 0 and seg.file_size == 0:
                self.ql.nprint("[+] PageZero Size: {:X}".format(seg.vm_size))
                self.page_zero_size = seg.vm_size
                self.header_address = seg.vm_size

    @staticmethod
    def readFile(path):
        with open(path, "rb") as f:
            return f.read()

    def parseFile(self):

        if not self.binary_file:
            return 
        
        if not self.parseHeader():
            return

        if not self.parseLoadCommand():
            return 

        if not self.parseData():
            return 
        

    def parseHeader(self):

        self.magic = self.getMagic(self.binary_file)
        
        if self.magic == MAGIC_64:
            self.ql.dprint(0, "[+] Got a 64bit Header ")
            self.header = BinaryHeader(self.binary_file)

        #elif self.magic == MAGIC_X86:
        #    # x86
        #    self.ql.dprint(0,"[+] Got a x86 Header") 
        #    self.header = BinaryHeader(self.binary_file)

        elif self.magic == MAGIC_FAT:
            # fat 
            self.ql.dprint(0, "[+] Got a fat header")
            fat = FatHeader(self.binary_file)
            file_info = fat.getBinary(self.arch)
            self.binary_file = self.binary_file[file_info.offset : file_info.offset + file_info.size]
            self.header = BinaryHeader(self.binary_file)
        else:
            self.ql.nprint("[-] unknow header!")
            return False
        
        if not self.header:
            self.ql.nprint("[-] parse header error")
            return False 

        return True

    def parseLoadCommand(self):

        self.ql.dprint(0, "[+] Parse LoadCommand")
        if not self.header.lc_num or not self.header.lc_size or not self.header.header_size:
            return False

        FR = FileReader(self.binary_file)
        FR.setOffset(self.header.header_size)
        self.lc_raw = FR.read(self.header.lc_size)
        self.commands = []
        offset = 0

        for i in range(self.header.lc_num):

            if self.header.lc_size >= 8:
                lc = LoadCommand(self.lc_raw[offset:])
            else:
                self.ql.nprint("[-] cmd size overflow")
                return False 

            if self.header.lc_size >= offset + lc.cmd_size:
                complete_cmd = lc.get_complete()
                pass
            else:
                self.ql.nprint("[-] cmd size overflow")
                return False
            
            self.commands.append(complete_cmd)
            
            offset += lc.cmd_size
        
        return True


    def parseData(self):
        self.segments = []      
        for command in self.commands:
            if command.cmd_id == LC_SEGMENT_64:
                self.segments.append(Segment(command, self.binary_file))
            elif command.cmd_id == LC_SEGMENT:
                self.segments.append(Segment(command, self.binary_file))
            elif command.cmd_id == LC_FUNCTION_STARTS:
                self.function_starts = FunctionStarts(command, self.binary_file)
            elif command.cmd_id == LC_SYMTAB:
                self.symbol_table = SymbolTable(command, self.binary_file)
                self.string_table = StringTable(command, self.binary_file)
            elif command.cmd_id == LC_DATA_IN_CODE:
                self.data_in_code = DataInCode(command, self.binary_file)
            elif command.cmd_id == LC_CODE_SIGNATURE:
                self.code_signature = CodeSignature(command, self.binary_file)
            elif command.cmd_id == LC_SEGMENT_SPLIT_INFO:
                self.seg_split_info = SegmentSplitInfo(command, self.binary_file)
            elif command.cmd_id == LC_DYSYMTAB:
                self.dysymbol_table = DySymbolTable(command, self.binary_file)
        return True
    
    @staticmethod
    def getMagic(binary):
        return unpack("<L", binary[:4])[0]

    def get_segment(self, name):
        for seg in self.segments:
            if seg.name == name:
                return seg
        return None


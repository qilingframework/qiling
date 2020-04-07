#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os

from struct import pack
from qiling.loader.macho_parser.parser import *
from qiling.loader.macho_parser.const import *
from qiling.exception import *


# TODO: we maybe we should use a better way to load
# reference to xnu source code /bsd/kern/mach_loader.c
class Macho:

    # macho x8664 loader 
    def __init__(self, ql, file_path, stack_sp, argvs, envs, apples, argc, dyld_path=None):

        self.macho_file     = MachoParser(ql, file_path)
        self.loading_file   = self.macho_file
        self.slide          = 0x0000000000000000
        self.dyld_slide     = 0x0000000500000000
        # self.dyld_slide     = 0x0000000100020000
        self.string_align   = 8
        self.ptr_align      = 8
        self.ql             = ql
        self.uc             = ql.uc
        self.binary_entry   = 0x0
        self.proc_entry     = 0x0
        self.stack_sp       = stack_sp
        self.argvs          = argvs
        self.envs           = envs
        self.apples         = apples
        self.argc           = argc
        self.dyld_path      = dyld_path
        self.using_dyld     = False
        self.vm_end_addr    = 0x0
        # self.dyld_slide = 0x1
        # todo: dyld loader

    def loadMacho(self, depth=0, isdyld=False):

        # MAX load depth 
        if depth > 5:
            return

        # three pass 
        # 1: unixthread, uuid, code signature
        # 2: segment
        # 3: dyld
        for pass_count in range(1, 4):

            if isdyld:
                cmds = self.dyld_file.commands
            else:
                cmds = self.macho_file.commands

            for cmd in cmds:
                if pass_count == 1:
                    if cmd.cmd_id == LC_UNIXTHREAD:
                        self.loadUnixThread(cmd, isdyld)

                    if cmd.cmd_id == LC_UUID:
                        self.loadUuid()

                    if cmd.cmd_id == LC_CODE_SIGNATURE:
                        self.loadCodeSignature()

                    if cmd.cmd_id == LC_MAIN:
                        self.loadMain(cmd)

                if pass_count == 2:
                    if cmd.cmd_id == LC_SEGMENT:
                        pass

                    if cmd.cmd_id == LC_SEGMENT_64:
                        #print(cmd)
                        self.loadSegment64(cmd, isdyld)

                if pass_count == 3:
                    if cmd.cmd_id == LC_LOAD_DYLINKER:
                        self.loadDylinker(cmd)
                        self.using_dyld = True
                        if not isdyld:
                            if not self.dyld_path:
                                raise QlErrorMACHOFormat("[!] Error No Dyld path")
                            self.dyld_path =  os.path.join(self.ql.rootfs + self.dyld_path)
                            self.dyld_file = MachoParser(self.ql, self.dyld_path)
                            self.loading_file = self.dyld_file
                            self.proc_entry = self.loadMacho(depth + 1, True)
                            self.loading_file = self.macho_file
                            #self.ql.nprint("[+] Dyld ProcEntry: {}".format(self.proc_entry))
                            self.using_dyld = True

        if depth == 0:
            self.ql.stack_sp = self.loadStack()
            if self.using_dyld:
                self.ql.nprint("[+] ProcEntry: {}".format(hex(self.proc_entry)))
                self.ql.entry_point = self.proc_entry + self.dyld_slide
                self.ql.nprint("[+] Dyld entry point: {}".format(hex(self.ql.entry_point)))
            else:
                self.ql.entry_point = self.proc_entry + self.slide
            self.ql.nprint("[+] Binary Entry Point: 0x{:X}".format(self.binary_entry))
            self.ql.macho_entry = self.binary_entry + self.slide
            self.ql.loadbase = self.ql.macho_entry
            self.ql.load_base =  self.slide
        # else:
        #     self.ql.nprint("[+] Loading dyld")

        return self.proc_entry
        
    def loadSegment64(self, cmd, isdyld):
        if isdyld:
            slide = self.dyld_slide
        else:
            slide = self.slide
        vaddr_start = cmd.vm_address + slide
        vaddr_end = cmd.vm_address + cmd.vm_size + slide 
        seg_size = cmd.vm_size
        seg_name = cmd.segment_name
        seg_data = bytes(self.loading_file.get_segment(seg_name).content)

        self.ql.dprint(0, "[+] Now loading {}, VM[{}:{}]".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
        self.ql.mem.map(vaddr_start, seg_size)
        self.ql.mem.write(vaddr_start, seg_data)
        if self.vm_end_addr < vaddr_end:
            self.vm_end_addr = vaddr_end
        # print("SegData : {}".format(seg_data[0x119c:]))
    
    def loadUnixThread(self, cmd, isdyld):
        if not isdyld:
            self.binary_entry = cmd.entry
 
        self.proc_entry = cmd.entry
        self.ql.dprint(0, "[+] Binary Thread Entry: {}".format(hex(cmd.entry)))


    def loadUuid(self):
        # todo: WIP
        pass

    def loadCodeSignature(self):
        # todo: WIP
        pass
    
    def loadMain(self, cmd, isdyld=False):
        if self.macho_file.page_zero_size:
            if not isdyld:
                self.binary_entry = cmd.entry_offset + self.macho_file.page_zero_size
            self.proc_entry = cmd.entry_offset + self.macho_file.page_zero_size

    def loadDylinker(self, cmd):
        self.dyld_path = cmd.name

    def make_string(self, argvs, envs, apple_str):
        result = bytes()
        for item in apple_str:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result
        for item in envs:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result 
        for item in argvs:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result
        return result 

    # TODO: add size check
    def loadStack(self):

        argvs_ptr = []
        envs_ptr = []
        apple_ptr = []

        all_str = self.make_string(self.argvs, self.envs, self.apples)
        self.push_stack_string(all_str)
        ptr = self.stack_sp

        for item in self.argvs[::-1]:
            argvs_ptr.append(ptr)  # need pack and tostring
            self.ql.dprint(0, '[+] add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.dprint(0, '[+] add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.dprint(0, '[+] add apple ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        ptr = self.stack_sp
        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in apple_ptr:
            self.push_stack_addr(item)
            ptr -= 4
        
        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in envs_ptr:
            ptr -= 4
            self.push_stack_addr(item)

        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in argvs_ptr:
            ptr -= 4
            self.push_stack_addr(item)
            self.ql.dprint(0, "[+] SP 0x%x, content 0x%x" % (self.stack_sp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.dprint(0, "[+] SP 0x%x, content 0x%x" % (self.stack_sp, self.argc))
       
        if self.using_dyld:
            ptr -= 4
            #self.ql.nprint("[+] Binary Dynamic Entry Point: {:X}".format(self.binary_entry))
            self.push_stack_addr(self.macho_file.header_address)
            # self.push_stack_addr(self.binary_entry)

        return self.stack_sp

    def push_stack_string(self, data):
        align = self.string_align
        length = len(data)
        
        if length % align != 0:
            for i in range(align - (length % align)):
                data += b'\x00' 
            length = len(data)
        
        self.stack_sp -= length
        self.uc.mem_write(self.stack_sp, data)
        self.ql.dprint(0, "[+] SP {} write data len {}".format(hex(self.stack_sp), length))
        
        return self.stack_sp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        
        if data == 0:
            content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            content = pack('<Q', data)

        if len(content) != align:
            self.ql.nprint('[!] stack align error')
            return 
        
        self.stack_sp -= align
        self.uc.mem_write(self.stack_sp, content)

        return self.stack_sp

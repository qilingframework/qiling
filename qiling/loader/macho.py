#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

from struct import pack
from qiling.loader.macho_parser.parser import *
from qiling.loader.macho_parser.define_value import *
from qiling.exception import *

# TODO: we maybe we should use a better way to load
# reference to xnu source code /bsd/kern/mach_loader.c

class MachoX86:

    # macho x86 parser
    def __init__(self, ql, file_path, stack_esp, argvs, envs, apples, argc, dyld_path=None):

        # parse macho file 
        self.macho_file     = MachoParser(ql, file_path, "x86")
        self.slide          = 0x0
        self.dyld_slide     = 0x30000000
        self.string_align   = 4
        self.ptr_align      = 4
        self.ql             = ql
        self.uc             = ql.uc
        self.binary_entry   = 0x0
        self.proc_entry     = 0x0
        self.stack_esp      = stack_esp
        self.stack_ebp      = stack_esp
        self.argvs          = argvs
        self.envs           = envs
        self.apples         = apples
        self.argc           = argc
        self.dyld_path      = dyld_path
        self.using_dyld     = False
        # self.dyld_slide = 0x1
        # todo: dyld loader

    def loadMachoX86(self, depth=0, isdyld=False):

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
                        self.loadSegment(cmd, isdyld)

                    if cmd.cmd_id == LC_SEGMENT_64:
                        pass

                if pass_count == 3:
                    if cmd.cmd_id == LC_LOAD_DYLINKER:
                        if not isdyld:
                            if not self.dyld_path:
                                raise QlErrorMACHOFormat("Error No Dyld path")
                            self.dyld_file = MachoParser(self.ql, self.dyld_path, "x86")
                            self.loadMachoX86(depth + 1, True)
                            self.using_dyld = True

        if depth == 0:
            self.ql.stack_esp = self.loadStack()
            if self.using_dyld:
                self.ql.entry_point = self.proc_entry + self.dyld_slide
            else:
                self.ql.entry_point = self.proc_entry + self.slide
            self.ql.macho_entry = self.binary_entry + self.slide
            self.ql.load_base =  self.slide

    def loadUnixThread(self, cmd, isdyld):
        if not isdyld:
            self.binary_entry = cmd.entry
        self.proc_entry = cmd.entry

    def loadUuid(self):
        # todo: finish
        pass

    def loadCodeSignature(self):
        # todo: finish
        pass
    
    def loadMain(self, cmd, isdyld=False):
        text_base = 0
        for seg in self.macho_file.segments:
            if seg.name == "__TEXT":
                text_base = seg.vm_address
                break
        if not isdyld:
            self.binary_entry = cmd.entry_offset + text_base 
        self.proc_entry = cmd.entry_offset + text_base 

    def loadSegment(self, cmd, isdyld):
        if isdyld:
            slide = self.dyld_slide
        else:
            slide = self.slide
        vaddr_start = cmd.vm_address + slide
        vaddr_end = cmd.vm_address + cmd.vm_size + slide 
        seg_size = cmd.vm_size
        seg_name = cmd.segment_name
        seg_data = bytes(self.macho_file.get_segment(seg_name).content)

        self.ql.dprint("[+] Now Loading {}, VM[{}:{}]".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
        self.uc.mem_map(vaddr_start, seg_size)
        self.uc.mem_write(vaddr_start, seg_data)

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
        ptr = self.stack_esp
                
        for item in self.argvs[::-1]:
            argvs_ptr.append(ptr)   # need pack and tostring
            self.ql.dprint('[+] add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.dprint('[+] add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.dprint('[+] add apple ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        ptr = self.stack_esp
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
            self.ql.dprint("[+] Esp 0x%x, content 0x%x" % (self.stack_esp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.dprint("[+] Esp 0x%x, content 0x%x" % (self.stack_esp, self.argc))
        if self.using_dyld:
            ptr -= 4
            self.push_stack_addr(binary_entry)

        return self.stack_esp

    def push_stack_string(self, data):
        align = self.string_align
        length = len(data)
        if length % align != 0:
            for i in range(align - (length % align)):
                data += b'\x00' 
            length = len(data)
        self.stack_esp -= length
        self.uc.mem_write(self.stack_esp, data)
        self.ql.dprint("[+] esp {} write data len {}".format(hex(self.stack_esp), length))
        return self.stack_esp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        if data == 0:
            content = b'\x00\x00\x00\x00'
        else:
            content = pack('<L', data)

        if len(content) != align:
            self.ql.nprint('[!] stack align error')
            return 
        
        self.stack_esp -= align
        self.uc.mem_write(self.stack_esp, content)
        return self.stack_esp


class MachoX8664:

    # macho x8664 loader 
    def __init__(self, ql, file_path, stack_esp, argvs, envs, apples, argc, dyld_path=None):

        self.macho_file     = MachoParser(ql, file_path)
        self.loading_file   = self.macho_file
        self.slide          = 0x0000000
        self.dyld_slide     = 0x3000000000000000
        self.string_align   = 8
        self.ptr_align      = 8
        self.ql             = ql
        self.uc             = ql.uc
        self.binary_entry   = 0x0
        self.proc_entry     = 0x0
        self.stack_esp      = stack_esp
        self.stack_ebp      = stack_esp
        self.argvs          = argvs
        self.envs           = envs
        self.apples         = apples
        self.argc           = argc
        self.dyld_path      = dyld_path
        self.using_dyld     = False
        # self.dyld_slide = 0x1
        # todo: dyld loader

    def loadMachoX8664(self, depth=0, isdyld=False):

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
                        self.loadSegment64(cmd, isdyld)

                if pass_count == 3:
                    if cmd.cmd_id == LC_LOAD_DYLINKER:
                        self.loadDylinker(cmd)
                        self.using_dyld = True
                        if not isdyld:
                            if not self.dyld_path:
                                raise QlErrorMACHOFormat("Error No Dyld path")
                            self.dyld_file = MachoParser(self.ql, self.dyld_path)
                            self.loading_file = self.dyld_file
                            self.proc_entry = self.loadMachoX8664(depth + 1, True)
                            self.loading_file = self.macho_file
                            print("dyldProcEntry : {}".format(self.proc_entry))
                            self.using_dyld = True

        if depth == 0:
            # self.ql.stack_esp = self.stack_esp
            self.ql.stack_esp = self.loadStack()
            if self.using_dyld:
                print("procEntry : {}".format(hex(self.proc_entry)))
                self.ql.entry_point = self.proc_entry + self.dyld_slide
                print("entryPoint : {}".format(hex(self.ql.entry_point)))
            else:
                self.ql.entry_point = self.proc_entry + self.slide
            print("binEntry : {}".format(self.binary_entry))
            self.ql.macho_entry = self.binary_entry + self.slide
            self.ql.load_base =  self.slide
        else:
            print("finish load dyld")

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

        self.ql.dprint("[+] Now loading {}, VM[{}:{}]".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
        self.uc.mem_map(vaddr_start, seg_size)
        self.uc.mem_write(vaddr_start, seg_data)
        # print("SegData : {}".format(seg_data[0x119c:]))
    
    def loadUnixThread(self, cmd, isdyld):
        if not isdyld:
            self.binary_entry = cmd.entry
        self.proc_entry = cmd.entry
        self.ql.dprint("[+] entry {}".format(hex(cmd.entry)))

    def loadUuid(self):
        # todo: finish
        pass

    def loadCodeSignature(self):
        # todo: finish
        pass
    
    def loadMain(self, cmd, isdyld=False):
        text_base = 0
        for seg in self.macho_file.segments:
            if seg.name == "__TEXT":
                text_base = seg.vm_address
                print("Text base {}".format(hex(text_base)))
                break
        if not isdyld:
            self.binary_entry = cmd.entry_offset + text_base 
        self.proc_entry = cmd.entry_offset + text_base 

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
        ptr = self.stack_esp

        for item in self.argvs[::-1]:
            argvs_ptr.append(ptr)   # need pack and tostring
            self.ql.dprint('[+] add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.dprint('[+] add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.dprint('[+] add apple ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        ptr = self.stack_esp
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
            self.ql.dprint("[+] esp 0x%x, content 0x%x" % (self.stack_esp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.dprint("[+] esp 0x%x, content 0x%x" % (self.stack_esp, self.argc))
        if self.using_dyld:
            ptr -= 4
            self.push_stack_addr(self.proc_entry)

        return self.stack_esp

    def push_stack_string(self, data):
        align = self.string_align
        length = len(data)
        if length % align != 0:
            for i in range(align - (length % align)):
                data += b'\x00' 
            length = len(data)
        self.stack_esp -= length
        self.uc.mem_write(self.stack_esp, data)
        self.ql.dprint("[+] esp {} write data len {}".format(hex(self.stack_esp), length))
        return self.stack_esp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        if data == 0:
            content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            content = pack('<Q', data)

        if len(content) != align:
            self.ql.nprint('[!] stack align error')
            return 
        
        self.stack_esp -= align
        self.uc.mem_write(self.stack_esp, content)
        return self.stack_esp

class MachoARM64:

    # macho ARM64 loader 
    def __init__(self, ql, file_path, stack_esp, argvs, envs, apples, argc, dyld_path=None):

        self.macho_file     = MachoParser(ql, file_path)
        self.slide          = 0x0000000
        self.dyld_slide     = 0x30000000
        self.string_align   = 8
        self.ptr_align      = 8
        self.ql             = ql
        self.uc             = ql.uc
        self.binary_entry   = 0x0
        self.proc_entry     = 0x0
        self.stack_esp      = stack_esp
        self.stack_ebp      = stack_esp
        self.argvs          = argvs
        self.envs           = envs
        self.apples         = apples
        self.argc           = argc
        self.dyld_path      = dyld_path
        self.using_dyld     = False
        # self.dyld_slide = 0x1
        # todo: dyld loader

    def loadMachoX8664(self, depth=0, isdyld=False):

        # MAX load depth +
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
                        self.loadSegment64(cmd, isdyld)

                if pass_count == 3:
                    if cmd.cmd_id == LC_LOAD_DYLINKER:
                        if not isdyld:
                            if not self.dyld_path:
                                raise QlErrorMACHOFormat("Error No Dyld path")
                            self.dyld_file = MachoParser(self.ql, self.dyld_path)
                            self.loadMachoX86(depth + 1, True)
                            self.using_dyld = True

        if depth == 0:
            # self.ql.stack_esp = self.stack_esp
            self.ql.stack_esp = self.loadStack()
            if self.using_dyld:
                self.ql.entry_point = self.proc_entry + self.dyld_slide
            else:
                self.ql.entry_point = self.proc_entry + self.slide
            self.ql.macho_entry = self.binary_entry + self.slide
            self.ql.load_base =  self.slide
        
    def loadSegment64(self, cmd, isdyld):
        if isdyld:
            slide = self.dyld_slide
        else:
            slide = self.slide
        vaddr_start = cmd.vm_address + slide
        vaddr_end = cmd.vm_address + cmd.vm_size + slide 
        seg_size = cmd.vm_size
        seg_name = cmd.segment_name
        seg_data = bytes(self.macho_file.get_segment(seg_name).content)

        self.ql.dprint("[+] Now loading {}, VM[{}:{}]".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
        self.uc.mem_map(vaddr_start, seg_size)
        self.uc.mem_write(vaddr_start, seg_data)
    
    def loadUnixThread(self, cmd, isdyld):
        if not isdyld:
            self.binary_entry = cmd.entry
        self.proc_entry = cmd.entry
        self.ql.dprint("[+] entry {}".format(hex(cmd.entry)))

    def loadUuid(self):
        # todo: finish
        pass

    def loadCodeSignature(self):
        # todo: finish
        pass
    
    def loadMain(self, cmd, isdyld=False):
        text_base = 0
        for seg in self.macho_file.segments:
            if seg.name == "__TEXT":
                text_base = seg.vm_address
                break
        if not isdyld:
            self.binary_entry = cmd.entry_offset + text_base 
        self.proc_entry = cmd.entry_offset + text_base 

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
        ptr = self.stack_esp

        for item in self.argvs[::-1]:
            argvs_ptr.append(ptr)   # need pack and tostring
            self.ql.dprint('[+] add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.dprint('[+] add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.dprint('[+] add apple ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        ptr = self.stack_esp
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
            self.ql.dprint("[+] esp 0x%x, content 0x%x" % (self.stack_esp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.dprint("[+] esp 0x%x, content 0x%x" % (self.stack_esp, self.argc))
        if self.using_dyld:
            ptr -= 4
            self.push_stack_addr(binary_entry)

        return self.stack_esp

    def push_stack_string(self, data):
        align = self.string_align
        length = len(data)
        if length % align != 0:
            for i in range(align - (length % align)):
                data += b'\x00' 
            length = len(data)
        self.stack_esp -= length
        self.uc.mem_write(self.stack_esp, data)
        self.ql.dprint("[+] esp {} write data len {}".format(hex(self.stack_esp), length))
        return self.stack_esp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        if data == 0:
            content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            content = pack('<Q', data)

        if len(content) != align:
            self.ql.nprint('[!] stack align error')
            return 
        
        self.stack_esp -= align
        self.uc.mem_write(self.stack_esp, content)
        return self.stack_esp
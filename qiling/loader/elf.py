#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
import os
import string
from elftools.elf.elffile import ELFFile

from qiling.const import *
from qiling.exception import *
from .loader import QlLoader
from qiling.os.linux.function_hook import FunctionHook


AT_NULL = 0
AT_IGNORE = 1
AT_EXECFD = 2
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_FLAGS = 8
AT_ENTRY = 9
AT_NOTELF = 10
AT_UID = 11
AT_EUID = 12
AT_GID = 13
AT_EGID = 14
AT_PLATFORM = 15
AT_HWCAP = 16
AT_CLKTCK = 17
AT_SECURE = 23
AT_BASE_PLATFORM = 24
AT_RANDOM = 25
AT_HWCAP2 = 26
AT_EXECFN = 31

FILE_DES = []


class ELFParse():
    def __init__(self, path, ql):
        self.path = os.path.abspath(path)
        self.ql = ql

        self.f = open(path, "rb")
        elfdata = self.f.read()
        self.elffile = ELFFile(self.f)

        self.elfdata = elfdata.ljust(52, b'\x00')        

        if self.elffile.e_ident_raw[ : 4] != b'\x7fELF':
            raise QlErrorELFFormat("[!] ERROR: NOT a ELF")

        self.elfhead = self.parse_header()

    def getelfdata(self, offest, size):
        return self.elfdata[offest : offest + size]
    
    def parse_header(self):
        return dict(self.elffile.header)

    def parse_sections(self):
        return self.elffile.iter_sections()

    def parse_segments(self):
        return self.elffile.iter_segments()


class QlLoaderELF(QlLoader, ELFParse):
    def __init__(self, ql):
        super(QlLoaderELF, self).__init__(ql)
        self.ql = ql
              
    def run(self):
        if self.ql.archbit == 32:
            stack_address = int(self.ql.os.profile.get("OS32", "stack_address"), 16)
            stack_size = int(self.ql.os.profile.get("OS32", "stack_size"), 16)
        elif self.ql.archbit == 64:
            stack_address = int(self.ql.os.profile.get("OS64", "stack_address"), 16)
            stack_size = int(self.ql.os.profile.get("OS64", "stack_size"), 16)

        if self.ql.shellcoder:
            self.ql.mem.map(self.ql.os.entry_point, self.ql.os.shellcoder_ram_size, info="[shellcode_stack]")
            self.ql.os.entry_point  = (self.ql.os.entry_point + 0x200000 - 0x1000)
            
            # for ASM file input, will mem.write in qltools
            try:
                self.ql.mem.write(self.ql.os.entry_point, self.ql.shellcoder)
            except:
                pass    
            
            self.ql.reg.arch_sp = self.ql.os.entry_point
            return
            
        self.path = self.ql.path
        ELFParse.__init__(self, self.path, self.ql)
        self.interp_address = 0
        self.mmap_address = 0
        self.argv = self.ql.argv
        self.ql.mem.map(stack_address, stack_size, info="[stack]") 
        self.load_with_ld(stack_address + stack_size, argv = self.argv, env = self.env)
        self.stack_address  = self.new_stack
        self.ql.reg.arch_sp = self.stack_address

        if self.ql.ostype == QL_OS.FREEBSD:
            init_rbp = self.stack_address + 0x40
            init_rdi = self.stack_address
            self.ql.reg.rbp = init_rbp
            self.ql.reg.rdi = init_rdi
            self.ql.reg.r14 = init_rdi

    def pack(self, data):
        if self.ql.archbit == 64:
            return self.ql.pack64(data)
        elif self.ql.archbit == 32:
            return self.ql.pack32(data)
        else:
            return self.ql.pack32(data)

    def copy_str(self, addr, l):
        l_addr = []
        s_addr = addr
        for i in l:
            s_addr = s_addr - len(i) - 1
            # if isinstance(i, bytes):
            #   self.ql.nprint(type(b'\x00'))
            #   self.ql.nprint(type(i))
            #   self.ql.nprint(i)
            #   self.ql.nprint(type(i.encode()))
            #   self.ql.nprint(type(addr))
            #   self.ql.mem.write(s_addr, i + b'\x00')
            # else:
            self.ql.mem.write(s_addr, i.encode() + b'\x00')
            l_addr.append(s_addr)
        return l_addr, s_addr

    def alignment(self, val):
        if self.ql.archbit == 64:
            return (val // 8) * 8
        elif self.ql.archbit == 32:
            return (val // 4) * 4

    def NEW_AUX_ENT(self, key, val):
        if self.ql.archbit == 32:
            return self.ql.pack32(int(key)) + self.ql.pack32(int(val))
        elif self.ql.archbit == 64:
            return self.ql.pack64(int(key)) + self.ql.pack64(int(val))

    def NullStr(self, s):
        return s[ : s.find(b'\x00')]

    def load_with_ld(self, stack_addr, load_address = -1, argv = [], env = {}):

        if load_address <= 0:
            if self.ql.archbit == 64:
                load_address = int(self.ql.os.profile.get("OS64", "load_address"), 16)
            else:
                load_address = int(self.ql.os.profile.get("OS32", "load_address"), 16)

        elfhead = super().parse_header()

        # Determine the range of memory space opened up
        mem_start = -1
        mem_end = -1
        interp_path = ''
        for i in super().parse_segments():
            i = dict(i.header)
            if i['p_type'] == 'PT_LOAD':
                if mem_start > i['p_vaddr'] or mem_start == -1:
                    mem_start = i['p_vaddr']
                if mem_end < i['p_vaddr'] + i['p_memsz'] or mem_end == -1:
                    mem_end = i['p_vaddr'] + i['p_memsz']
            if i['p_type'] == 'PT_INTERP':
                interp_path = self.NullStr(super().getelfdata(i['p_offset'], i['p_filesz']))

        mem_start = int(mem_start // 0x1000) * 0x1000
        mem_end = int(mem_end // 0x1000 + 1) * 0x1000

        if elfhead['e_type'] == 'ET_EXEC':
            load_address = 0
        elif elfhead['e_type'] != 'ET_DYN':
            self.ql.nprint("[+] Some error in head e_type: %u!" %elfhead['e_type'])
            return -1

        for i in super().parse_segments():
            i = dict(i.header)
            if i['p_type'] == 'PT_LOAD':
                _mem_s = ((load_address + i["p_vaddr"]) // 0x1000 ) * 0x1000
                _mem_e = ((load_address + i["p_vaddr"] + i["p_filesz"]) // 0x1000 + 1) * 0x1000
                _perms = int(bin(i["p_flags"])[:1:-1], 2) # reverse bits for perms mapping

                self.ql.mem.map(_mem_s, _mem_e-_mem_s, perms=_perms, info=self.path)
                self.ql.dprint(D_INFO, "[+] load 0x%x - 0x%x" % (_mem_s, _mem_e))

                self.ql.mem.write(load_address+i["p_vaddr"], super().getelfdata(i['p_offset'], i['p_filesz']))

        loaded_mem_end = load_address + mem_end
        if loaded_mem_end > _mem_e:
            
            self.ql.mem.map(_mem_e, loaded_mem_end-_mem_e, info=self.path)
            self.ql.dprint(D_INFO, "[+] load 0x%x - 0x%x" % (_mem_e, loaded_mem_end)) # make sure we map all PT_LOAD tagged area

        entry_point = elfhead['e_entry'] + load_address
        self.ql.os.elf_mem_start = mem_start
        self.ql.dprint(D_INFO, "[+] mem_start: 0x%x mem_end: 0x%x" % (mem_start, mem_end))

        self.brk_address = mem_end + load_address + 0x2000

        # Load interpreter if there is an interpreter

        if interp_path != '':
            interp_path = str(interp_path, 'utf-8', errors="ignore")
           
            interp = ELFParse(self.ql.rootfs + interp_path, self.ql)
            interphead = interp.parse_header()
            self.ql.dprint(D_INFO, "[+] interp is : %s" % (self.ql.rootfs + interp_path))

            interp_mem_size = -1
            for i in interp.parse_segments():
                i =dict(i.header)
                if i['p_type'] == 'PT_LOAD':
                    if interp_mem_size < i['p_vaddr'] + i['p_memsz'] or interp_mem_size == -1:
                        interp_mem_size = i['p_vaddr'] + i['p_memsz']

            interp_mem_size = (interp_mem_size // 0x1000 + 1) * 0x1000
            self.ql.dprint(D_INFO, "[+] interp_mem_size is : 0x%x" % int(interp_mem_size))

            if self.ql.archbit == 64:
                self.interp_address = int(self.ql.os.profile.get("OS64", "interp_address"), 16)
            elif self.ql.archbit == 32:
                self.interp_address = int(self.ql.os.profile.get("OS32", "interp_address"), 16)

            self.ql.dprint(D_INFO, "[+] interp_address is : 0x%x" % (self.interp_address))
            self.ql.mem.map(self.interp_address, int(interp_mem_size), info=os.path.abspath(self.ql.rootfs+interp_path))

            for i in interp.parse_segments():
                # i =dict(i.header)
                if i['p_type'] == 'PT_LOAD':
                    self.ql.mem.write(self.interp_address + i['p_vaddr'], interp.getelfdata(i['p_offset'], i['p_filesz']))
            entry_point = interphead['e_entry'] + self.interp_address

        # Set MMAP addr
        if self.ql.archbit == 64:
            self.mmap_address = int(self.ql.os.profile.get("OS64", "mmap_address"), 16)
        else:
            self.mmap_address = int(self.ql.os.profile.get("OS32", "mmap_address"), 16)

        self.ql.dprint(D_INFO, "[+] mmap_address is : 0x%x" % (self.mmap_address))

        # Set elf table
        elf_table = b''
        new_stack = stack_addr

        # Set argc
        #if self.ql.archbit == 32:
        #    elf_table += self.ql.pack32(len(argv))
        #else:
        elf_table += self.pack(len(argv))

        # Set argv
        if len(argv) != 0:
            argv_addr, new_stack = self.copy_str(stack_addr, argv)

            if self.ql.archbit == 32:
                elf_table += b''.join([self.ql.pack32(_) for _ in argv_addr])
            elif self.ql.archbit == 64:
                elf_table += b''.join([self.ql.pack64(_) for _ in argv_addr])

        if self.ql.archbit == 32:
            elf_table += self.ql.pack32(0)
        elif self.ql.archbit == 64:
            elf_table += self.ql.pack64(0)

        # Set env
        if len(env) != 0:
            env_addr, new_stack = self.copy_str(new_stack, [key + '=' + value for key, value in env.items()])
            if self.ql.archbit == 32:
                elf_table += b''.join([self.ql.pack32(_) for _ in env_addr])
            elif self.ql.archbit == 64:
                elf_table += b''.join([self.ql.pack64(_) for _ in env_addr])

        if self.ql.archbit == 32:
            elf_table += self.ql.pack32(0)
        elif self.ql.archbit == 64:
            elf_table += self.ql.pack64(0)

        new_stack = self.alignment(new_stack)

        randstr = 'a' * 0x10
        cpustr = 'i686'
        (addr, new_stack) = self.copy_str(new_stack, [randstr, cpustr])
        new_stack = self.alignment(new_stack)

        # Set AUX

        # self.ql.mem.write(new_stack - 4, self.ql.pack32(0x11111111))
        # new_stack = new_stack - 4
        # rand_addr = new_stack - 4

        self.elf_phdr     = (load_address + elfhead['e_phoff'])
        self.elf_phent    = (elfhead['e_phentsize'])
        self.elf_phnum    = (elfhead['e_phnum'])
        self.elf_pagesz   = 0x1000
        self.elf_guid     = self.ql.os.uid
        self.elf_flags    = 0
        self.elf_entry    = (load_address + elfhead['e_entry'])
        self.randstraddr  = addr[0]
        self.cpustraddr   = addr[1]
        if self.ql.archbit == 64:
            self.elf_hwcap = 0x078bfbfd
        elif self.ql.archbit == 32:
            self.elf_hwcap = 0x1fb8d7
            if self.ql.archendian == QL_ENDIAN.EB:
                self.elf_hwcap = 0xd7b81f

        elf_table += self.NEW_AUX_ENT(AT_PHDR, self.elf_phdr + mem_start)
        elf_table += self.NEW_AUX_ENT(AT_PHENT, self.elf_phent)
        elf_table += self.NEW_AUX_ENT(AT_PHNUM, self.elf_phnum)
        elf_table += self.NEW_AUX_ENT(AT_PAGESZ, self.elf_pagesz)
        elf_table += self.NEW_AUX_ENT(AT_BASE, self.interp_address)
        elf_table += self.NEW_AUX_ENT(AT_FLAGS, self.elf_flags)
        elf_table += self.NEW_AUX_ENT(AT_ENTRY, self.elf_entry)
        elf_table += self.NEW_AUX_ENT(AT_UID, self.elf_guid)
        elf_table += self.NEW_AUX_ENT(AT_EUID, self.elf_guid)
        elf_table += self.NEW_AUX_ENT(AT_GID, self.elf_guid)
        elf_table += self.NEW_AUX_ENT(AT_EGID, self.elf_guid)
        elf_table += self.NEW_AUX_ENT(AT_HWCAP, self.elf_hwcap)
        elf_table += self.NEW_AUX_ENT(AT_CLKTCK, 100)
        elf_table += self.NEW_AUX_ENT(AT_RANDOM, self.randstraddr)
        elf_table += self.NEW_AUX_ENT(AT_PLATFORM, self.cpustraddr)
        elf_table += self.NEW_AUX_ENT(AT_SECURE, 0)
        elf_table += self.NEW_AUX_ENT(AT_NULL, 0)
        elf_table += b'\x00' * (0x10 - (new_stack - len(elf_table)) & 0xf)

        self.ql.mem.write(new_stack - len(elf_table), elf_table)
        new_stack = new_stack - len(elf_table)

        # self.ql.reg.write(UC_X86_REG_RDI, new_stack + 8)

        # for i in range(120):
        #     buf = self.ql.mem.read(new_stack + i * 0x8, 8)
        #     self.ql.nprint("0x%08x : 0x%08x " % (new_stack + i * 0x4, self.ql.unpack64(buf)) + ' '.join(['%02x' % i for i in buf]) + '  ' + ''.join([chr(i) if i in string.printable[ : -5].encode('ascii') else '.' for i in buf]))
        
        self.ql.os.entry_point = self.entry_point = entry_point
        self.ql.os.elf_entry = self.elf_entry = load_address + elfhead['e_entry']
        self.new_stack = new_stack
        self.load_address = load_address
        self.images.append(self.coverage_image(load_address, load_address + mem_end, self.path))
        self.ql.os.function_hook = FunctionHook(self.ql, self.elf_phdr + mem_start, self.elf_phnum, self.elf_phent, load_address, load_address + mem_end)

        # map vsyscall section for some specific needs
        if self.ql.archtype == QL_ARCH.X8664 and self.ql.ostype == QL_OS.LINUX:
            _vsyscall_addr = int(self.ql.os.profile.get("OS64", "vsyscall_address"), 16)
            _vsyscall_size = int(self.ql.os.profile.get("OS64", "vsyscall_size"), 16)

            if not self.ql.mem.is_mapped(_vsyscall_addr, _vsyscall_size):
                # initialize with \xcc then insert syscall entry
                # each syscall should be 1KiB(0x400 bytes) away
                self.ql.mem.map(_vsyscall_addr, _vsyscall_size, info="[vsyscall]")
                self.ql.mem.write(_vsyscall_addr, _vsyscall_size * b'\xcc')

                def _compile(asm):
                    return self.ql.compile(self.ql.archtype, asm)

                _vsyscall_entry_asm = [ "mov rax, 0x60;",  # syscall gettimeofday
                                        "mov rax, 0xc9;",  # syscall time
                                        "mov rax, 0x135;", # syscall getcpu
                                       ]

                for idx, val in enumerate(_vsyscall_entry_asm):
                    self.ql.mem.write(_vsyscall_addr + idx * 0x400, _compile(val + "; syscall; ret"))

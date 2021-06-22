#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from heapq import heappush, heappop

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_reloc_type

from qiling.const import *

from qiling.exception import *
from .loader import QlLoader, Image
from qiling.os.linux.function_hook import FunctionHook
from qiling.os.linux.syscall_nums import SYSCALL_NR
from qiling.os.linux.kernel_api.hook import *
from qiling.os.linux.kernel_api.kernel_api import hook_sys_open, hook_sys_read, hook_sys_write

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

# start area memory for API hooking
# we will reserve 0x1000 bytes for this (which contains multiple slots of 4/8 bytes, each for one api)
API_HOOK_MEM = 0x1000000

# SYSCALL_MEM = 0xffff880000000000
# memory for syscall table
SYSCALL_MEM = API_HOOK_MEM + 0x1000


class ELFParse():
    def __init__(self, path, ql):
        self.path = os.path.abspath(path)
        self.ql = ql

        self.f = open(path, "rb")
        elfdata = self.f.read()
        self.elffile = ELFFile(self.f)

        self.elfdata = elfdata.ljust(52, b'\x00')

        if self.elffile.e_ident_raw[: 4] != b'\x7fELF':
            raise QlErrorELFFormat("ERROR: NOT a ELF")

        self.elfhead = self.parse_header()
        if self.elfhead['e_type'] == "ET_REL":  # kernel driver
            self.is_driver = True
        else:
            self.is_driver = False

    def getelfdata(self, offest, size):
        return self.elfdata[offest: offest + size]

    def parse_header(self):
        return dict(self.elffile.header)

    def parse_sections(self):
        return self.elffile.iter_sections()

    def parse_segments(self):
        return self.elffile.iter_segments()

    def translate_segment_perm_to_uc_prot(self, perm):
        """
        Unicorn define the following memory protection constants :

        'Public Enum uc_prot
        '    UC_PROT_NONE = 0
        '    UC_PROT_READ = 1
        '    UC_PROT_WRITE = 2
        '    UC_PROT_EXEC = 4
        '    UC_PROT_ALL = 7
        'End Enum

        Elf segment permissions are the following
            * bit 0 : X
            * bit 1 : W
            * bit 2 : R
        """

        prot = 0

        if perm & 0x1:
            prot |= 4
        if (perm >> 1) & 0x1:
            prot |= 2
        if (perm >> 2) & 0x1:
            prot |= 1

        return prot

class QlLoaderELF(QlLoader, ELFParse):
    def __init__(self, ql):
        super(QlLoaderELF, self).__init__(ql)
        self.ql = ql

    def run(self):
        if self.ql.code:
            self.ql.mem.map(self.ql.os.entry_point, self.ql.os.code_ram_size, info="[shellcode_stack]")
            self.ql.os.entry_point = (self.ql.os.entry_point + 0x200000 - 0x1000)
            self.ql.mem.write(self.ql.os.entry_point, self.ql.code)
            self.ql.reg.arch_sp = self.ql.os.entry_point
            return

        if self.ql.archbit == 32:
            stack_address = int(self.ql.os.profile.get("OS32", "stack_address"), 16)
            stack_size = int(self.ql.os.profile.get("OS32", "stack_size"), 16)
        elif self.ql.archbit == 64:
            stack_address = int(self.ql.os.profile.get("OS64", "stack_address"), 16)
            stack_size = int(self.ql.os.profile.get("OS64", "stack_size"), 16)

        self.path = self.ql.path
        ELFParse.__init__(self, self.path, self.ql)
        self.interp_address = 0
        self.mmap_address = 0
        self.ql.mem.map(stack_address, stack_size, info="[stack]")

        # if self.ql.ostype == QL_OS.FREEBSD:
        #     init_rbp = stack_address + 0x40
        #     init_rdi = stack_address
        #     self.ql.reg.rbp = init_rbp
        #     self.ql.reg.rdi = init_rdi
        #     self.ql.reg.r14 = init_rdi

        if not self.is_driver:
            self.load_with_ld(stack_address + stack_size, argv=self.argv, env=self.env)
        else:

            # Linux kernel driver
            if self.load_driver(self.ql, stack_address + stack_size):
                raise QlErrorFileType("Unsupported FileType")
            # hook Linux kernel api
            self.ql.hook_code(hook_kernel_api)

        self.ql.reg.arch_sp = self.stack_address
        self.ql.os.stack_address = self.stack_address
        
        # No idea why.
        if self.ql.ostype == QL_OS.FREEBSD:
            self.ql.reg.rdi = self.stack_address
            self.ql.reg.r14 = self.stack_address

    # Copy strings to stack.
    def copy_str(self, addr, strs):
        l_addr = []
        s_addr = addr
        for s in strs:
            bs = s.encode("utf-8") + b"\x00" if not isinstance(s, bytes) else s
            s_addr = s_addr - len(bs)
            self.ql.mem.write(s_addr, bs)
            l_addr.append(s_addr)
        return l_addr, s_addr

    def alignment(self, val):
        if self.ql.archbit == 64:
            return (val // 8) * 8
        elif self.ql.archbit == 32:
            return (val // 4) * 4

    def NEW_AUX_ENT(self, key, val):
        return self.ql.pack(int(key)) + self.ql.pack(int(val))

    def NullStr(self, s):
        return s[: s.find(b'\x00')]

    def pcalc(self, length, align):
        tmp = length // align
        if length % align:
            tmp = tmp + 1
        return tmp * align

    def load_with_ld(self, stack_addr, load_address=-1, argv=[], env={}):
        pagesize = 0x1000
        _mem_e = 0

        if load_address <= 0:
            if self.ql.archbit == 64:
                load_address = int(self.ql.os.profile.get("OS64", "load_address"), 16)
            else:
                load_address = int(self.ql.os.profile.get("OS32", "load_address"), 16)

        elfhead = super().parse_header()

        # Correct the load_address if needed
        if elfhead['e_type'] == 'ET_EXEC':
            load_address = 0
        elif elfhead['e_type'] != 'ET_DYN':
            self.ql.log.debug("Some error in head e_type: %i!", elfhead['e_type'])
            return -1

        # We need to sort the memory segments first, sometimes they are unordered
        loadheap = []
        for entry in super().parse_segments():
            if entry['p_type'] == 'PT_LOAD' or entry['p_type'] == 'PT_INTERP':
                paddr = entry['p_vaddr']
                heappush(loadheap, (paddr, entry))
        loaddb = [dict(heappop(loadheap)[1].header) for i in range(len(loadheap))]

        # Determine the range of memory space opened up
        mem_start = -1
        mem_end = -1
        interp_path = ''
        for entry in loaddb:
            if entry['p_type'] == 'PT_LOAD':
                if mem_start > entry['p_vaddr'] or mem_start == -1:
                    mem_start = entry['p_vaddr']
                if mem_end < entry['p_vaddr'] + entry['p_memsz'] or mem_end == -1:
                    mem_end = entry['p_vaddr'] + entry['p_memsz']
            if entry['p_type'] == 'PT_INTERP':
                interp_path = self.NullStr(super().getelfdata(entry['p_offset'], entry['p_filesz']))

        mem_start = int(mem_start // 0x1000) * 0x1000
        mem_end = int(mem_end // 0x1000 + 1) * 0x1000

        # Now we calculate the segments based on page alignment
        _load_segments = {}
        _last_start = 0
        _last_end = 0
        _last_perm = 0
        for entry in loaddb:
            if entry['p_type'] == 'PT_LOAD':
                _mem_start = ((load_address + entry["p_vaddr"]) // pagesize) * pagesize
                _mem_len = entry['p_memsz']
                _mem_end = self.pcalc(load_address + entry["p_vaddr"] + _mem_len, pagesize)
                _perms = self.translate_segment_perm_to_uc_prot(entry["p_flags"])
                if _last_end < _mem_start:
                    _load_segments[_mem_start] = _mem_end, _perms
                    _last_start = _mem_start
                elif _perms == _last_perm:
                    _load_segments[_last_start] = _mem_end, _perms
                elif _last_end == _mem_start:
                    _load_segments[_mem_start] = _mem_end, _perms
                    _last_start = _mem_start
                elif _mem_start<_last_end:
                    _load_segments[_last_start]=_mem_end,_perms
                _last_end = _mem_end
                _last_perm = _perms


        # Let's map the memory first
        _highestmapped_e = 0
        for segment in _load_segments:
            _mem_s = segment
            _mem_e = _load_segments[segment][0]
            _perms = _load_segments[segment][1] & 0xFF
            try:
                self.ql.mem.map(_mem_s, _mem_e - _mem_s, perms=_perms, info=self.path)
                if _mem_e > _highestmapped_e:
                    _highestmapped_e = _mem_e
                self.ql.log.debug("load 0x%x - 0x%x" % (_mem_s, _mem_e))
            except Exception as e:
                self.ql.log.debug("load 0x%x - 0x%x => %s" % (_mem_s, _mem_e, str(e)))
                continue

        # Now we write the segment data to the memory
        for entry in loaddb:
            if entry['p_type'] == 'PT_LOAD' and entry['p_filesz'] > 0:
                try:
                    _mem_s = load_address + entry["p_vaddr"]
                    data = super().getelfdata(entry['p_offset'], entry['p_filesz'])
                    self.ql.mem.write(_mem_s, data)
                except Exception as e:
                    self.ql.log.debug("segment data 0x%x - Length 0x%x => %s" % (_mem_s, len(data), str(e)))
                    continue

        loaded_mem_end = load_address + mem_end
        if loaded_mem_end > _mem_e:
            self.ql.mem.map(_mem_e, loaded_mem_end - _mem_e, info=self.path)
            self.ql.log.debug("load 0x%x - 0x%x" % (
            _mem_e, loaded_mem_end))  # make sure we map all PT_LOAD tagged area

        entry_point = elfhead['e_entry'] + load_address
        self.ql.os.elf_mem_start = mem_start
        self.ql.log.debug("mem_start: 0x%x mem_end: 0x%x" % (mem_start, mem_end))

        self.brk_address = mem_end + load_address + 0x2000

        # Load interpreter if there is an interpreter

        if interp_path != '':
            interp_path = str(interp_path, 'utf-8', errors="ignore")

            interp = ELFParse(self.ql.rootfs + interp_path, self.ql)
            interphead = interp.parse_header()
            self.ql.log.debug("interp is : %s" % (self.ql.rootfs + interp_path))

            interp_mem_size = -1
            for i in interp.parse_segments():
                i = dict(i.header)
                if i['p_type'] == 'PT_LOAD':
                    if interp_mem_size < i['p_vaddr'] + i['p_memsz'] or interp_mem_size == -1:
                        interp_mem_size = i['p_vaddr'] + i['p_memsz']

            interp_mem_size = (interp_mem_size // 0x1000 + 1) * 0x1000
            self.ql.log.debug("interp_mem_size is : 0x%x" % int(interp_mem_size))

            if self.ql.archbit == 64:
                self.interp_address = int(self.ql.os.profile.get("OS64", "interp_address"), 16)
            elif self.ql.archbit == 32:
                self.interp_address = int(self.ql.os.profile.get("OS32", "interp_address"), 16)

            self.ql.log.debug("interp_address is : 0x%x" % (self.interp_address))
            self.ql.mem.map(self.interp_address, int(interp_mem_size),
                            info=os.path.abspath(self.ql.rootfs + interp_path))

            for i in interp.parse_segments():
                # i =dict(i.header)
                if i['p_type'] == 'PT_LOAD':
                    self.ql.mem.write(self.interp_address + i['p_vaddr'],
                                      interp.getelfdata(i['p_offset'], i['p_filesz']))
            entry_point = interphead['e_entry'] + self.interp_address

        # Set MMAP addr
        if self.ql.archbit == 64:
            self.mmap_address = int(self.ql.os.profile.get("OS64", "mmap_address"), 16)
        else:
            self.mmap_address = int(self.ql.os.profile.get("OS32", "mmap_address"), 16)

        self.ql.log.debug("mmap_address is : 0x%x" % (self.mmap_address))

        # Set elf table
        elf_table = b''
        new_stack = stack_addr

        # Set argc
        elf_table += self.ql.pack(len(argv))

        # Set argv
        if len(argv) != 0:
            argv_addr, new_stack = self.copy_str(stack_addr, argv)
            elf_table += b''.join([self.ql.pack(_) for _ in argv_addr])

        elf_table += self.ql.pack(0)

        # Set env
        if len(env) != 0:
            env_addr, new_stack = self.copy_str(new_stack, [key + '=' + value for key, value in env.items()])
            elf_table += b''.join([self.ql.pack(_) for _ in env_addr])

        elf_table += self.ql.pack(0)

        new_stack = self.alignment(new_stack)
        randstr = 'a' * 0x10
        cpustr = 'i686'
        (addr, new_stack) = self.copy_str(new_stack, [randstr, cpustr])
        new_stack = self.alignment(new_stack)

        # Set AUX
        self.elf_phdr = (load_address + elfhead['e_phoff'])
        self.elf_phent = (elfhead['e_phentsize'])
        self.elf_phnum = (elfhead['e_phnum'])
        self.elf_pagesz = 0x1000
        self.elf_guid = self.ql.os.uid
        self.elf_flags = 0
        self.elf_entry = (load_address + elfhead['e_entry'])
        self.randstraddr = addr[0]
        self.cpustraddr = addr[1]
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
        #     self.ql.log.info("0x%08x : 0x%08x " % (new_stack + i * 0x4, self.ql.unpack64(buf)) + ' '.join(['%02x' % i for i in buf]) + '  ' + ''.join([chr(i) if i in string.printable[ : -5].encode('ascii') else '.' for i in buf]))

        self.ql.os.entry_point = self.entry_point = entry_point
        self.ql.os.elf_entry = self.elf_entry = load_address + elfhead['e_entry']
        self.stack_address = new_stack
        self.load_address = load_address
        self.images.append(Image(load_address, load_address + mem_end, self.path))
        self.ql.os.function_hook = FunctionHook(self.ql, self.elf_phdr + mem_start, self.elf_phnum, self.elf_phent,
                                                load_address, load_address + mem_end)
        self.init_sp = self.ql.reg.arch_sp

        # If there is a loader, we ignore exit
        self.skip_exit_check = self.elf_entry != self.entry_point

        # map vsyscall section for some specific needs
        if self.ql.archtype == QL_ARCH.X8664 and self.ql.ostype == QL_OS.LINUX:
            _vsyscall_addr = int(self.ql.os.profile.get("OS64", "vsyscall_address"), 16)
            _vsyscall_size = int(self.ql.os.profile.get("OS64", "vsyscall_size"), 16)

            if not self.ql.mem.is_mapped(_vsyscall_addr, _vsyscall_size):
                # initialize with \xcc then insert syscall entry
                # each syscall should be 1KiB(0x400 bytes) away
                self.ql.mem.map(_vsyscall_addr, _vsyscall_size, info="[vsyscall]")
                self.ql.mem.write(_vsyscall_addr, _vsyscall_size * b'\xcc')
                assembler = self.ql.create_assembler()

                def _compile(asm):
                    bs, _ = assembler.asm(asm)
                    return bytes(bs)

                _vsyscall_entry_asm = ["mov rax, 0x60;",  # syscall gettimeofday
                                       "mov rax, 0xc9;",  # syscall time
                                       "mov rax, 0x135;",  # syscall getcpu
                                       ]

                for idx, val in enumerate(_vsyscall_entry_asm):
                    self.ql.mem.write(_vsyscall_addr + idx * 0x400, _compile(val + "; syscall; ret"))

    # get file offset of init module function
    def lkm_get_init(self, ql):
        elffile = ELFFile(open(ql.path, 'rb'))
        symbol_tables = [s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)]
        for section in symbol_tables:
            for nsym, symbol in enumerate(section.iter_symbols()):
                if symbol.name == 'init_module':
                    addr = symbol.entry.st_value + elffile.get_section(symbol['st_shndx'])['sh_offset']
                    ql.log.info("init_module = 0x%x" % addr)
                    return addr

        # not found. FIXME: report error on invalid module??
        ql.log.warning("invalid module? symbol init_module not found")
        return -1

    def lkm_dynlinker(self, ql, mem_start):
        def get_symbol(elffile, name):
            section = elffile.get_section_by_name('.symtab')
            for symbol in section.iter_symbols():
                if symbol.name == name:
                    return symbol
            return None

        elffile = ELFFile(open(ql.path, 'rb'))

        all_symbols = []
        self.ql.os.hook_addr = API_HOOK_MEM
        # map address to symbol name
        self.import_symbols = {}
        # reverse dictionary to map symbol name -> address
        rev_reloc_symbols = {}

        # dump_mem("XX Original code at 15a1 = ", ql.mem.read(0x15a1, 8))
        _sections = list(elffile.iter_sections())
        for section in _sections:
            # only care about reloc section
            if not isinstance(section, RelocationSection):
                continue

            # ignore reloc for module section
            if section.name == ".rela.gnu.linkonce.this_module":
                continue

            dest_sec_idx = section.header.get('sh_info', None)
            if dest_sec_idx is not None and dest_sec_idx < len(_sections):
                dest_sec = _sections[dest_sec_idx]
                if dest_sec.header['sh_flags'] & 2 == 0:
                    # The target section is not loaded into memory, so just continue
                    continue

            # The symbol table section pointed to in sh_link
            symtable = elffile.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_sym'] == 0:
                    continue

                symbol = symtable.get_symbol(rel['r_info_sym'])

                # Some symbols have zero 'st_name', so instead what's used is
                # the name of the section they point at.
                if symbol['st_name'] == 0:
                    symsec = elffile.get_section(symbol['st_shndx'])  # save sh_addr of this section
                    symbol_name = symsec.name
                    sym_offset = symsec['sh_offset']
                    # we need to do reverse lookup from symbol to address
                    rev_reloc_symbols[symbol_name] = sym_offset + mem_start
                else:
                    symbol_name = symbol.name
                    # get info about related section to be patched
                    info_section = elffile.get_section(section['sh_info'])
                    sym_offset = info_section['sh_offset']

                    if not symbol_name in all_symbols:
                        _symbol = get_symbol(elffile, symbol_name)
                        if _symbol['st_shndx'] == 'SHN_UNDEF':
                            # external symbol
                            # only save symbols of APIs
                            all_symbols.append(symbol_name)
                            # we need to lookup from address to symbol, so we can find the right callback
                            # for sys_xxx handler for syscall, the address must be aligned to 8
                            if symbol_name.startswith('sys_'):
                                if self.ql.os.hook_addr % self.ql.pointersize != 0:
                                    self.ql.os.hook_addr = (int(
                                        self.ql.os.hook_addr / self.ql.pointersize) + 1) * self.ql.pointersize
                                    # print("hook_addr = %x" %self.ql.os.hook_addr)
                            self.import_symbols[self.ql.os.hook_addr] = symbol_name
                            # ql.log.info(":: Demigod is hooking %s(), at slot %x" %(symbol_name, self.ql.os.hook_addr))

                            if symbol_name == "page_offset_base":
                                # FIXME: this is for rootkit to scan for syscall table from page_offset_base
                                # write address of syscall table to this slot,
                                # so syscall scanner can quickly find it
                                ql.mem.write(self.ql.os.hook_addr, self.ql.pack(SYSCALL_MEM))

                            # we also need to do reverse lookup from symbol to address
                            rev_reloc_symbols[symbol_name] = self.ql.os.hook_addr
                            sym_offset = self.ql.os.hook_addr - mem_start
                            self.ql.os.hook_addr += self.ql.pointersize
                        else:
                            # local symbol
                            all_symbols.append(symbol_name)
                            _section = elffile.get_section(_symbol['st_shndx'])
                            rev_reloc_symbols[symbol_name] = _section['sh_offset'] + _symbol['st_value'] + mem_start
                            # ql.log.info(":: Add reverse lookup for %s to %x (%x, %x)" %(symbol_name, rev_reloc_symbols[symbol_name], _section['sh_offset'], _symbol['st_value']))
                            # ql.log.info(":: Add reverse lookup for %s to %x" %(symbol_name, rev_reloc_symbols[symbol_name]))
                    else:
                        sym_offset = rev_reloc_symbols[symbol_name] - mem_start

                # ql.log.info("Relocating symbol %s -> 0x%x" %(symbol_name, rev_reloc_symbols[symbol_name]))

                loc = elffile.get_section(section['sh_info'])['sh_offset'] + rel['r_offset']
                loc += mem_start

                if describe_reloc_type(rel['r_info_type'], elffile) in ('R_X86_64_32S', 'R_X86_64_32'):
                    # patch this reloc
                    if rel['r_addend']:
                        val = sym_offset + rel['r_addend']
                        val += mem_start
                        # ql.log.info('R_X86_64_32S %s: [0x%x] = 0x%x' %(symbol_name, loc, val & 0xFFFFFFFF))
                        ql.mem.write(loc, ql.pack32(val & 0xFFFFFFFF))
                    else:
                        # print("sym_offset = %x, rel = %x" %(sym_offset, rel['r_addend']))
                        # ql.log.info('R_X86_64_32S %s: [0x%x] = 0x%x' %(symbol_name, loc, rev_reloc_symbols[symbol_name] & 0xFFFFFFFF))
                        ql.mem.write(loc, ql.pack32(rev_reloc_symbols[symbol_name] & 0xFFFFFFFF))

                elif describe_reloc_type(rel['r_info_type'], elffile) == 'R_X86_64_64':
                    # patch this function?
                    val = sym_offset + rel['r_addend']
                    val += 0x2000000  # init_module position: FIXME
                    # finally patch this reloc
                    # ql.log.info('R_X86_64_64 %s: [0x%x] = 0x%x' %(symbol_name, loc, val))
                    ql.mem.write(loc, ql.pack64(val))

                elif describe_reloc_type(rel['r_info_type'], elffile) == 'R_X86_64_PC64':
                    val = rel['r_addend'] - loc
                    val += rev_reloc_symbols[symbol_name]
                    ql.mem.write(loc, ql.pack64(val))

                elif describe_reloc_type(rel['r_info_type'], elffile) in ('R_X86_64_PC32', 'R_X86_64_PLT32'):
                    # patch branch address: X86 case
                    val = rel['r_addend'] - loc
                    val += rev_reloc_symbols[symbol_name]
                    # finally patch this reloc
                    # ql.log.info('R_X86_64_PC32 %s: [0x%x] = 0x%x' %(symbol_name, loc, val & 0xFFFFFFFF))
                    ql.mem.write(loc, ql.pack32(val & 0xFFFFFFFF))

                elif describe_reloc_type(rel['r_info_type'], elffile) in ('R_386_PC32', 'R_386_PLT32'):
                    val = ql.unpack(ql.mem.read(loc, 4))
                    val = rev_reloc_symbols[symbol_name] + val - loc
                    ql.mem.write(loc, ql.pack32(val & 0xFFFFFFFF))

                elif describe_reloc_type(rel['r_info_type'], elffile) in ('R_386_32', 'R_MIPS_32'):
                    val = ql.unpack(ql.mem.read(loc, 4))
                    val = rev_reloc_symbols[symbol_name] + val
                    ql.mem.write(loc, ql.pack32(val & 0xFFFFFFFF))

                elif describe_reloc_type(rel['r_info_type'], elffile) == 'R_MIPS_HI16':
                    # actual relocation is done in R_MIPS_LO16
                    prev_mips_hi16_loc = loc

                elif describe_reloc_type(rel['r_info_type'], elffile) == 'R_MIPS_LO16':
                    val = ql.unpack16(ql.mem.read(prev_mips_hi16_loc + 2, 2)) << 16 | ql.unpack16(ql.mem.read(loc + 2, 2))
                    val = rev_reloc_symbols[symbol_name] + val
                    # *(word)(mips_lo16_loc + 2) is treated as signed
                    if (val & 0xFFFF) >= 0x8000:
                        val += (1 << 16)

                    ql.mem.write(prev_mips_hi16_loc + 2, ql.pack16(val >> 16))
                    ql.mem.write(loc + 2, ql.pack16(val & 0xFFFF))

                else:
                    raise QlErrorNotImplemented("Relocation type %s not implemented" % describe_reloc_type(rel['r_info_type'], elffile))

        return rev_reloc_symbols

    def load_driver(self, ql, stack_addr, loadbase=0):
        elfhead = super().parse_header()
        elfdata_mapping = self.get_elfdata_mapping()

        # Determine the range of memory space opened up
        mem_start = -1
        mem_end = -1

        # for i in super().parse_program_header(ql):
        #     if i['p_type'] == PT_LOAD:
        #         if mem_start > i['p_vaddr'] or mem_start == -1:
        #             mem_start = i['p_vaddr']
        #         if mem_end < i['p_vaddr'] + i['p_memsz'] or mem_end == -1:
        #             mem_end = i['p_vaddr'] + i['p_memsz']

        # mem_start = int(mem_start // 0x1000) * 0x1000
        # mem_end = int(mem_end // 0x1000 + 1) * 0x1000

        # FIXME
        mem_start = 0x1000
        mem_end = mem_start + int(len(elfdata_mapping) / 0x1000 + 1) * 0x1000

        # map some memory to intercept external functions of Linux kernel
        ql.mem.map(API_HOOK_MEM, 0x1000, info="[api_mem]")

        ql.log.info("loadbase: %x, mem_start: %x, mem_end: %x" % (loadbase, mem_start, mem_end))
        ql.mem.map(loadbase + mem_start, mem_end - mem_start, info=ql.path)
        ql.mem.write(loadbase + mem_start, elfdata_mapping)

        entry_point = self.lkm_get_init(ql) + loadbase + mem_start
        ql.brk_address = mem_end + loadbase

        # Set MMAP addr
        if self.ql.archbit == 64:
            self.mmap_address = int(self.ql.os.profile.get("OS64", "mmap_address"), 16)
        else:
            self.mmap_address = int(self.ql.os.profile.get("OS32", "mmap_address"), 16)

        ql.log.debug("mmap_address is : 0x%x" % (self.mmap_address))

        new_stack = stack_addr
        new_stack = self.alignment(new_stack)

        # self.ql.os.elf_entry = self.elf_entry = loadbase + elfhead['e_entry']
        self.ql.os.entry_point = self.entry_point = entry_point
        self.elf_entry = self.ql.os.elf_entry = self.ql.os.entry_point

        self.stack_address = new_stack
        self.load_address = loadbase

        rev_reloc_symbols = self.lkm_dynlinker(ql, mem_start + loadbase)

        # remember address of syscall table, so external tools can access to it
        ql.os.syscall_addr = SYSCALL_MEM
        # setup syscall table
        ql.mem.map(SYSCALL_MEM, 0x1000, info="[syscall_mem]")
        # zero out syscall table memory
        ql.mem.write(SYSCALL_MEM, b'\x00' * 0x1000)

        # print("sys_close = %x" %rev_reloc_symbols['sys_close'])
        # print(rev_reloc_symbols.keys())
        for sc in rev_reloc_symbols.keys():
            if sc != 'sys_call_table' and sc.startswith('sys_'):
                tmp_sc = sc[4:]
                if hasattr(SYSCALL_NR, tmp_sc):
                    syscall_id = getattr(SYSCALL_NR, tmp_sc).value
                    ql.log.debug("Writing syscall %s to [0x%x]" % (sc, SYSCALL_MEM + ql.pointersize * syscall_id))
                    ql.mem.write(SYSCALL_MEM + ql.pointersize * syscall_id, ql.pack(rev_reloc_symbols[sc]))

        # write syscall addresses into syscall table
        # ql.mem.write(SYSCALL_MEM + 0, struct.pack("<Q", hook_sys_read))
        ql.mem.write(SYSCALL_MEM + 0, ql.pack(self.ql.os.hook_addr))
        # ql.mem.write(SYSCALL_MEM + 1  * 8, struct.pack("<Q", hook_sys_write))
        ql.mem.write(SYSCALL_MEM + 1 * ql.pointersize, ql.pack(self.ql.os.hook_addr + 1 * ql.pointersize))
        # ql.mem.write(SYSCALL_MEM + 2  * 8, struct.pack("<Q", hook_sys_open))
        ql.mem.write(SYSCALL_MEM + 2 * ql.pointersize, ql.pack(self.ql.os.hook_addr + 2 * ql.pointersize))

        # setup hooks for read/write/open syscalls
        self.import_symbols[self.ql.os.hook_addr] = hook_sys_read
        self.import_symbols[self.ql.os.hook_addr + 1 * ql.pointersize] = hook_sys_write
        self.import_symbols[self.ql.os.hook_addr + 2 * ql.pointersize] = hook_sys_open

    def get_elfdata_mapping(self):
        elfdata_mapping = bytearray()
        elfdata_mapping.extend(self.getelfdata(0, self.elfhead['e_ehsize']))    #elf header

        for section in self.parse_sections():
            if section.header['sh_flags'] & 2:      # alloc flag
                sh_offset = section.header['sh_offset']
                sh_size = section.header['sh_size']

                # align section addr
                elfdata_len = len(elfdata_mapping)
                if elfdata_len < sh_offset:
                    elfdata_mapping.extend(b'\x00' * (sh_offset - elfdata_len))

                if section.header['sh_type'] == 'SHT_NOBITS':
                    elfdata_mapping.extend(b'\x00' * sh_size)
                else:
                    elfdata_mapping.extend(self.getelfdata(sh_offset, sh_size))

        return bytes(elfdata_mapping)

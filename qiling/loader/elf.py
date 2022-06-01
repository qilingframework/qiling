#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import io
import os

from enum import IntEnum
from typing import Optional, Sequence, Mapping, Tuple

from elftools.common.utils import preserve_stream_pos
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationHandler
from elftools.elf.sections import Symbol, SymbolTableSection
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.segments import InterpSegment
from unicorn.unicorn_const import UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN, QL_OS
from qiling.exception import QlErrorELFFormat, QlMemoryMappedError
from qiling.loader.loader import QlLoader, Image
from qiling.os.linux.function_hook import FunctionHook
from qiling.os.linux.syscall_nums import SYSCALL_NR
from qiling.os.linux.kernel_api.hook import *
from qiling.os.linux.kernel_api.kernel_api import hook_sys_open, hook_sys_read, hook_sys_write

# auxiliary vector types
# see: https://man7.org/linux/man-pages/man3/getauxval.3.html
class AUXV(IntEnum):
    AT_NULL     = 0
    AT_IGNORE   = 1
    AT_EXECFD   = 2
    AT_PHDR     = 3
    AT_PHENT    = 4
    AT_PHNUM    = 5
    AT_PAGESZ   = 6
    AT_BASE     = 7
    AT_FLAGS    = 8
    AT_ENTRY    = 9
    AT_NOTELF   = 10
    AT_UID      = 11
    AT_EUID     = 12
    AT_GID      = 13
    AT_EGID     = 14
    AT_PLATFORM = 15
    AT_HWCAP    = 16
    AT_CLKTCK   = 17
    AT_SECURE   = 23
    AT_BASE_PLATFORM = 24
    AT_RANDOM   = 25
    AT_HWCAP2   = 26
    AT_EXECFN   = 31

# start area memory for API hooking
# we will reserve 0x1000 bytes for this (which contains multiple slots of 4/8 bytes, each for one api)
API_HOOK_MEM = 0x1000000

# memory for syscall table
SYSCALL_MEM = API_HOOK_MEM + 0x1000

class QlLoaderELF(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

    def run(self):
        if self.ql.code:
            self.ql.mem.map(self.ql.os.entry_point, self.ql.os.code_ram_size, info="[shellcode_stack]")

            shellcode_base = self.ql.os.entry_point + 0x200000 - 0x1000
            self.ql.mem.write(shellcode_base, self.ql.code)

            self.ql.arch.regs.arch_sp = shellcode_base
            self.ql.os.entry_point = shellcode_base
            self.load_address = shellcode_base

            return

        section = {
            32 : 'OS32',
            64 : 'OS64'
        }[self.ql.arch.bits]

        self.profile = self.ql.os.profile[section]

        # setup program stack
        stack_address = int(self.profile.get('stack_address'), 0)
        stack_size = int(self.profile.get('stack_size'), 0)
        self.ql.mem.map(stack_address, stack_size, info='[stack]')

        self.path = self.ql.path

        with open(self.path, 'rb') as infile:
            fstream = io.BytesIO(infile.read())

        elffile = ELFFile(fstream)
        elftype = elffile['e_type']

        # is it a driver?
        if elftype == 'ET_REL':
            self.load_driver(elffile, stack_address + stack_size)
            self.ql.hook_code(hook_kernel_api)

        # is it an executable?
        elif elftype == 'ET_EXEC':
            load_address = 0

            self.load_with_ld(elffile, stack_address + stack_size, load_address, self.argv, self.env)

        # is it a shared object?
        elif elftype == 'ET_DYN':
            load_address = int(self.profile.get('load_address'), 0)

            self.load_with_ld(elffile, stack_address + stack_size, load_address, self.argv, self.env)

        else:
            raise QlErrorELFFormat(f'unexpected elf type value (e_type = {elftype})')

        self.is_driver = (elftype == 'ET_REL')

        self.ql.arch.regs.arch_sp = self.stack_address

        # No idea why.
        if self.ql.os.type == QL_OS.FREEBSD:
            # self.ql.arch.regs.rbp = self.stack_address + 0x40
            self.ql.arch.regs.rdi = self.stack_address
            self.ql.arch.regs.r14 = self.stack_address

    @staticmethod
    def seg_perm_to_uc_prot(perm: int) -> int:
        """Translate ELF segment perms to Unicorn protection constants.
        """

        prot = UC_PROT_NONE

        if perm & P_FLAGS.PF_X:
            prot |= UC_PROT_EXEC

        if perm & P_FLAGS.PF_W:
            prot |= UC_PROT_WRITE

        if perm & P_FLAGS.PF_R:
            prot |= UC_PROT_READ

        return prot

    def load_with_ld(self, elffile: ELFFile, stack_addr: int, load_address: int, argv: Sequence[str] = [], env: Mapping[str, str] = {}):

        def load_elf_segments(elffile: ELFFile, load_address: int, info: str):
            # get list of loadable segments; these segments will be loaded to memory
            load_segments = sorted(elffile.iter_segments(type='PT_LOAD'), key=lambda s: s['p_vaddr'])

            # determine the memory regions that need to be mapped in order to load the segments.
            # note that region boundaries are aligned to page, which means they may be larger than
            # the segment they contain. to reduce mapping clutter, adjacent regions with the same
            # perms are consolidated into one contigous memory region
            load_regions: Sequence[Tuple[int, int, int]] = []

            # iterate over loadable segments
            for seg in load_segments:
                lbound = self.ql.mem.align(load_address + seg['p_vaddr'])
                ubound = self.ql.mem.align_up(load_address + seg['p_vaddr'] + seg['p_memsz'])
                perms = QlLoaderELF.seg_perm_to_uc_prot(seg['p_flags'])

                if load_regions:
                    prev_lbound, prev_ubound, prev_perms = load_regions[-1]

                    # new region starts where the previous one ended
                    if lbound == prev_ubound:
                        # same perms? extend previous memory region
                        if perms == prev_perms:
                            load_regions[-1] = (prev_lbound, ubound, prev_perms)

                        # different perms? start a new one
                        else:
                            load_regions.append((lbound, ubound, perms))

                    # start a new memory region
                    elif lbound > prev_ubound:
                        load_regions.append((lbound, ubound, perms))

                    # overlapping segments? something probably went wrong
                    elif lbound < prev_ubound:
                        # EDL ELF files use 0x400 bytes pages, which might make some segments look as if they
                        # start at the same segment as their predecessor. though that is fixable, unicorn
                        # supports only 0x1000 bytes pages; this becomes problematic when using mem.protect
                        #
                        # this workaround unifies such "overlapping" segments, which may apply more permissive
                        # protection flags to that memory region.
                        if self.ql.arch.type == QL_ARCH.ARM64:
                            load_regions[-1] = (prev_lbound, ubound, prev_perms | perms)
                            continue

                        raise RuntimeError

                else:
                    load_regions.append((lbound, ubound, perms))

            # map the memory regions
            for lbound, ubound, perms in load_regions:
                try:
                    self.ql.mem.map(lbound, ubound - lbound, perms, os.path.basename(info))
                except QlMemoryMappedError:
                    self.ql.log.exception(f'Failed to map {lbound:#x}-{ubound:#x}')
                else:
                    self.ql.log.debug(f'Mapped {lbound:#x}-{ubound:#x}')

            # load loadable segments contents to memory
            for seg in load_segments:
                self.ql.mem.write(load_address + seg['p_vaddr'], seg.data())

            return load_regions[0][0], load_regions[-1][1]

        mem_start, mem_end = load_elf_segments(elffile, load_address, self.path)
        self.elf_entry = entry_point = load_address + elffile['e_entry']

        self.ql.log.debug(f'mem_start : {mem_start:#x}')
        self.ql.log.debug(f'mem_end   : {mem_end:#x}')

        # by convention the loaded binary is first on the list
        self.images.append(Image(mem_start, mem_end, os.path.abspath(self.path)))

        # note: 0x2000 is the size of [hook_mem]
        self.brk_address = mem_end + 0x2000

        # determine interpreter path
        interp_seg = next(elffile.iter_segments(type='PT_INTERP'), None)
        interp_path = str(interp_seg.get_interp_name()) if interp_seg else ''

        interp_address = 0

        # load the interpreter, if there is one
        if interp_path:
            interp_local_path = os.path.normpath(self.ql.rootfs + interp_path)
            self.ql.log.debug(f'Interpreter path: {interp_local_path}')

            with open(interp_local_path, 'rb') as infile:
                interp = ELFFile(infile)
                min_vaddr = min(seg['p_vaddr'] for seg in interp.iter_segments(type='PT_LOAD'))

                # determine interpreter base address
                # some old interpreters may not be PIE: p_vaddr of the first LOAD segment is not zero
                # we should load interpreter at the address p_vaddr specified in such situation
                interp_address = int(self.profile.get('interp_address'), 0) if min_vaddr == 0 else 0
                self.ql.log.debug(f'Interpreter addr: {interp_address:#x}')

                # load interpreter segments data to memory
                interp_start, interp_end = load_elf_segments(interp, interp_address, interp_local_path)

                # add interpreter to the loaded images list
                self.images.append(Image(interp_start, interp_end, os.path.abspath(interp_local_path)))

                # determine entry point
                entry_point = interp_address + interp['e_entry']

        # set mmap addr
        mmap_address = int(self.profile.get('mmap_address'), 0)
        self.ql.log.debug(f'mmap_address is : {mmap_address:#x}')

        # set info to be used by gdb
        self.mmap_address = mmap_address

        # set elf table
        elf_table = bytearray()
        new_stack = stack_addr

        def __push_str(top: int, s: str) -> int:
            """Write a string to stack memory and adjust the top of stack accordingly.
            Top of stack remains aligned to pointer size
            """

            data = (s if isinstance(s, bytes) else s.encode("utf-8")) + b'\x00'
            top = self.ql.mem.align(top - len(data), self.ql.arch.pointersize)
            self.ql.mem.write(top, data)

            return top

        # write argc
        elf_table.extend(self.ql.pack(len(argv)))

        # write argv
        for s in argv:
            new_stack = __push_str(new_stack, s)
            elf_table.extend(self.ql.pack(new_stack))

        # add a nullptr sentinel
        elf_table.extend(self.ql.pack(0))

        # write env
        for k, v in env.items():
            new_stack = __push_str(new_stack, f'{k}={v}')
            elf_table.extend(self.ql.pack(new_stack))

        # add a nullptr sentinel
        elf_table.extend(self.ql.pack(0))

        new_stack = randstraddr = __push_str(new_stack, 'a' * 16)
        new_stack = cpustraddr  = __push_str(new_stack, 'i686')
        new_stack = execfn      = __push_str(new_stack, argv[0])

        # store aux vector data for gdb use
        elf_phdr = elffile['e_phoff'] + mem_start
        elf_phent = elffile['e_phentsize']
        elf_phnum = elffile['e_phnum']

        if self.ql.arch.bits == 64:
            elf_hwcap = 0x078bfbfd
        elif self.ql.arch.bits == 32:
            elf_hwcap = 0x1fb8d7

            if self.ql.arch.endian == QL_ENDIAN.EB:
                # FIXME: considering this is a 32 bits value, it is not a big-endian version of the
                # value above like it is meant to be, since the one above has an implied leading zero
                # byte (i.e. 0x001fb8d7) which the EB value didn't take into account
                elf_hwcap = 0xd7b81f

        # setup aux vector
        auxv_entries = (
            (AUXV.AT_HWCAP, elf_hwcap),
            (AUXV.AT_PAGESZ, self.ql.mem.pagesize),
            (AUXV.AT_CLKTCK, 100),
            (AUXV.AT_PHDR, elf_phdr),
            (AUXV.AT_PHENT, elf_phent),
            (AUXV.AT_PHNUM, elf_phnum),
            (AUXV.AT_BASE, interp_address),
            (AUXV.AT_FLAGS, 0),
            (AUXV.AT_ENTRY, self.elf_entry),
            (AUXV.AT_UID, self.ql.os.uid),
            (AUXV.AT_EUID, self.ql.os.euid),
            (AUXV.AT_GID, self.ql.os.gid),
            (AUXV.AT_EGID, self.ql.os.egid),
            (AUXV.AT_SECURE, 0),
            (AUXV.AT_RANDOM, randstraddr),
            (AUXV.AT_HWCAP2, 0),
            (AUXV.AT_EXECFN, execfn),
            (AUXV.AT_PLATFORM, cpustraddr),
            (AUXV.AT_NULL, 0)
        )

        bytes_before_auxv = len(elf_table)

        # add all auxv entries
        for key, val in auxv_entries:
            elf_table.extend(self.ql.pack(key))
            elf_table.extend(self.ql.pack(val))

        new_stack = self.ql.mem.align(new_stack - len(elf_table), 0x10)
        self.ql.mem.write(new_stack, bytes(elf_table))

        self.auxv = new_stack + bytes_before_auxv

        self.stack_address = new_stack
        self.load_address = load_address
        self.init_sp = self.ql.arch.regs.arch_sp

        self.ql.os.entry_point = self.entry_point = entry_point
        self.ql.os.elf_mem_start = mem_start
        self.ql.os.elf_entry = self.elf_entry
        self.ql.os.function_hook = FunctionHook(self.ql, elf_phdr, elf_phnum, elf_phent, load_address, mem_end)

        # If there is a loader, we ignore exit
        self.skip_exit_check = (self.elf_entry != self.entry_point)

        # map vsyscall section for some specific needs
        if self.ql.arch.type == QL_ARCH.X8664 and self.ql.os.type == QL_OS.LINUX:
            _vsyscall_addr = int(self.profile.get('vsyscall_address'), 0)
            _vsyscall_size = int(self.profile.get('vsyscall_size'), 0)

            if self.ql.mem.is_available(_vsyscall_addr, _vsyscall_size):
                # initialize with int3 instructions then insert syscall entry
                # each syscall should be 1KiB away
                self.ql.mem.map(_vsyscall_addr, _vsyscall_size, info="[vsyscall]")
                self.ql.mem.write(_vsyscall_addr, _vsyscall_size * b'\xcc')
                assembler = self.ql.arch.assembler

                def __assemble(asm: str) -> bytes:
                    bs, _ = assembler.asm(asm)
                    return bytes(bs)

                _vsyscall_ids = (
                    SYSCALL_NR.gettimeofday,
                    SYSCALL_NR.time,
                    SYSCALL_NR.getcpu
                )

                for i, scid in enumerate(_vsyscall_ids):
                    self.ql.mem.write(_vsyscall_addr + i * 1024, __assemble(f'mov rax, {scid:#x}; syscall; ret'))

    def lkm_get_init(self, elffile: ELFFile) -> int:
        """Get file offset of the init_module function.
        """

        symbol_tables = (sec for sec in elffile.iter_sections() if type(sec) is SymbolTableSection)

        for sec in symbol_tables:
            syms = sec.get_symbol_by_name('init_module')

            if syms:
                sym = syms[0]
                addr = sym['st_value'] + elffile.get_section(sym['st_shndx'])['sh_offset']
                self.ql.log.info(f'init_module = {addr:#x}')
                return addr

        raise QlErrorELFFormat('invalid module: symbol init_module not found')

    def lkm_dynlinker(self, elffile: ELFFile, mem_start: int) -> Mapping[str, int]:
        def __get_symbol(name: str) -> Optional[Symbol]:
            _symtab = elffile.get_section_by_name('.symtab')
            _sym = _symtab.get_symbol_by_name(name)

            return _sym[0] if _sym else None

        ql = self.ql

        all_symbols = []
        self.ql.os.hook_addr = API_HOOK_MEM
        # map address to symbol name
        self.import_symbols = {}
        # reverse dictionary to map symbol name -> address
        rev_reloc_symbols = {}

        rh = RelocationHandler(elffile)
        sections = [sec for sec in elffile.iter_sections() if sec['sh_flags'] & SH_FLAGS.SHF_ALLOC]

        for sec in sections:
            reloc_sec = rh.find_relocations_for_section(sec)

            if reloc_sec and reloc_sec.name != '.rela.gnu.linkonce.this_module':
                # get the symbol table section pointed in sh_link
                symtab = elffile.get_section(reloc_sec['sh_link'])
                assert isinstance(symtab, SymbolTableSection)

                for rel in reloc_sec.iter_relocations():
                    # if reloc['r_info_sym'] == 0:
                    #     continue

                    symbol = symtab.get_symbol(rel['r_info_sym'])
                    assert symbol

                    # Some symbols have zero 'st_name', so instead what's used is
                    # the name of the section they point at.
                    if symbol['st_name'] == 0:
                        symsec = elffile.get_section(symbol['st_shndx'])
                        symbol_name = symsec.name
                        sym_offset = symsec['sh_offset']

                        rev_reloc_symbols[symbol_name] = sym_offset + mem_start
                    else:
                        symbol_name = symbol.name
                        # get info about related section to be patched
                        info_section = elffile.get_section(reloc_sec['sh_info'])
                        sym_offset = info_section['sh_offset']

                        if symbol_name in all_symbols:
                            sym_offset = rev_reloc_symbols[symbol_name] - mem_start
                        else:
                            all_symbols.append(symbol_name)
                            _symbol = __get_symbol(symbol_name)

                            if _symbol['st_shndx'] == 'SHN_UNDEF':
                                # external symbol
                                # only save symbols of APIs

                                # we need to lookup from address to symbol, so we can find the right callback
                                # for sys_xxx handler for syscall, the address must be aligned to pointer size
                                if symbol_name.startswith('sys_'):
                                    self.ql.os.hook_addr = self.ql.mem.align_up(self.ql.os.hook_addr, self.ql.arch.pointersize)

                                self.import_symbols[self.ql.os.hook_addr] = symbol_name

                                # FIXME: this is for rootkit to scan for syscall table from page_offset_base
                                # write address of syscall table to this slot, so syscall scanner can quickly find it
                                if symbol_name == "page_offset_base":
                                    ql.mem.write_ptr(self.ql.os.hook_addr, SYSCALL_MEM)

                                # we also need to do reverse lookup from symbol to address
                                rev_reloc_symbols[symbol_name] = self.ql.os.hook_addr
                                sym_offset = self.ql.os.hook_addr - mem_start
                                self.ql.os.hook_addr += self.ql.arch.pointersize
                            else:
                                # local symbol
                                _section = elffile.get_section(_symbol['st_shndx'])
                                rev_reloc_symbols[symbol_name] = _section['sh_offset'] + _symbol['st_value'] + mem_start

                    # ql.log.info(f'relocating: {symbol_name} -> {rev_reloc_symbols[symbol_name]:#010x}')

                    # FIXME: using the rh.apply_section_relocations method for the following relocation work
                    # seems to be cleaner.

                    loc = elffile.get_section(reloc_sec['sh_info'])['sh_offset'] + rel['r_offset']
                    loc += mem_start

                    desc = describe_reloc_type(rel['r_info_type'], elffile)

                    if desc in ('R_X86_64_32S', 'R_X86_64_32'):
                        # patch this reloc
                        if rel['r_addend']:
                            val = sym_offset + rel['r_addend']
                            val += mem_start
                        else:
                            val = rev_reloc_symbols[symbol_name]

                        ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                    elif desc == 'R_X86_64_64':
                        val = sym_offset + rel['r_addend']
                        val += 0x2000000  # init_module position: FIXME
                        ql.mem.write_ptr(loc, val, 8)

                    elif desc == 'R_X86_64_PC64':
                        val = rel['r_addend'] - loc
                        val += rev_reloc_symbols[symbol_name]
                        ql.mem.write_ptr(loc, val, 8)

                    elif desc in ('R_X86_64_PC32', 'R_X86_64_PLT32'):
                        val = rel['r_addend'] - loc
                        val += rev_reloc_symbols[symbol_name]
                        ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                    elif desc in ('R_386_PC32', 'R_386_PLT32'):
                        val = ql.mem.read_ptr(loc, 4)
                        val = rev_reloc_symbols[symbol_name] + val - loc
                        ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                    elif desc in ('R_386_32', 'R_MIPS_32'):
                        val = ql.mem.read_ptr(loc, 4)
                        val = rev_reloc_symbols[symbol_name] + val
                        ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                    elif desc == 'R_MIPS_HI16':
                        # actual relocation is done in R_MIPS_LO16
                        prev_mips_hi16_loc = loc

                    elif desc == 'R_MIPS_LO16':
                        val = ql.mem.read_ptr(prev_mips_hi16_loc + 2, 2) << 16 | ql.mem.read_ptr(loc + 2, 2)
                        val = rev_reloc_symbols[symbol_name] + val
                        # *(word)(mips_lo16_loc + 2) is treated as signed
                        if (val & 0xFFFF) >= 0x8000:
                            val += (1 << 16)

                        ql.mem.write_ptr(prev_mips_hi16_loc + 2, (val >> 16), 2)
                        ql.mem.write_ptr(loc + 2, (val & 0xFFFF), 2)

                    else:
                        raise NotImplementedError(f'Relocation type {desc} not implemented')

        return rev_reloc_symbols

    def load_driver(self, elffile: ELFFile, stack_addr: int, loadbase: int = 0) -> None:
        elfdata_mapping = self.get_elfdata_mapping(elffile)

        # Determine the range of memory space opened up
        # mem_start = -1
        # mem_end = -1
        #
        # for i in super().parse_program_header(ql):
        #     if i['p_type'] == PT_LOAD:
        #         if mem_start > i['p_vaddr'] or mem_start == -1:
        #             mem_start = i['p_vaddr']
        #         if mem_end < i['p_vaddr'] + i['p_memsz'] or mem_end == -1:
        #             mem_end = i['p_vaddr'] + i['p_memsz']
        #
        # mem_start = int(mem_start // 0x1000) * 0x1000
        # mem_end = int(mem_end // 0x1000 + 1) * 0x1000

        # FIXME
        mem_start = 0x1000
        mem_end = mem_start + (len(elfdata_mapping) // 0x1000 + 1) * 0x1000

        # map some memory to intercept external functions of Linux kernel
        self.ql.mem.map(API_HOOK_MEM, 0x1000, info="[api_mem]")

        self.ql.log.debug(f'loadbase  : {loadbase:#x}')
        self.ql.log.debug(f'mem_start : {mem_start:#x}')
        self.ql.log.debug(f'mem_end   : {mem_end:#x}')

        self.ql.mem.map(loadbase + mem_start, mem_end - mem_start, info=self.ql.path)
        self.ql.mem.write(loadbase + mem_start, elfdata_mapping)

        entry_point = self.lkm_get_init(elffile) + loadbase + mem_start
        self.brk_address = mem_end + loadbase

        # Set MMAP addr
        mmap_address = int(self.profile.get('mmap_address'), 0)
        self.ql.log.debug(f'mmap_address is : {mmap_address:#x}')

        # self.ql.os.elf_entry = self.elf_entry = loadbase + elfhead['e_entry']
        self.ql.os.entry_point = self.entry_point = entry_point
        self.elf_entry = self.ql.os.elf_entry = self.ql.os.entry_point

        self.stack_address = self.ql.mem.align(stack_addr, self.ql.arch.pointersize)
        self.load_address = loadbase

        # remember address of syscall table, so external tools can access to it
        # self.ql.os.syscall_addr = SYSCALL_MEM

        # setup syscall table
        self.ql.mem.map(SYSCALL_MEM, 0x1000, info="[syscall_mem]")
        self.ql.mem.write(SYSCALL_MEM, b'\x00' * 0x1000)

        rev_reloc_symbols = self.lkm_dynlinker(elffile, mem_start + loadbase)

        # iterate over relocatable symbols, but pick only those who start with 'sys_'
        for sc, addr in rev_reloc_symbols.items():
            if sc.startswith('sys_') and sc != 'sys_call_table':
                tmp_sc = sc[4:]

                if hasattr(SYSCALL_NR, tmp_sc):
                    syscall_id = getattr(SYSCALL_NR, tmp_sc).value
                    dest = SYSCALL_MEM + syscall_id * self.ql.arch.pointersize

                    self.ql.log.debug(f'Writing syscall {tmp_sc} to {dest:#x}')
                    self.ql.mem.write_ptr(dest, addr)

        # write syscall addresses into syscall table
        self.ql.mem.write_ptr(SYSCALL_MEM + 0 * self.ql.arch.pointersize, self.ql.os.hook_addr + 0 * self.ql.arch.pointersize)
        self.ql.mem.write_ptr(SYSCALL_MEM + 1 * self.ql.arch.pointersize, self.ql.os.hook_addr + 1 * self.ql.arch.pointersize)
        self.ql.mem.write_ptr(SYSCALL_MEM + 2 * self.ql.arch.pointersize, self.ql.os.hook_addr + 2 * self.ql.arch.pointersize)

        # setup hooks for read/write/open syscalls
        self.import_symbols[self.ql.os.hook_addr + 0 * self.ql.arch.pointersize] = hook_sys_read
        self.import_symbols[self.ql.os.hook_addr + 1 * self.ql.arch.pointersize] = hook_sys_write
        self.import_symbols[self.ql.os.hook_addr + 2 * self.ql.arch.pointersize] = hook_sys_open

    def get_elfdata_mapping(self, elffile: ELFFile) -> bytes:
        elfdata_mapping = bytearray()

        # pick up elf header
        with preserve_stream_pos(elffile.stream):
            elffile.stream.seek(0)
            elf_header = elffile.stream.read(elffile['e_ehsize'])

        elfdata_mapping.extend(elf_header)

        # pick up loadable sections and relocate them if needed
        for sec in elffile.iter_sections():
            if sec['sh_flags'] & SH_FLAGS.SHF_ALLOC:
                # pad aggregated elf data to the offset of the current section 
                elfdata_mapping.extend(b'\x00' * (sec['sh_offset'] - len(elfdata_mapping)))

                # aggregate section data
                elfdata_mapping.extend(sec.data())

        return bytes(elfdata_mapping)

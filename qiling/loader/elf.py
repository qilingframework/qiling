#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import io
import os

import struct
from enum import IntEnum
from typing import Any, AnyStr, Optional, Sequence, Mapping, Tuple

from lief import ELF
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
API_HOOK_SIZE = 0x1000

# memory for syscall table
SYSCALL_MEM = API_HOOK_MEM + 0x1000
SYSCALL_SIZE = 0x1000


# workaround for https://github.com/lief-project/LIEF/issues/795
def _iter_raw_relocations(binary: ELF.Binary, raw: bytes):
    is_be = binary.header.identity_data == ELF.Header.ELF_DATA.MSB
    is_64 = binary.header.identity_class == ELF.Header.CLASS.ELF64
    endian = '>' if is_be else '<'

    for sec in binary.sections:
        if sec.type not in (ELF.Section.TYPE.REL, ELF.Section.TYPE.RELA):
            continue

        is_rela = (sec.type == ELF.Section.TYPE.RELA)

        # sh_info = section being relocated; sh_link = symbol table section
        info_idx = sec.information
        if info_idx >= len(list(binary.sections)):
            continue
        target_sec = list(binary.sections)[info_idx]

        entry_size = (24 if is_rela else 16) if is_64 else (12 if is_rela else 8)
        raw_sec = raw[sec.offset : sec.offset + sec.size]

        for i in range(len(raw_sec) // entry_size):
            entry = raw_sec[i * entry_size : (i + 1) * entry_size]
            if is_64:
                r_offset, r_info = struct.unpack_from(f'{endian}QQ', entry)
                r_sym  = r_info >> 32
                r_type = r_info & 0xFFFFFFFF
                r_addend = struct.unpack_from(f'{endian}q', entry, 16)[0] if is_rela else 0
            else:
                r_offset, r_info = struct.unpack_from(f'{endian}II', entry)
                r_sym  = r_info >> 8
                r_type = r_info & 0xFF
                r_addend = struct.unpack_from(f'{endian}i', entry, 8)[0] if is_rela else 0

            yield target_sec, r_sym, r_offset, r_type, r_addend


def _iter_lief_relocations(binary: ELF.Binary):
    """Primary relocation iterator using LIEF's parsed relocations.

    Yields (target_sec, r_sym, r_offset, r_type, r_addend) with r_type as
    the ELF.Relocation.TYPE enum value for direct comparison.
    """
    cls = binary.header.identity_class
    is_64 = cls == ELF.Header.CLASS.ELF64

    for rel in binary.relocations:
        target_sec = rel.section
        if target_sec is None:
            continue

        r_info = rel.r_info(cls)
        r_sym = r_info >> 32 if is_64 else r_info >> 8
        r_offset = rel.address
        r_addend = rel.addend

        yield target_sec, r_sym, r_offset, rel.type, r_addend


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

        self.profile = self.ql.os.profile[f'OS{self.ql.arch.bits}']

        # setup program stack
        stack_address = self.profile.getint('stack_address')
        stack_size = self.profile.getint('stack_size')
        top_of_stack = stack_address + stack_size
        self.ql.mem.map(stack_address, stack_size, info='[stack]')

        self.path = self.ql.path

        with open(self.path, 'rb') as infile:
            raw = infile.read()

        binary = ELF.parse(list(raw))

        if binary is None:
            raise QlErrorELFFormat('failed to parse ELF file')

        elftype = binary.header.file_type

        # is it a driver?
        if elftype == ELF.Header.FILE_TYPE.REL:
            self.load_driver(binary, raw, top_of_stack, loadbase=0x8000000)
            self.ql.hook_code(hook_kernel_api)

        # is it an executable?
        elif elftype == ELF.Header.FILE_TYPE.EXEC:
            load_address = 0

            self.load_with_ld(binary, top_of_stack, load_address, self.argv, self.env)

        # is it a shared object?
        elif elftype == ELF.Header.FILE_TYPE.DYN:
            load_address = self.profile.getint('load_address')

            self.load_with_ld(binary, top_of_stack, load_address, self.argv, self.env)

        else:
            raise QlErrorELFFormat(f'unexpected elf type value (e_type = {elftype})')

        self.is_driver = (elftype == ELF.Header.FILE_TYPE.REL)

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

        if perm & 0x1:  # PF_X
            prot |= UC_PROT_EXEC

        if perm & 0x2:  # PF_W
            prot |= UC_PROT_WRITE

        if perm & 0x4:  # PF_R
            prot |= UC_PROT_READ

        return prot

    def load_with_ld(self, binary: ELF.Binary, stack_addr: int, load_address: int, argv: Sequence[str] = [], env: Mapping[str, str] = {}):

        def load_elf_segments(binary: ELF.Binary, load_address: int, info: str):
            # get list of loadable segments; these segments will be loaded to memory
            load_segments = sorted(
                [s for s in binary.segments if s.type == ELF.Segment.TYPE.LOAD],
                key=lambda s: s.virtual_address
            )

            # determine the memory regions that need to be mapped in order to load the segments.
            # note that region boundaries are aligned to page, which means they may be larger than
            # the segment they contain. to reduce mapping clutter, adjacent regions with the same
            # perms are consolidated into one contigous memory region
            load_regions: Sequence[Tuple[int, int, int]] = []

            # iterate over loadable segments
            for seg in load_segments:
                lbound = self.ql.mem.align(load_address + seg.virtual_address)
                ubound = self.ql.mem.align_up(load_address + seg.virtual_address + seg.virtual_size)
                perms = QlLoaderELF.seg_perm_to_uc_prot(int(seg.flags))

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
                size = ubound - lbound

                # there might be a region with zero size. in this case, do not mmap it
                if size:
                    try:
                        self.ql.mem.map(lbound, size, perms, os.path.basename(info))
                    except QlMemoryMappedError:
                        self.ql.log.exception(f'Failed to map {lbound:#x}-{ubound:#x}')
                    else:
                        self.ql.log.debug(f'Mapped {lbound:#x}-{ubound:#x}')

            # load loadable segments contents to memory
            for seg in load_segments:
                self.ql.mem.write(load_address + seg.virtual_address, bytes(seg.content))

            return load_regions[0][0], load_regions[-1][1]

        mem_start, mem_end = load_elf_segments(binary, load_address, self.path)
        self.elf_entry = entry_point = load_address + binary.header.entrypoint

        self.ql.log.debug(f'mem_start : {mem_start:#x}')
        self.ql.log.debug(f'mem_end   : {mem_end:#x}')

        # by convention the loaded binary is first on the list
        self.images.append(Image(mem_start, mem_end, os.path.abspath(self.path)))

        # note: 0x2000 is the size of [hook_mem]
        self.brk_address = mem_end + 0x2000

        # determine interpreter path
        interp_path = binary.interpreter  # '' if no PT_INTERP segment

        interp_address = 0

        # load the interpreter, if there is one
        if interp_path:
            interp_vpath = self.ql.os.path.virtual_abspath(interp_path)
            interp_hpath = self.ql.os.path.virtual_to_host_path(interp_path)

            self.ql.log.debug(f'Interpreter path: {interp_vpath}')

            if not self.ql.os.path.is_safe_host_path(interp_hpath):
                raise PermissionError(f'unsafe path: {interp_hpath}')

            interp_binary = ELF.parse(interp_hpath)
            if interp_binary is None:
                raise QlErrorELFFormat(f'failed to parse interpreter: {interp_hpath}')

            interp_load_segs = [s for s in interp_binary.segments if s.type == ELF.Segment.TYPE.LOAD]
            min_vaddr = min(s.virtual_address for s in interp_load_segs)

            # determine interpreter base address
            # some old interpreters may not be PIE: p_vaddr of the first LOAD segment is not zero
            # we should load interpreter at the address p_vaddr specified in such situation
            interp_address = self.profile.getint('interp_address') if min_vaddr == 0 else 0
            self.ql.log.debug(f'Interpreter addr: {interp_address:#x}')

            # load interpreter segments data to memory
            interp_start, interp_end = load_elf_segments(interp_binary, interp_address, interp_vpath)

            # add interpreter to the loaded images list
            self.images.append(Image(interp_start, interp_end, interp_hpath))

            # determine entry point
            entry_point = interp_address + interp_binary.header.entrypoint

        # set mmap addr
        mmap_address = self.profile.getint('mmap_address')
        self.ql.log.debug(f'mmap_address is : {mmap_address:#x}')

        # set info to be used by gdb
        self.mmap_address = mmap_address

        # set elf table
        elf_table = bytearray()
        new_stack = stack_addr

        def __push_bytes(top: int, b: bytes) -> int:
            """Write bytes to stack memory and adjust the top of stack accordingly.
            Top of stack remains aligned to pointer size
            """

            data = b + b'\x00'
            top = self.ql.mem.align(top - len(data), self.ql.arch.pointersize)
            self.ql.mem.write(top, data)

            return top

        def __push_str(top: int, s: str) -> int:
            """A convinient method for writing a string to stack memory.
            """

            return __push_bytes(top, s.encode('latin'))

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
            _k = k if isinstance(k, bytes) else k.encode('latin')
            _v = v if isinstance(v, bytes) else v.encode('latin')

            pair = b'='.join((_k, _v))

            new_stack = __push_bytes(new_stack, pair)
            elf_table.extend(self.ql.pack(new_stack))

        # add a nullptr sentinel
        elf_table.extend(self.ql.pack(0))

        new_stack = randstraddr = __push_str(new_stack, 'a' * 16)
        new_stack = cpustraddr  = __push_str(new_stack, 'i686')
        new_stack = execfn      = __push_str(new_stack, argv[0])

        # store aux vector data for gdb use
        elf_phdr = binary.header.program_header_offset + mem_start
        elf_phent = binary.header.program_header_size
        elf_phnum = binary.header.numberof_segments

        # for more details on the following values see:
        # https://github.com/google/cpu_features/blob/main/include/internal/hwcaps.h
        hwcap_values = {
            (QL_ARCH.ARM,   QL_ENDIAN.EL, 32): 0x001fb8d7,
            (QL_ARCH.ARM,   QL_ENDIAN.EB, 32): 0xd7b81f00,
            (QL_ARCH.ARM64, QL_ENDIAN.EL, 64): 0x078bfafd
        }

        # determine hwcap value by arch properties; if not found default to 0
        hwcap = hwcap_values.get((self.ql.arch.type, self.ql.arch.endian, self.ql.arch.bits), 0)

        # setup aux vector
        auxv_entries = [
            (AUXV.AT_PHDR, elf_phdr),
            (AUXV.AT_PHENT, elf_phent),
            (AUXV.AT_PHNUM, elf_phnum),
            (AUXV.AT_PAGESZ, self.ql.mem.pagesize),
        ]

        if interp_path:
            auxv_entries.append((AUXV.AT_BASE, interp_address))

        auxv_entries.extend([
            (AUXV.AT_FLAGS, 0),
            (AUXV.AT_ENTRY, self.elf_entry),
            (AUXV.AT_UID, self.ql.os.uid),
            (AUXV.AT_EUID, self.ql.os.euid),
            (AUXV.AT_GID, self.ql.os.gid),
            (AUXV.AT_EGID, self.ql.os.egid),
            (AUXV.AT_CLKTCK, 100),
            (AUXV.AT_PLATFORM, cpustraddr),
            (AUXV.AT_HWCAP, hwcap),
            (AUXV.AT_SECURE, 0),
            (AUXV.AT_RANDOM, randstraddr),
            (AUXV.AT_HWCAP2, 0),
            (AUXV.AT_EXECFN, execfn),
            (AUXV.AT_NULL, 0)
        ])

        bytes_before_auxv = len(elf_table)

        # add all auxv entries
        for key, val in auxv_entries:
            elf_table.extend(self.ql.pack(key))
            elf_table.extend(self.ql.pack(val))

        sp_align = self.ql.arch.pointersize

        # mips requires doubleword alignment
        if self.ql.arch.type is QL_ARCH.MIPS:
            sp_align *= 2

        new_stack = self.ql.mem.align(new_stack - len(elf_table), sp_align)
        self.ql.mem.write(new_stack, bytes(elf_table))

        self.auxv = new_stack + bytes_before_auxv

        self.stack_address = new_stack
        self.load_address = load_address
        self.init_sp = self.ql.arch.regs.arch_sp

        self.ql.os.entry_point = self.entry_point = entry_point
        self.ql.os.function_hook = FunctionHook(self.ql, elf_phdr, elf_phnum, elf_phent, load_address, mem_end)

        # If there is a loader, we ignore exit
        self.skip_exit_check = (self.elf_entry != self.entry_point)

        # map vsyscall section for some specific needs
        if self.ql.arch.type == QL_ARCH.X8664 and self.ql.os.type == QL_OS.LINUX:
            vsyscall_addr = self.profile.getint('vsyscall_address')

            vsyscall_ids = (
                SYSCALL_NR.gettimeofday,
                SYSCALL_NR.time,
                SYSCALL_NR.getcpu
            )

            # each syscall should be 1KiB away
            entry_size = 1024
            vsyscall_size = self.ql.mem.align_up(len(vsyscall_ids) * entry_size)

            if self.ql.mem.is_available(vsyscall_addr, vsyscall_size):
                # initialize with int3 instructions then insert syscall entry
                self.ql.mem.map(vsyscall_addr, vsyscall_size, info="[vsyscall]")
                assembler = self.ql.arch.assembler

                def __assemble(asm: str) -> bytes:
                    bs, _ = assembler.asm(asm)
                    return bytes(bs)

                for i, scid in enumerate(vsyscall_ids):
                    entry = __assemble(f'mov rax, {scid:#x}; syscall; ret')

                    self.ql.mem.write(vsyscall_addr + i * entry_size, entry.ljust(entry_size, b'\xcc'))

    def lkm_get_init(self, binary: ELF.Binary) -> int:
        """Get file offset of the init_module function.
        """

        sym = binary.get_symbol('init_module')

        if sym is not None:
            return sym.value + binary.sections[sym.shndx].offset

        raise QlErrorELFFormat('invalid module: symbol init_module not found')

    def lkm_dynlinker(self, binary: ELF.Binary, raw: bytes, mem_start: int) -> Mapping[str, int]:
        # Index symbols by name for fast lookup
        sym_by_name = {sym.name: sym for sym in binary.symbols if sym.name}

        def __get_symbol(name: str):
            return sym_by_name.get(name)

        ql = self.ql

        all_symbols = []
        self.ql.os.hook_addr = API_HOOK_MEM
        # map address to symbol name
        self.import_symbols = {}
        # reverse dictionary to map symbol name -> address
        rev_reloc_symbols = {}

        # Build a list of all ELF symbols for index-based lookup (for anonymous symbols)
        all_elf_symbols = list(binary.symbols)
        sections_list = list(binary.sections)

        SHF_ALLOC = int(ELF.Section.FLAGS.ALLOC)
        alloc_section_names = {sec.name for sec in sections_list if sec.flags & SHF_ALLOC}

        # binary.header.machine_type is correct even for big-endian targets —
        # LIEF handles ELF header byte-swapping correctly for all architectures.
        e_machine = binary.header.machine_type

        T = ELF.Relocation.TYPE
        A = ELF.ARCH

        prev_mips_hi16_loc = 0  # used by R_MIPS_HI16/LO16 pair

        is_be = binary.header.identity_data == ELF.Header.ELF_DATA.MSB
        if is_be and e_machine == A.MIPS:
            # fall back to raw parser: LIEF has an endianness bug for big-endian MIPS REL (issue #795)
            # lift raw ints back to ELF.Relocation.TYPE so dispatch is uniform
            mips_arch_bits = int(T.MIPS_32) & 0xFF000000
            def reloc_iter():
                for target_sec, r_sym, r_offset, r_type_raw, r_addend in _iter_raw_relocations(binary, raw):
                    yield target_sec, r_sym, r_offset, T(mips_arch_bits | r_type_raw), r_addend
            reloc_source = reloc_iter()
        else:
            reloc_source = _iter_lief_relocations(binary)

        for target_sec, r_sym, r_offset, r_type, r_addend in reloc_source:
            # skip relocations for non-alloc sections (e.g. .gnu.linkonce.this_module)
            if target_sec.name not in alloc_section_names:
                continue

            # Look up symbol by index
            symbol = all_elf_symbols[r_sym] if (0 < r_sym < len(all_elf_symbols)) else None

            # sym_offset defaults to the target section offset (for named symbols)
            sym_offset = target_sec.offset

            if symbol is not None and symbol.name == '':
                # SECTION-type anonymous symbol: resolve via symbol.shndx to the actual referenced section
                if 0 < symbol.shndx < len(sections_list):
                    symsec = sections_list[symbol.shndx]
                    symbol_name = symsec.name
                    sym_offset = symsec.offset
                    rev_reloc_symbols[symbol_name] = sym_offset + mem_start
                else:
                    continue
            elif symbol is None:
                # r_sym == 0: null symbol, section-relative to target section itself
                symbol_name = target_sec.name
                rev_reloc_symbols[symbol_name] = sym_offset + mem_start
            else:
                symbol_name = symbol.name

                if symbol_name in all_symbols:
                    sym_offset = rev_reloc_symbols[symbol_name] - mem_start
                else:
                    all_symbols.append(symbol_name)
                    _symbol = __get_symbol(symbol_name)

                    if _symbol is None or _symbol.shndx == 0:  # SHN_UNDEF
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

                    elif _symbol.shndx == 0xfff1:  # SHN_ABS
                        rev_reloc_symbols[symbol_name] = _symbol.value

                    else:
                        # local symbol
                        _section = list(binary.sections)[_symbol.shndx]
                        rev_reloc_symbols[symbol_name] = _section.offset + _symbol.value + mem_start

            # ql.log.info(f'relocating: {symbol_name} -> {rev_reloc_symbols[symbol_name]:#010x}')

            loc = target_sec.offset + r_offset + mem_start

            if e_machine == A.X86_64:
                if r_type in (T.X86_64_32S, T.X86_64_32):
                    if r_addend:
                        val = sym_offset + r_addend + mem_start
                    else:
                        val = rev_reloc_symbols[symbol_name]
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                elif r_type == T.X86_64_64:
                    val = sym_offset + r_addend + 0x2000000  # init_module position: FIXME
                    ql.mem.write_ptr(loc, val, 8)

                elif r_type == T.X86_64_PC64:
                    val = r_addend - loc + rev_reloc_symbols[symbol_name]
                    ql.mem.write_ptr(loc, val, 8)

                elif r_type in (T.X86_64_PC32, T.X86_64_PLT32):
                    val = r_addend - loc + rev_reloc_symbols[symbol_name]
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                else:
                    raise NotImplementedError(f'Relocation type {r_type} not implemented for x86_64')

            elif e_machine == A.I386:
                if r_type in (T.X86_PC32, T.X86_PLT32):
                    val = ql.mem.read_ptr(loc, 4)
                    val += rev_reloc_symbols[symbol_name] - loc
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                elif r_type == T.X86_32:
                    val = ql.mem.read_ptr(loc, 4)
                    val += rev_reloc_symbols[symbol_name]
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                else:
                    raise NotImplementedError(f'Relocation type {r_type} not implemented for i386')

            elif e_machine == A.MIPS:
                if r_type == T.MIPS_32:
                    val = ql.mem.read_ptr(loc, 4)
                    val += rev_reloc_symbols[symbol_name]
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                elif r_type == T.MIPS_HI16:
                    prev_mips_hi16_loc = loc

                elif r_type == T.MIPS_LO16:
                    val = ql.mem.read_ptr(prev_mips_hi16_loc + 2, 2) << 16 | ql.mem.read_ptr(loc + 2, 2)
                    val = rev_reloc_symbols[symbol_name] + val
                    # *(word)(mips_lo16_loc + 2) is treated as signed
                    if (val & 0xFFFF) >= 0x8000:
                        val += (1 << 16)

                    ql.mem.write_ptr(prev_mips_hi16_loc + 2, (val >> 16), 2)
                    ql.mem.write_ptr(loc + 2, (val & 0xFFFF), 2)

                else:
                    raise NotImplementedError(f'Relocation type {r_type} not implemented for MIPS')

            elif e_machine == A.ARM:
                if r_type in (T.ARM_CALL, T.ARM_JUMP24):
                    val = (rev_reloc_symbols[symbol_name] - loc - 8) >> 2
                    val = (val & 0xFFFFFF) | (ql.mem.read_ptr(loc, 4) & 0xFF000000)
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                elif r_type == T.ARM_ABS32:
                    val = rev_reloc_symbols[symbol_name] + ql.mem.read_ptr(loc, 4)
                    ql.mem.write_ptr(loc, (val & 0xFFFFFFFF), 4)

                else:
                    raise NotImplementedError(f'Relocation type {r_type} not implemented for ARM')

        return rev_reloc_symbols

    def load_driver(self, binary: ELF.Binary, raw: bytes, stack_addr: int, loadbase: int = 0) -> None:
        elfdata_mapping = self.get_elfdata_mapping(binary, raw)

        mem_start = self.ql.mem.align(loadbase)
        mem_end = self.ql.mem.align_up(loadbase + len(elfdata_mapping))

        # map some memory to intercept external functions of Linux kernel
        self.ql.mem.map(API_HOOK_MEM, API_HOOK_SIZE, info="[api_mem]")

        self.ql.log.debug(f'mem_start : {mem_start:#x}')
        self.ql.log.debug(f'mem_end   : {mem_end:#x}')

        self.ql.mem.map(mem_start, mem_end - mem_start, info=os.path.basename(self.ql.path))
        self.ql.mem.write(loadbase, elfdata_mapping)

        self.images.append(Image(mem_start, mem_end, os.path.abspath(self.path)))

        init_module = loadbase + self.lkm_get_init(binary)
        self.ql.log.debug(f'init_module : {init_module:#x}')

        self.brk_address = mem_end

        # Set MMAP addr
        mmap_address = self.profile.getint('mmap_address')
        self.ql.log.debug(f'mmap_address is : {mmap_address:#x}')

        # there is no interperter so emulation entry point is also elf entry
        self.elf_entry = self.entry_point = init_module
        self.ql.os.entry_point = self.entry_point

        self.stack_address = self.ql.mem.align(stack_addr, self.ql.arch.pointersize)
        self.load_address = loadbase

        # setup syscall table
        self.ql.mem.map(SYSCALL_MEM, SYSCALL_SIZE, info="[syscall_mem]")
        self.ql.mem.write(SYSCALL_MEM, b'\x00' * SYSCALL_SIZE)

        rev_reloc_symbols = self.lkm_dynlinker(binary, raw, loadbase)

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

    def get_elfdata_mapping(self, binary: ELF.Binary, raw: bytes) -> bytes:
        # TODO: need to patch hooked symbols with their hook targets
        # (e.g. replace calls to 'printk' with the hooked address that
        # was allocate for it)

        elfdata_mapping = bytearray()

        # pick up elf header from raw bytes
        elf_header = raw[:binary.header.header_size]
        elfdata_mapping.extend(elf_header)

        # FIXME: normally the address of a section would be determined by its 'sh_addr' value.
        # in case of a relocatable object all its sections' sh_addr will be set to zero, so
        # the value in 'sh_offset' should be used to determine the final address.
        # see: https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
        #
        # here we presume this a relocatable object and don't do any relocation (that is, it
        # is relocated to 0)

        SHF_ALLOC = int(ELF.Section.FLAGS.ALLOC)

        # pick up loadable sections
        for sec in binary.sections:
            if sec.flags & SHF_ALLOC:
                # pad aggregated elf data to the offset of the current section
                elfdata_mapping.extend(b'\x00' * (sec.offset - len(elfdata_mapping)))

                # aggregate section data
                elfdata_mapping.extend(bytes(sec.content))

        return bytes(elfdata_mapping)

    def save(self) -> Mapping[str, Any]:
        saved = super().save()

        saved['brk_address'] = self.brk_address

        return saved

    def restore(self, saved_state: Mapping[str, Any]):
        self.brk_address = saved_state['brk_address']

        super().restore(saved_state)

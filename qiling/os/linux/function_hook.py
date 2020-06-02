#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
from qiling.const import *

PT_DYNAMIC = 2

DT_NULL 		= 0
DT_NEEDED 		= 1
DT_PLTRELSZ 	= 2
DT_PLTGOT 		= 3
DT_HASH 		= 4
DT_STRTAB 		= 5
DT_SYMTAB 		= 6
DT_RELA 		= 7
DT_RELASZ 		= 8
DT_RELAENT 		= 9
DT_STRSZ 		= 10
DT_SYMENT 		= 11
DT_INIT 		= 12
DT_FINI 		= 13
DT_SONAME 		= 14
DT_RPATH 		= 15
DT_SYMBOLIC 	= 16
DT_REL 			= 17
DT_RELSZ 		= 18
DT_RELENT 		= 19
DT_PLTREL 		= 20
DT_DEBUG 		= 21
DT_TEXTREL 		= 22
DT_JMPREL 		= 23
DT_BIND_NOW 	= 24
DT_INIT_ARRAY 	= 25
DT_FINI_ARRAY 	= 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH 		= 29
DT_FLAGS 		= 30
DT_ENCODING 	= 32
DT_GNU_HASH	    = 0x6ffffef5

DT_MIPS_LOCAL_GOTNO = 0x7000000a
DT_MIPS_SYMTABNO = 0x70000011
DT_MIPS_GOTSYM = 0x70000013

class HookFunc:
    def __init__(self, ql, funcname, r, load_base):
        self.funcname = funcname
        self.hook = []
        self.rel = r
        self.idx = None
        self.hook_fuc_ptr = None
        self.hook_data_ptr = None
        self.load_base = load_base
        self.ql = ql
        self.ori_offest = None
        self.ori_data = None
    
    def add_hook(self, cb, userdata):
        self.hook.append((cb, userdata))
    
    def call(self):
        if self.ql.archtype == QL_ARCH.ARM or self.ql.archtype == QL_ARCH.ARM64:
            self.ql.reg.arch_pc = self.ql.reg.arch_pc + 4

        next_pc = self.ql.unpack(self.ql.mem.read(self.hook_data_ptr, self.ql.pointersize))
        for cb, userdata in self.hook:
            if userdata == None:
                ret = cb(self.ql)
            else:
                ret = cb(self.ql, userdata)

            if type(ret) != int:
                ret = 0
            
            if ret & QL_CALL_BLOCK == 0:
                self.ql.reg.arch_pc = next_pc
            
            if ret & QL_HOOK_BLOCK != 0:
                break
    
    def enable(self):
        if self.rel == None or self.hook_fuc_ptr == None or self.hook_data_ptr == None:
            raise
        
        self.ori_offest = self.rel.r_offset
        self.rel.r_offset = self.hook_data_ptr - self.load_base        
        self.ql.mem.write(self.rel.ptr, self.rel.pack())

        self.ori_data = self.ql.mem.read(self.ori_offest + self.load_base, self.ql.pointersize)

        self.ql.mem.write(self.ori_offest + self.load_base, self.ql.pack(self.hook_fuc_ptr))
        self.ql.mem.write(self.hook_data_ptr, bytes(self.ori_data))
        

class ELF_Phdr:
    def __init__(self, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align

class ELF32_Phdr(ELF_Phdr):
    Phdr_SIZE = 4 * 8
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Phdr_SIZE:
            raise

        fmt = '<IIIIIIII' if endian == 0 else '>IIIIIIII'

        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(fmt, buf)
        super(ELF32_Phdr, self).__init__(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)

class ELF64_Phdr(ELF_Phdr):
    Phdr_SIZE = 8 * 7
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Phdr_SIZE:
            raise
        
        fmt = '<IIQQQQQQ' if endian == 0 else '>IIQQQQQQ'

        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(fmt, buf)
        super(ELF64_Phdr, self).__init__(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)
        
class ELF_Dyn:
    def __init__(self, d_tag, d_un):
        self.d_tag = d_tag
        self.d_un = d_un

class ELF32_Dyn(ELF_Dyn):
    Dyn_SIZE = 4 * 2
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Dyn_SIZE:
            raise
        
        fmt = '<iI' if endian == 0 else '>iI'

        d_tag, d_un = struct.unpack(fmt, buf)
        super(ELF32_Dyn, self).__init__(d_tag, d_un)

class ELF64_Dyn(ELF_Dyn):
    Dyn_SIZE = 8 * 2
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Dyn_SIZE:
            raise
        
        fmt = '<qQ' if endian == 0 else '>qQ'

        d_tag, d_un = struct.unpack(fmt, buf)
        super(ELF64_Dyn, self).__init__(d_tag, d_un)

class ELF_Rel:
    def __init__(self, r_offset, r_info):
        self.r_offset = r_offset
        self.r_info = r_info

class ELF32_Rel(ELF_Rel):
    Rel_SIZE = 4 * 2
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rel_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<II' if endian == 0 else '>II'

        r_offset, r_info = struct.unpack(self.fmt, buf)
        super(ELF32_Rel, self).__init__(r_offset, r_info)

    @property
    def r_type(self):
        return self.r_info & 0xff

    @property
    def r_sym(self):
        return self.r_info >> 8
    
    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info)

class ELF64_Rel(ELF_Rel):
    Rel_SIZE = 8 * 2
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rel_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<QQ' if endian == 0 else '>QQ'

        r_offset, r_info = struct.unpack(self.fmt, buf)
        super(ELF64_Rel, self).__init__(r_offset, r_info)

    @property
    def r_type(self):
        return self.r_info & 0xffffffff
        
    @property
    def r_sym(self):
        return self.r_info >> 32
    
    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info)


class ELF_Rela:
    def __init__(self, r_offset, r_info, r_addend):
        self.r_offset = r_offset
        self.r_info = r_info
        self.r_addend = r_addend

class ELF32_Rela(ELF_Rela):
    Rela_SIZE = 4 * 3
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rela_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<IIi' if endian == 0 else '>IIi'

        r_offset, r_info, r_addend = struct.unpack(self.fmt, buf)
        super(ELF32_Rela, self).__init__(r_offset, r_info, r_addend)

    @property
    def r_type(self):
        return self.r_info & 0xff

    @property
    def r_sym(self):
        return self.r_info >> 8
    
    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info, self.r_addend)

class ELF64_Rela(ELF_Rela):
    Rela_SIZE = 8 * 3
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rela_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<QQq' if endian == 0 else '>QQq'

        r_offset, r_info, r_addend = struct.unpack(self.fmt, buf)
        super(ELF64_Rela, self).__init__(r_offset, r_info, r_addend)

    @property
    def r_type(self):
        return self.r_info & 0xffffffff
        
    @property
    def r_sym(self):
        return self.r_info >> 32

    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info, self.r_addend)

class ELF_Sym:
    def __init__(self, st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx):
        self.st_name = st_name
        self.st_value = st_value
        self.st_size = st_size
        self.st_info = st_info
        self.st_other = st_other
        self.st_shndx = st_shndx

class ELF32_Sym(ELF_Sym):
    Sym_SIZE = 4 * 4
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Sym_SIZE:
            raise
        
        fmt = '<IIIBBH' if endian == 0 else '>IIIBBH'

        st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx = struct.unpack(fmt, buf)
        super(ELF32_Sym, self).__init__(st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx)

class ELF64_Sym(ELF_Sym):
    Sym_SIZE = 8 * 3
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Sym_SIZE:
            raise
        
        fmt = '<IBBHQQ' if endian == 0 else '>IBBHQQ'

        st_name ,st_info ,st_other ,st_shndx ,st_value ,st_size = struct.unpack(fmt, buf)
        super(ELF64_Sym, self).__init__(st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx)

class ELF_Symtab:
    def __init__(self, ql, symtab, endian = 0):
        self.ql = ql
        self.symtab = symtab
        self.endian = endian

        self.symclass = ELF32_Sym if self.ql.archbit == 32 else ELF64_Sym
    
    def __getitem__(self, idx):
        buf = self.ql.mem.read(self.symtab + idx * self.symclass.Sym_SIZE, self.symclass.Sym_SIZE)
        return self.symclass(buf, self.endian)

class ELF_Strtab:
    def __init__(self, strtab):
        self.strtab = bytes(strtab)
    
    def __getitem__(self, idx):
        return self.strtab[idx: self.strtab.index(b'\x00', idx)]

class FunctionHook:
    def __init__(self, ql, phoff, phnum, phentsize, load_base, hook_mem):
        self.ql = ql
        self.hook_mem = hook_mem
        self.phoff = phoff
        self.phnum = phnum
        self.phentsize = phentsize
        self.load_base = load_base
        self.add_function_hook = self.add_function_hook_default 

        self.dynamic = None

        self.hash_nbucket = None
        self.hash_nchain = None
        self.hash_bucket = None
        self.hash_chain = None

        self.gnu_nbucket = None
        self.gnu_symbias = None
        self.gnu_maskwords = None
        self.gnu_shift2 = None
        self.gnu_bloom_filter = None
        self.gnu_bucket = None
        self.gnu_chain = None

        self.strtab = None
        self.strtab_size = None

        self.symtab = None
        self.syment = ELF32_Sym.Sym_SIZE if ql.archbit == 32 else ELF64_Sym.Sym_SIZE

        self.plt_rel_size = None
        self.plt_rel = None
        self.plt_rel_type = DT_REL if ql.archbit == 32 else DT_RELA

        self.rela = None
        self.rela_size = None
        self.relaent = ELF32_Rela.Rela_SIZE if ql.archbit == 32 else ELF64_Rela.Rela_SIZE

        self.rel = None
        self.rel_size = None
        self.relent = ELF32_Rel.Rel_SIZE if ql.archbit == 32 else ELF64_Rel.Rel_SIZE

        self.plt_got = None
        self.mips_local_gotno = None
        self.mips_symtabno = None
        self.mips_gotsym = None

        self.rel_list = []
        self.endian = 0 if ql.archendian == QL_ENDIAN.EL else 1

        # ARM
        if self.ql.archtype== QL_ARCH.ARM:
            self.GLOB_DAT = 21
            self.JMP_SLOT = 22
            # bkpt 0; bx lr
            ins = b'p\x00 \xe1\x1e\xff/\xe1'
            self.add_function_hook = self.add_function_hook_relocation

        # MIPS32
        elif self.ql.archtype== QL_ARCH.MIPS:
            self.GLOB_DAT = 21
            self.JMP_SLOT = 22
            ins = b'\xa0\x00\x00\xef\x1e\xff/\xe1'
            self.add_function_hook = self.add_function_hook_mips

        # ARM64
        elif self.ql.archtype== QL_ARCH.ARM64:
            self.GLOB_DAT = 1025
            self.JMP_SLOT = 1026
            #brk 0; ret
            ins = b'\x00\x00 \xd4\xc0\x03_\xd6'
            self.add_function_hook = self.add_function_hook_relocation

        # X86
        elif self.ql.archtype== QL_ARCH.X86:
            self.GLOB_DAT = 6
            self.JMP_SLOT = 7
            # int 0xa0; ret
            ins = b'\xcd\xa0\xc3'.ljust(8, b'\x90')
            self.add_function_hook = self.add_function_hook_relocation

        # X8664
        elif self.ql.archtype== QL_ARCH.X8664:
            self.GLOB_DAT = 6
            self.JMP_SLOT = 7
            # int 0xa0; ret
            ins = b'\xcd\xa0\xc3'.ljust(8, b'\x90')
            self.add_function_hook = self.add_function_hook_relocation

        self._parse()
        if self.rel != None:
            self.show_relocation(self.rel)

        if self.rela != None:
            self.rel_list += self.rela
            self.show_relocation(self.rela)

        if self.plt_rel != None:
            self.rel_list += self.plt_rel
            self.show_relocation(self.plt_rel)
        
        if self.ql.archtype == QL_ARCH.MIPS and self.plt_got != None and self.mips_gotsym != None and self.mips_local_gotno != None and self.mips_symtabno != None:
            self.show_dynsym_name(self.mips_gotsym, self.mips_symtabno)

        self.ql.mem.map(hook_mem, 0x2000, perms=7, info="hook mem")
        self.ql.mem.write(hook_mem, (ins + b'\x00' * 8) * (0x2000 // 0x10))

        self.free_list = [_ for _ in range(0, 0x2000, 0x10)]
        self.use_list = {}
        self.hook_list = {}

        self.hook_int = False

    def parse_program_header32(self):
        # typedef struct elf32_phdr{
        # Elf32_Word	p_type;
        # Elf32_Off	p_offset;
        # Elf32_Addr	p_vaddr;
        # Elf32_Addr	p_paddr;
        # Elf32_Word	p_filesz;
        # Elf32_Word	p_memsz;
        # Elf32_Word	p_flags;
        # Elf32_Word	p_align;
        # } Elf32_Phdr;

        # /* 32-bit ELF base types. */
        # typedef uint32_t Elf32_Addr;
        # typedef uint16_t Elf32_Half;
        # typedef uint32_t Elf32_Off;
        # typedef int32_t  Elf32_Sword;
        # typedef uint32_t Elf32_Word;

        Psize = int(self.phentsize)
        Pnum = int(self.phnum)
        Pdata = self.ql.mem.read(self.phoff, Pnum * Psize)

        for i in range(Pnum):
            buf = Pdata[i * ELF32_Phdr.Phdr_SIZE : (i + 1) * ELF32_Phdr.Phdr_SIZE]
            P = ELF32_Phdr(buf, self.endian)
            yield P
        return

    def parse_program_header64(self):
        # typedef struct elf64_phdr {
        # Elf64_Word p_type;
        # Elf64_Word p_flags;
        # Elf64_Off p_offset;		/* Segment file offset */
        # Elf64_Addr p_vaddr;		/* Segment virtual address */
        # Elf64_Addr p_paddr;		/* Segment physical address */
        # Elf64_Xword p_filesz;		/* Segment size in file */
        # Elf64_Xword p_memsz;		/* Segment size in memory */
        # Elf64_Xword p_align;		/* Segment alignment, file & memory */
        # } Elf64_Phdr;

        # /* 64-bit ELF base types. */
        # typedef uint64_t Elf64_Addr;
        # typedef uint16_t Elf64_Half;
        # typedef int16_t	 Elf64_SHalf;
        # typedef uint64_t Elf64_Off;
        # typedef int32_t	 Elf64_Sword;
        # typedef uint32_t Elf64_Word;
        # typedef uint64_t Elf64_Xword;
        # typedef int64_t  Elf64_Sxword;

        Psize = int(self.phentsize)
        Pnum = int(self.phnum)
        Pdata = self.ql.mem.read(self.phoff, Pnum * Psize)

        for i in range(Pnum):
            buf = Pdata[i * ELF64_Phdr.Phdr_SIZE : (i + 1) * ELF64_Phdr.Phdr_SIZE]
            P = ELF64_Phdr(buf, self.endian)
            yield P
        return

    def parse_program_header(self):
        if self.ql.archbit == 64:
            return self.parse_program_header64()
        elif self.ql.archbit == 32:
            return self.parse_program_header32()

    def parse_dynamic64(self):
        # typedef struct
        # {
        # Elf64_Sxword	d_tag;			/* Dynamic entry type */
        # union
        #     {
        #     Elf64_Xword d_val;		/* Integer value */
        #     Elf64_Addr d_ptr;			/* Address value */
        #     } d_un;
        # } Elf64_Dyn;

        # /* 64-bit ELF base types. */
        # typedef uint64_t Elf64_Addr;
        # typedef uint16_t Elf64_Half;
        # typedef int16_t	 Elf64_SHalf;
        # typedef uint64_t Elf64_Off;
        # typedef int32_t	 Elf64_Sword;
        # typedef uint32_t Elf64_Word;
        # typedef uint64_t Elf64_Xword;
        # typedef int64_t  Elf64_Sxword;

        Dsize = ELF64_Dyn.Dyn_SIZE
        idx = 0

        while True:
            buf = self.ql.mem.read(self.dynamic + idx * Dsize, Dsize)
            D = ELF64_Dyn(buf, self.endian)
            yield D
            idx += 1
            if D.d_tag == DT_NULL:
                break
        return
    
    def parse_dynamic32(self):
        # typedef struct
        # {
        # Elf32_Sword	d_tag;			/* Dynamic entry type */
        # union
        #     {
        #     Elf32_Word d_val;			/* Integer value */
        #     Elf32_Addr d_ptr;			/* Address value */
        #     } d_un;
        # } Elf32_Dyn;

        # /* 32-bit ELF base types. */
        # typedef uint32_t Elf32_Addr;
        # typedef uint16_t Elf32_Half;
        # typedef uint32_t Elf32_Off;
        # typedef int32_t  Elf32_Sword;
        # typedef uint32_t Elf32_Word;
        Dsize = ELF32_Dyn.Dyn_SIZE
        idx = 0

        while True:
            buf = self.ql.mem.read(self.dynamic + idx * Dsize, Dsize)
            D = ELF32_Dyn(buf, self.endian)
            yield D
            idx += 1
            if D.d_tag == DT_NULL:
                break
        return

    def parse_dynamic(self):
        if self.ql.archbit == 64:
            return self.parse_dynamic64()
        elif self.ql.archbit == 32:
            return self.parse_dynamic32()

    def _parse(self):
        for p in self.parse_program_header():
            if p.p_type == PT_DYNAMIC:
                self.dynamic = p.p_vaddr + self.load_base
                break
        
        if self.dynamic == None:
            return

        for d in self.parse_dynamic():
            if d.d_tag == DT_NULL:
                break
            elif d.d_tag == DT_HASH:
                # self.hash_nbucket = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un, self.ql.pointersize))
                # self.hash_nchain = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize, self.ql.pointersize))
                # self.hash_bucket = self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize * 2, self.ql.pointersize * self.hash_nbucket)
                # self.hash_chain = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize * 2 + self.ql.pointersize * self.hash_nbucket, self.ql.pointersize))
                pass
            elif d.d_tag == DT_GNU_HASH:
                # self.gnu_nbucket = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un, self.ql.pointersize))
                # self.gnu_symbias = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize, self.ql.pointersize))))
                # self.gnu_maskwords = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize * 2, self.ql.pointersize))
                # self.gnu_shift2 = self.ql.unpack(self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize * 3, self.ql.pointersize))
                # self.gnu_bloom_filter = self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize * 4, self.gnu_maskwords)
                # self.gnu_bucket = self.ql.mem.read(self.load_base + d.d_un + self.ql.pointersize * 4 + self.gnu_maskwords, self.ql.pointersize * self.gnu_nbucket)
                # self.gnu_chain = self.load_base + d.d_un + self.ql.pointersize * 4 + self.gnu_maskwords + self.ql.pointersize * self.gnu_nbucket - self.ql.pointersize * self.gnu_symbias
                pass

            elif d.d_tag == DT_STRTAB:
                self.strtab = d.d_un + self.load_base
            elif d.d_tag == DT_STRSZ:
                self.strtab_size = d.d_un

            elif d.d_tag == DT_SYMTAB:
                self.symtab = d.d_un + self.load_base
            elif d.d_tag == DT_SYMENT:
                if d.d_un != self.syment:
                    raise

            elif d.d_tag == DT_PLTREL:
                if d.d_un != self.plt_rel_type:
                    raise
            elif d.d_tag == DT_PLTRELSZ:
                self.plt_rel_size = d.d_un
            elif d.d_tag == DT_JMPREL:
                self.plt_rel = d.d_un + self.load_base

            elif d.d_tag == DT_RELA:
                self.rela = d.d_un + self.load_base
            elif d.d_tag == DT_RELASZ:
                self.rela_size = d.d_un
            elif d.d_tag == DT_RELAENT:
                if self.relaent != d.d_un:
                    raise

            elif d.d_tag == DT_REL:
                self.rel = d.d_un + self.load_base
            elif d.d_tag == DT_RELSZ:
                self.rel_size = d.d_un
            elif d.d_tag == DT_RELENT:
                if self.relent != d.d_un:
                    raise

            elif d.d_tag == DT_PLTGOT:
                self.plt_got = d.d_un

            elif d.d_tag == DT_MIPS_LOCAL_GOTNO:
                self.mips_local_gotno = d.d_un
            elif d.d_tag == DT_MIPS_SYMTABNO:
                self.mips_symtabno = d.d_un
            elif d.d_tag == DT_MIPS_GOTSYM:
                self.mips_gotsym = d.d_un
            
            elif d.d_tag == DT_NEEDED:
                pass
            else:
                pass
            
        if self.strtab != None and self.strtab_size != None:
            self.strtab = ELF_Strtab(self.ql.mem.read(self.strtab, self.strtab_size))
        
        if self.rela != None and self.rela_size != None:
            rela_buf = self.ql.mem.read(self.rela, self.rela_size)
            rela_ptr = self.rela
            if self.ql.archbit == 32:
                self.rela = [ELF32_Rela(rela_buf[_ * self.relaent : (_ + 1) * self.relaent], self.endian, rela_ptr + _ * self.relaent) for _ in range(self.rela_size // self.relaent)]
            else:
                self.rela = [ELF64_Rela(rela_buf[_ * self.relaent : (_ + 1) * self.relaent], self.endian, rela_ptr + _ * self.relaent) for _ in range(self.rela_size // self.relaent)]
        
        if self.rel != None and self.rel_size != None:
            rel_buf = self.ql.mem.read(self.rel, self.rel_size)
            rel_ptr = self.rel
            if self.ql.archbit == 32:
                self.rel = [ELF32_Rel(rel_buf[_ * self.relent : (_ + 1) * self.relent], self.endian, rel_ptr + _ * self.relent) for _ in range(self.rel_size // self.relent)]
            else:
                self.rel = [ELF64_Rel(rel_buf[_ * self.relent : (_ + 1) * self.relent], self.endian, rel_ptr + _ * self.relent) for _ in range(self.rel_size // self.relent)]

        if self.plt_rel != None and self.plt_rel_size != None:
            plt_rel_buf = self.ql.mem.read(self.plt_rel, self.plt_rel_size)
            plt_rel_ptr = self.plt_rel
            if self.plt_rel_type == DT_REL:
                if self.ql.archbit == 32:
                    self.plt_rel = [ELF32_Rel(plt_rel_buf[_ * self.relent : (_ + 1) * self.relent], self.endian, plt_rel_ptr + _ * self.relent) for _ in range(self.plt_rel_size // self.relent)]
                else:
                    self.plt_rel = [ELF64_Rel(plt_rel_buf[_ * self.relent : (_ + 1) * self.relent], self.endian, plt_rel_ptr + _ * self.relent) for _ in range(self.plt_rel_size // self.relent)]
            else:
                if self.ql.archbit == 32:
                    self.plt_rel = [ELF32_Rela(plt_rel_buf[_ * self.relaent : (_ + 1) * self.relaent], self.endian, plt_rel_ptr + _ * self.relaent) for _ in range(self.plt_rel_size // self.relaent)]
                else:
                    self.plt_rel = [ELF64_Rela(plt_rel_buf[_ * self.relaent : (_ + 1) * self.relaent], self.endian, plt_rel_ptr + _ * self.relaent) for _ in range(self.plt_rel_size // self.relaent)]
        
        if self.symtab != None:
            self.symtab = ELF_Symtab(self.ql, self.symtab, self.endian)
        
    
    def show_relocation(self, rel):
        for r in rel:
            if (r.r_type == self.JMP_SLOT or r.r_type == self.GLOB_DAT) and r.r_sym != 0:
                rel_name = self.strtab[self.symtab[r.r_sym].st_name]
                self.ql.dprint(D_INFO, '[+] rel name ' + str(rel_name))
    
    def show_dynsym_name(self, s, e):
        for symidx in range(s, e):
            rel_name = self.strtab[self.symtab[symidx].st_name]
            self.ql.dprint(D_INFO, '[+] dynsym name ' + str(rel_name))

    def _hook_int(self, ql, intno):
        idx = (self.ql.reg.arch_pc - self.hook_mem) // 0x10

        if idx not in self.use_list.keys():
            raise

        self.use_list[idx].call()

    def _hook_function(self, fn, r, cb, userdata):
        if fn in self.hook_list.keys():
            self.hook_list[fn].add_hook(cb, userdata)
            return

        hf = HookFunc(self.ql, fn, r, self.load_base)
        hf.add_hook(cb, userdata)

        if len(self.free_list) == 0:
            raise
        
        hf.idx = self.free_list[0]
        del self.free_list[0]

        hf.hook_fuc_ptr = hf.idx * 0x10 + self.hook_mem
        hf.hook_data_ptr = hf.idx * 0x10 + self.hook_mem + 8

        self.use_list[hf.idx] = hf
        self.hook_list[fn] = hf

        hf.enable()

        if self.hook_int == False:
            if self.ql.archtype == QL_ARCH.X86 or self.ql.archtype == QL_ARCH.X8664:
                self.ql.hook_intno(self._hook_int, 0xa0)
            elif self.ql.archtype == QL_ARCH.ARM or self.ql.archtype == QL_ARCH.ARM64:
                self.ql.hook_intno(self._hook_int, 7)


    def add_function_hook_relocation(self, funcname, cb, userdata = None):
        if type(funcname) != str:
            raise

        for r in self.rel_list:
            if (r.r_type == self.JMP_SLOT or r.r_type == self.GLOB_DAT) and r.r_sym != 0:
                tmp_name = self.strtab[self.symtab[r.r_sym].st_name]
                if tmp_name == funcname.encode():
                    self._hook_function(tmp_name, r, cb, userdata)
    
    def add_function_hook_default(self, funcname, cb, userdata = None):
        pass
    
    def add_function_hook_mips(self, funcname, cb, userdata = None):
        self.add_function_hook_relocation(funcname, cb, userdata)

        for symidx in range(self.mips_gotsym, self.mips_symtabno):
            tmp_name = self.strtab[self.symtab[symidx].st_name]
            if tmp_name == funcname.encode():
                pass

    def _load_import(self):
        pass
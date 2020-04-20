


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

class symbol:
    def __init__(self, ql, phoff, phnum, phentsize, load_base):
        self.ql = ql
        self.phoff = phoff
        self.phnum = phnum
        self.phentsize = phentsize
        self.load_base = load_base
        self._parse()

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
            P = {}
            P['p_type']     = self.ql.unpack32(Pdata[i * Psize : i * Psize + 4 ])
            P['p_offset']   = self.ql.unpack32(Pdata[i * Psize + 4 : i * Psize + 8 ])
            P['p_vaddr']    = self.ql.unpack32(Pdata[i * Psize + 8 : i * Psize + 12 ])
            P['p_paddr']    = self.ql.unpack32(Pdata[i * Psize + 12 : i * Psize + 16 ])
            P['p_filesz']   = self.ql.unpack32(Pdata[i * Psize + 16 : i * Psize + 20 ])
            P['p_memsz']    = self.ql.unpack32(Pdata[i * Psize + 20 : i * Psize + 24 ])
            P['p_flags']    = self.ql.unpack32(Pdata[i * Psize + 24 : i * Psize + 28 ])
            P['p_align']    = self.ql.unpack32(Pdata[i * Psize + 28 : i * Psize + 32])
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
            P = {}
            P['p_type']     = self.ql.unpack32(Pdata[i * Psize : i * Psize + 4 ])
            P['p_flags']    = self.ql.unpack32(Pdata[i * Psize + 4 : i * Psize + 8 ])
            P['p_offset']   = self.ql.unpack64(Pdata[i * Psize + 8 : i * Psize + 16 ])
            P['p_vaddr']    = self.ql.unpack64(Pdata[i * Psize + 16 : i * Psize + 24 ])
            P['p_paddr']    = self.ql.unpack64(Pdata[i * Psize + 24 : i * Psize + 32 ])
            P['p_filesz']   = self.ql.unpack64(Pdata[i * Psize + 32 : i * Psize + 40 ])
            P['p_memsz']    = self.ql.unpack64(Pdata[i * Psize + 40 : i * Psize + 48 ])
            P['p_align']    = self.ql.unpack64(Pdata[i * Psize + 48 : i * Psize + 56])
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

        Dsize = 8 * 2
        idx = 0

        while True:
            Ddata = self.ql.read(self.dynamic + idx * Dsize, Dsize)
            D = {}
            D['d_tag']  = self.ql.unpack64(Ddata[0 : 8])
            D['d_un']   = self.ql.unpack64(Ddata[8 : 16])
            yield D
            if D['d_tag'] == DT_NULL:
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
        Dsize = 4 * 2
        idx = 0

        while True:
            Ddata = self.ql.read(self.dynamic + idx * Dsize, Dsize)
            D = {}
            D['d_tag']  = self.ql.unpack64(Ddata[0 : 4])
            D['d_un']   = self.ql.unpack64(Ddata[4 : 8])
            yield D
            if D['d_tag'] == DT_NULL:
                break
        return

    def parse_dynamic(self):
        if self.ql.archbit == 64:
            return self.parse_dynamic64()
        elif self.ql.archbit == 32:
            return self.parse_dynamic32()

    def _parse(self):
        for p in self.parse_program_header():
            if p['p_type'] == PT_DYNAMIC:
                self.dynamic = p['p_vaddr']
                break
        
        for d in self.parse_dynamic():
            if d['d_tag'] == DT_NULL:
                break
            elif d['d_tag'] == DT_HASH:
                pass
            elif d['d_tag'] == DT_GNU_HASH:
                pass
            elif d['d_tag'] == DT_STRTAB:
                pass
            elif d['d_tag'] == DT_STRSZ:
                pass
            elif d['d_tag'] == DT_SYMTAB:
                pass
            elif d['d_tag'] == DT_SYMENT:
                pass
            elif d['d_tag'] == DT_PLTREL:
                pass
            elif d['d_tag'] == DT_PLTRELSZ:
                pass
            elif d['d_tag'] == DT_JMPREL:
                pass
            elif d['d_tag'] == DT_RELA:
                pass
            elif d['d_tag'] == DT_RELASZ:
                pass
            elif d['d_tag'] == DT_RELAENT:
                pass
            elif d['d_tag'] == DT_REL:
                pass
            elif d['d_tag'] == DT_RELSZ:
                pass
            else:
                raise
        
        

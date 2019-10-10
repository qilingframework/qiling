from .define_value import *
from .utils import *
from struct import unpack


class LoadCommand:

    def __init__(self, data):
        self.data = data
        self.FR = FileReader(data)
        self.cmd_id = unpack("<L", self.FR.read(4))[0]
        self.cmd_size = unpack("<L", self.FR.read(4))[0]
        pass

    def get_complete(self):
        
        if self.cmd_id == LC_SEGMENT_64:
            return LoadSegment64(self.data)
        if self.cmd_id == LC_SEGMENT:
            return LoadSegment32(self.data)
        if self.cmd_id == LC_SYMTAB:
            return LoadSymtab(self.data)
        if self.cmd_id == LC_DYSYMTAB:
            return LoadDysymtab(self.data)
        if self.cmd_id == LC_ID_DYLINKER:
            return LoadIdDylinker(self.data)
        if self.cmd_id == LC_UUID:
            return LoadUuid(self.data)
        if self.cmd_id == LC_VERSION_MIN_MACOSX:
            return LoadVersionMinMacosx(self.data)
        if self.cmd_id == LC_SOURCE_VERSION:
            return LoadSourceVersion(self.data)
        if self.cmd_id == LC_UNIXTHREAD:
            return LoadUnixThread(self.data)
        if self.cmd_id == LC_SEGMENT_SPLIT_INFO:
            return LoadSegmentSplitInfo(self.data)
        if self.cmd_id == LC_FUNCTION_STARTS:
            return LoadFunctionStarts(self.data)
        if self.cmd_id == LC_DATA_IN_CODE:
            return LoadDataInCode(self.data)
        if self.cmd_id == LC_CODE_SIGNATURE:
            return LoadCodeSignature(self.data)
        if self.cmd_id == LC_DYLD_INFO_ONLY:
            return LoadDyldInfoOnly(self.data)
        if self.cmd_id == LC_LOAD_DYLINKER:
            return LoadDylinker(self.data)
        if self.cmd_id == LC_MAIN:
            return LoadMain(self.data)
        if self.cmd_id == LC_LOAD_DYLIB:
            return LoadDyLib(self.data)
    

class LoadSegment(LoadCommand):
    
    def __init__(self, data):
        super().__init__(data)
        self.segment_name = self.FR.read(0x10).decode("utf-8")

    def get_complete(self):
        pass


class LoadSegment32(LoadSegment):
    
    def __init__(self, data):
        super().__init__(data)
        self.vm_address = unpack("<L", self.FR.read(4))[0]
        self.vm_size = unpack("<L", self.FR.read(4))[0]
        self.file_offset = unpack("<L", self.FR.read(4))[0]
        self.file_size = unpack("<L", self.FR.read(4))[0]
        self.maximum_vm_protection = unpack("<L", self.FR.read(4))[0]
        self.initial_vm_protection = unpack("<L", self.FR.read(4))[0]
        self.number_of_sections = unpack("<L", self.FR.read(4))[0]
        self.flags = unpack("<L", self.FR.read(4))[0]
        self.sections = []
        if self.number_of_sections:
            for i in range(self.number_of_sections):
                self.sections.append(LoadSection32(self.FR.read(0x44)))

    def get_complete(self):
        pass


class LoadSegment64(LoadSegment):

    def __init__(self, data):
        super().__init__(data)
        self.vm_address = unpack("<Q", self.FR.read(8))[0]
        self.vm_size = unpack("<Q", self.FR.read(8))[0]
        self.file_offset = unpack("<Q", self.FR.read(8))[0]
        self.file_size = unpack("<Q", self.FR.read(8))[0]
        self.maximum_vm_protection = unpack("<L", self.FR.read(4))[0]
        self.initial_vm_protection = unpack("<L", self.FR.read(4))[0]
        self.number_of_sections = unpack("<L", self.FR.read(4))[0]
        self.flags = unpack("<L", self.FR.read(4))[0]
        self.sections = []
        if self.number_of_sections:
            for i in range(self.number_of_sections):
                self.sections.append(LoadSection64(self.FR.read(0x50)))
        
    def __str__(self):
        return (" SEG64:Seg Name %s, vmaddr 0x%X, vm size 0x%X, file offset 0x%X, file size 0x%X, max vp 0x%X, init vp 0x%X, section num %d, flags 0x%X" % (
           self.segment_name, self.vm_address, self.vm_size, self.file_offset, self.file_size, self.maximum_vm_protection,
           self.initial_vm_protection, self.number_of_sections, self.flags 
        ))

    def get_complete(self):
        pass


class LoadSymtab(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.symbol_table_offset = unpack("<L", self.FR.read(4))[0]
        self.number_of_symbols = unpack("<L", self.FR.read(4))[0]
        self.string_table_offset = unpack("<L", self.FR.read(4))[0]
        self.string_table_size = unpack("<L", self.FR.read(4))[0]


    def __str__(self):
        return (" Symtab: sym table offset 0x%X, sym num 0x%X, str table offset 0x%X, str table size 0x%X" % (
            self.symbol_table_offset, self.number_of_symbols, self.string_table_offset, self.string_table_size
        ))

    def get_complete(self):
        pass


class LoadDysymtab(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.locsymbol_index = unpack("<L", self.FR.read(4))[0]
        self.locsymbol_number = unpack("<L", self.FR.read(4))[0]
        self.defined_extsymbol_index = unpack("<L", self.FR.read(4))[0]
        self.defined_extsymbol_number = unpack("<L", self.FR.read(4))[0]
        self.undef_extsymbol_index = unpack("<L", self.FR.read(4))[0]
        self.undef_extsymbol_number = unpack("<L", self.FR.read(4))[0]
        self.toc_offset = unpack("<L", self.FR.read(4))[0]
        self.toc_entries = unpack("<L", self.FR.read(4))[0]
        self.module_table_offset = unpack("<L", self.FR.read(4))[0]
        self.module_table_entries = unpack("<L", self.FR.read(4))[0]
        self.extref_table_offset = unpack("<L", self.FR.read(4))[0]
        self.extref_table_entries = unpack("<L", self.FR.read(4))[0]
        self.indsym_table_offset = unpack("<L", self.FR.read(4))[0]
        self.indsym_table_entries = unpack("<L", self.FR.read(4))[0]
        self.extreloc_table_offset = unpack("<L", self.FR.read(4))[0]
        self.extref_table_entries = unpack("<L", self.FR.read(4))[0]
        self.locreloc_table_offset = unpack("<L", self.FR.read(4))[0]
        self.locreloc_table_entries = unpack("<L", self.FR.read(4))[0]

    def get_complete(self):
        pass


class LoadDylinker(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.str_offset = unpack("<L", self.FR.read(4))[0]
        self.name = self.FR.readString(4)

    def __str__(self):
        return (" DyLinker: Name %s" % self.name)

    def get_complete(self):
        pass


class LoadIdDylinker(LoadCommand):

    def __init__(self, data):
        super().__init__(data)

    def get_complete(self):
        pass


class LoadUuid(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.uuid = self.FR.read(16)

    def get_complete(self):
        pass


class LoadVersionMinMacosx(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.version = unpack("<L", self.FR.read(4))[0]
        self.reserved = unpack("<L", self.FR.read(4))[0]

    def __str__(self):
        return (" VersionMinMacosx: version %X" % self.version)

    def get_complete(self):
        pass


class LoadSourceVersion(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.version = unpack("<Q", self.FR.read(8))[0]

    def get_complete(self):
        pass


class LoadMain(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.entry_offset = unpack("<Q", self.FR.read(8))[0]
        self.stack_size = unpack("<Q", self.FR.read(8))[0]

    def get_complete(self):
        pass


class LoadDyLib(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.str_offset = unpack("<L", self.FR.read(4))[0]
        self.time_stamp = unpack("<L", self.FR.read(4))[0]
        self.current_version = unpack("<L", self.FR.read(4))[0]
        self.compatibility_version = unpack("<L", self.FR.read(4))[0]
        self.name = self.FR.readString(4)
    
    def __str__(self):
        return (" Dylib: name %s" % self.name)

    def get_complete(self):
        pass


class LoadUnixThread(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.flavor = unpack("<L", self.FR.read(4))[0]
        self.count = unpack("<L", self.FR.read(4))[0]
        if self.flavor == X86_THREAD_STATE32:
            self.eax = unpack("<L", self.FR.read(4))[0]
            self.ebx = unpack("<L", self.FR.read(4))[0]
            self.ecx = unpack("<L", self.FR.read(4))[0]
            self.edx = unpack("<L", self.FR.read(4))[0]
            self.ebi = unpack("<L", self.FR.read(4))[0]
            self.esi = unpack("<L", self.FR.read(4))[0]
            self.ebp = unpack("<L", self.FR.read(4))[0]
            self.esp = unpack("<L", self.FR.read(4))[0]
            self.ss = unpack("<L", self.FR.read(4))[0]
            self.eflags = unpack("<L", self.FR.read(4))[0]
            self.eip = unpack("<L", self.FR.read(4))[0]
            self.cs = unpack("<L", self.FR.read(4))[0]
            self.ds = unpack("<L", self.FR.read(4))[0]
            self.es = unpack("<L", self.FR.read(4))[0]
            self.fs = unpack("<L", self.FR.read(4))[0]
            self.gs = unpack("<L", self.FR.read(4))[0]
            self.entry = self.eip
        elif self.flavor == X86_THREAD_STATE64:
            self.rax = unpack("<Q", self.FR.read(8))[0]
            self.rbx = unpack("<Q", self.FR.read(8))[0]
            self.rcx = unpack("<Q", self.FR.read(8))[0]
            self.rdx = unpack("<Q", self.FR.read(8))[0]
            self.rdi = unpack("<Q", self.FR.read(8))[0]
            self.rsi = unpack("<Q", self.FR.read(8))[0]
            self.rbp = unpack("<Q", self.FR.read(8))[0]
            self.rsp = unpack("<Q", self.FR.read(8))[0]
            self.r8 = unpack("<Q", self.FR.read(8))[0]
            self.r9 = unpack("<Q", self.FR.read(8))[0]
            self.r10 = unpack("<Q", self.FR.read(8))[0]
            self.r11 = unpack("<Q", self.FR.read(8))[0]
            self.r12 = unpack("<Q", self.FR.read(8))[0]
            self.r13 = unpack("<Q", self.FR.read(8))[0]
            self.r14 = unpack("<Q", self.FR.read(8))[0]
            self.r15 = unpack("<Q", self.FR.read(8))[0]
            self.rip = unpack("<Q", self.FR.read(8))[0]
            self.rflags = unpack("<Q", self.FR.read(8))[0]
            self.cs = unpack("<Q", self.FR.read(8))[0]
            self.fs = unpack("<Q", self.FR.read(8))[0]
            self.gs = unpack("<Q", self.FR.read(8))[0]
            self.entry = self.rip

    def __str__(self):
        return (" Unixthread: entry 0x%X" %self.entry)  

    def get_complete(self):
        pass


class LoadSegmentSplitInfo(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset = unpack("<L", self.FR.read(4))[0]
        self.data_size = unpack("<L", self.FR.read(4))[0]

    def get_complete(self):
        pass


class LoadFunctionStarts(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset = unpack("<L", self.FR.read(4))[0]
        self.data_size = unpack("<L", self.FR.read(4))[0]

    def get_complete(self):
        pass


class LoadDataInCode(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset = unpack("<L", self.FR.read(4))[0]
        self.data_size = unpack("<L", self.FR.read(4))[0]

    def __str__(self):
        return (" Data in code: offset 0x%X" % self.data_offset)

    def get_complete(self):
        pass


class LoadCodeSignature(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset = unpack("<L", self.FR.read(4))[0]
        self.data_size = unpack("<L", self.FR.read(4))[0]

    def __str__(self):
        return (" CodeSignature: offset 0x%X" % self.data_offset)

    def get_complete(self):
        pass


class LoadDyldInfoOnly(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.rebase_info_offset = unpack("<L", self.FR.read(4))[0]
        self.rebase_info_size = unpack("<L", self.FR.read(4))[0]
        self.binding_info_offset = unpack("<L", self.FR.read(4))[0]
        self.binding_info_size = unpack("<L", self.FR.read(4))[0]
        self.weak_binding_info_offset = unpack("<L", self.FR.read(4))[0]
        self.weak_binding_info_size = unpack("<L", self.FR.read(4))[0]
        self.lazy_binding_info_offset = unpack("<L", self.FR.read(4))[0]
        self.lazy_binding_info_size = unpack("<L", self.FR.read(4))[0]
        self.export_info_offset = unpack("<L", self.FR.read(4))[0]
        self.export_info_size = unpack("<L", self.FR.read(4))[0]

    def __str__(self):
        return (" DyldInfoOnly: rebase offset: 0x%X, rebase size 0x%X, binding offset 0x%X, binding size 0x%X,\
 weak offset 0x%X, weak size 0x%X, lazy offset 0x%X, lazy size 0x%X, export offset 0x%X, export size 0x%X" %(
            self.rebase_info_offset, self.rebase_info_size, self.binding_info_offset, self.binding_info_size,
            self.weak_binding_info_offset, self.weak_binding_info_size, self.lazy_binding_info_offset,
            self.lazy_binding_info_size, self.export_info_offset, self.export_info_size 
        ))

    def get_complete(self):
        pass


class LoadSection:

    def __init__(self, data):
        self.FR = FileReader(data)
        self.section_name = self.FR.read(0x10).decode("utf-8")
        self.segment_name = self.FR.read(0x10).decode("utf-8")
        

class LoadSection32(LoadSection):

    # size 0x44
    def __init__(self, data):
        super().__init__(data)
        self.address = unpack("<L", self.FR.read(4))[0]
        self.size = unpack("<L", self.FR.read(4))[0]
        self.offset = unpack("<L", self.FR.read(4))[0]
        self.alignment = unpack("<L", self.FR.read(4))[0]
        self.relocations_offset = unpack("<L", self.FR.read(4))[0]
        self.number_of_relocations = unpack("<L", self.FR.read(4))[0]
        self.flags = unpack("<L", self.FR.read(4))[0]
        self.reserved1 = unpack("<L", self.FR.read(4))[0]
        self.reserved2 = unpack("<L", self.FR.read(4))[0]
  
    def __str__(self):
        return ("     Section name %s, Seg name %s, addr 0x%X, size 0x%X, offset 0x%X, align 0x%X, rel offset 0x%X, rel num %d, flags 0x%X" % (
            self.section_name, self.segment_name, self.address, self.size, self.offset, self.alignment, self.relocations_offset,
            self.number_of_relocations, self.flags
        ))


class LoadSection64(LoadSection):

    # size 0x50
    def __init__(self, data):
        super().__init__(data)
        self.address = unpack("<Q", self.FR.read(8))[0]
        self.size = unpack("<Q", self.FR.read(8))[0]
        self.offset = unpack("<L", self.FR.read(4))[0]
        self.alignment = unpack("<L", self.FR.read(4))[0]
        self.relocations_offset = unpack("<L", self.FR.read(4))[0]
        self.number_of_relocations = unpack("<L", self.FR.read(4))[0]
        self.flags = unpack("<L", self.FR.read(4))[0]
        self.reserved1 = unpack("<L", self.FR.read(4))[0]
        self.reserved2 = unpack("<L", self.FR.read(4))[0]
        self.reserved3 = unpack("<L", self.FR.read(4))[0]
        
    def __str__(self):
        return ("     Sec64: Section name %s, Seg name %s, addr 0x%X, size 0x%X, offset 0x%X, align 0x%X, rel offset 0x%X, rel num %d, flags 0x%X" % (
            self.section_name, self.segment_name, self.address, self.size, self.offset, self.alignment, self.relocations_offset,
            self.number_of_relocations, self.flags
        ))
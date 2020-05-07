#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .const import *
from .utils import *
from struct import unpack

# TODO: We need support more LC command to load more kinds of binary

class LoadCommand:

    def __init__(self, data):
        self.data = data
        self.FR = FileReader(data)
        self.cmd_id = unpack("<L", self.FR.read(4))[0]
        self.cmd_size = unpack("<L", self.FR.read(4))[0]
        pass

    def get_complete(self):
        cmd_map = {
            LC_SEGMENT_64           :   LoadSegment64,
            LC_SEGMENT              :   LoadSegment32,
            LC_SYMTAB               :   LoadSymtab,
            LC_DYSYMTAB             :   LoadDysymtab,
            LC_ID_DYLINKER          :   LoadIdDylinker,
            LC_UUID                 :   LoadUuid,
            LC_VERSION_MIN_MACOSX   :   LoadVersionMinMacosx,
            LC_VERSION_MIN_IPHONEOS :   LoadVersionMinIphoneos,
            LC_SOURCE_VERSION       :   LoadSourceVersion,
            LC_UNIXTHREAD           :   LoadUnixThread,
            LC_SEGMENT_SPLIT_INFO   :   LoadSegmentSplitInfo,
            LC_FUNCTION_STARTS      :   LoadFunctionStarts,
            LC_DATA_IN_CODE         :   LoadDataInCode,
            LC_CODE_SIGNATURE       :   LoadCodeSignature,
            LC_DYLD_INFO_ONLY       :   LoadDyldInfoOnly,
            LC_LOAD_DYLINKER        :   LoadDylinker,
            LC_MAIN                 :   LoadMain,
            LC_LOAD_DYLIB           :   LoadDyLib,
            LC_ENCRYPTION_INFO_64   :   LoadEncryptionInfo64,
            LC_DYLD_EXPORTS_TRIE    :   LoadDyldExportTrie,
            LC_DYLD_CHAINED_FIXUPS  :   LoadDyldChainedFixups,
            LC_BUILD_VERSION        :   LoadBuildVersion
        }

        exec_func = cmd_map.get(self.cmd_id)
        if exec_func:
            return exec_func(self.data)
    

class LoadSegment(LoadCommand):
    
    def __init__(self, data):
        super().__init__(data)
        self.segment_name = self.FR.read(0x10).decode("utf-8")

    def get_complete(self):
        pass


class LoadSegment32(LoadSegment):
    
    def __init__(self, data):
        super().__init__(data)
        self.vm_address             = unpack("<L", self.FR.read(4))[0]
        self.vm_size                = unpack("<L", self.FR.read(4))[0]
        self.file_offset            = unpack("<L", self.FR.read(4))[0]
        self.file_size              = unpack("<L", self.FR.read(4))[0]
        self.maximum_vm_protection  = unpack("<L", self.FR.read(4))[0]
        self.initial_vm_protection  = unpack("<L", self.FR.read(4))[0]
        self.number_of_sections     = unpack("<L", self.FR.read(4))[0]
        self.flags                  = unpack("<L", self.FR.read(4))[0]
        self.sections               = []
        if self.number_of_sections:
            for i in range(self.number_of_sections):
                self.sections.append(LoadSection32(self.FR.read(0x44)))

    def get_complete(self):
        pass


class LoadSegment64(LoadSegment):
    # FIXME: segmengs should not be fixed size of 0x1000, should be calculated
    # header mark as 0x1000 but it seems we need count it to matched IDApro
    def __init__(self, data):
        super().__init__(data)
        self.vm_address             = unpack("<Q", self.FR.read(8))[0]
        self.vm_size                = unpack("<Q", self.FR.read(8))[0]
        self.file_offset            = unpack("<Q", self.FR.read(8))[0]
        self.file_size              = unpack("<Q", self.FR.read(8))[0]
        self.maximum_vm_protection  = unpack("<L", self.FR.read(4))[0]
        self.initial_vm_protection  = unpack("<L", self.FR.read(4))[0]
        self.number_of_sections     = unpack("<L", self.FR.read(4))[0]
        self.flags                  = unpack("<L", self.FR.read(4))[0]
        self.sections               = []
        if self.number_of_sections:
            for i in range(self.number_of_sections):
                self.sections.append(LoadSection64(self.FR.read(0x50)))
        
    # def __str__(self):
    #     return (" SEG64:Seg Name %s, vmaddr 0x%X, vm size 0x%X, file offset 0x%X, file size 0x%X, max vp 0x%X, init vp 0x%X, section num %d, flags 0x%X" % (
    #        self.segment_name, self.vm_address, self.vm_size, self.file_offset, self.file_size, self.maximum_vm_protection,
    #        self.initial_vm_protection, self.number_of_sections, self.flags 
    #     ))

    def get_complete(self):
        pass


class LoadSymtab(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.symbol_table_offset    = unpack("<L", self.FR.read(4))[0]
        self.number_of_symbols      = unpack("<L", self.FR.read(4))[0]
        self.string_table_offset    = unpack("<L", self.FR.read(4))[0]
        self.string_table_size      = unpack("<L", self.FR.read(4))[0]


    # def __str__(self):
    #     return (" Symtab: sym table offset 0x%X, sym num 0x%X, str table offset 0x%X, str table size 0x%X" % (
    #         self.symbol_table_offset, self.number_of_symbols, self.string_table_offset, self.string_table_size
    #     ))

    def get_complete(self):
        pass


class LoadDysymtab(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.locsymbol_index            = unpack("<L", self.FR.read(4))[0]
        self.locsymbol_number           = unpack("<L", self.FR.read(4))[0]
        self.defined_extsymbol_index    = unpack("<L", self.FR.read(4))[0]
        self.defined_extsymbol_number   = unpack("<L", self.FR.read(4))[0]
        self.undef_extsymbol_index      = unpack("<L", self.FR.read(4))[0]
        self.undef_extsymbol_number     = unpack("<L", self.FR.read(4))[0]
        self.toc_offset                 = unpack("<L", self.FR.read(4))[0]
        self.toc_entries                = unpack("<L", self.FR.read(4))[0]
        self.module_table_offset        = unpack("<L", self.FR.read(4))[0]
        self.module_table_entries       = unpack("<L", self.FR.read(4))[0]
        self.extref_table_offset        = unpack("<L", self.FR.read(4))[0]
        self.extref_table_entries       = unpack("<L", self.FR.read(4))[0]
        self.indsym_table_offset        = unpack("<L", self.FR.read(4))[0]
        self.indsym_table_entries       = unpack("<L", self.FR.read(4))[0]
        self.extreloc_table_offset      = unpack("<L", self.FR.read(4))[0]
        self.extreloc_table_entries     = unpack("<L", self.FR.read(4))[0]
        self.locreloc_table_offset      = unpack("<L", self.FR.read(4))[0]
        self.locreloc_table_entries     = unpack("<L", self.FR.read(4))[0]

    def get_complete(self):
        pass


class LoadDylinker(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.str_offset = unpack("<L", self.FR.read(4))[0]
        self.name = self.FR.readString(4)

    # def __str__(self):
    #     return (" DyLinker: Name %s" % self.name)

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
        self.version    = unpack("<L", self.FR.read(4))[0]
        self.reserved   = unpack("<L", self.FR.read(4))[0]

    # def __str__(self):
    #     return (" VersionMinMacosx: version %X" % self.version)

    def get_complete(self):
        pass

class LoadVersionMinIphoneos(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.version    = unpack("<L", self.FR.read(4))[0]
        self.reserved   = unpack("<L", self.FR.read(4))[0]

    # def __str__(self):
    #     return (" VersionMinIphoneos: version %X" % self.version)

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
        self.entry_offset   = unpack("<Q", self.FR.read(8))[0]
        self.stack_size     = unpack("<Q", self.FR.read(8))[0]

    def get_complete(self):
        pass


class LoadDyLib(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.str_offset             = unpack("<L", self.FR.read(4))[0]
        self.time_stamp             = unpack("<L", self.FR.read(4))[0]
        self.current_version        = unpack("<L", self.FR.read(4))[0]
        self.compatibility_version  = unpack("<L", self.FR.read(4))[0]
        self.name                   = self.FR.readString(4)
    
    # def __str__(self):
    #     return (" Dylib: name %s" % self.name)

    def get_complete(self):
        pass


class LoadUnixThread(LoadCommand):

    def __init__(self, data):
        super().__init__(data)

        self.flavor = unpack("<L", self.FR.read(4))[0]
        self.count  = unpack("<L", self.FR.read(4))[0]
        
        if self.flavor == X86_THREAD_STATE32:
            self.eax        = unpack("<L", self.FR.read(4))[0]
            self.ebx        = unpack("<L", self.FR.read(4))[0]
            self.ecx        = unpack("<L", self.FR.read(4))[0]
            self.edx        = unpack("<L", self.FR.read(4))[0]
            self.ebi        = unpack("<L", self.FR.read(4))[0]
            self.esi        = unpack("<L", self.FR.read(4))[0]
            self.ebp        = unpack("<L", self.FR.read(4))[0]
            self.esp        = unpack("<L", self.FR.read(4))[0]
            self.ss         = unpack("<L", self.FR.read(4))[0]
            self.eflags     = unpack("<L", self.FR.read(4))[0]
            self.eip        = unpack("<L", self.FR.read(4))[0]
            self.cs         = unpack("<L", self.FR.read(4))[0]
            self.ds         = unpack("<L", self.FR.read(4))[0]
            self.es         = unpack("<L", self.FR.read(4))[0]
            self.fs         = unpack("<L", self.FR.read(4))[0]
            self.gs         = unpack("<L", self.FR.read(4))[0]
            self.entry      = self.eip
        
        elif self.flavor == X86_THREAD_STATE64:
            self.rax        = unpack("<Q", self.FR.read(8))[0]
            self.rbx        = unpack("<Q", self.FR.read(8))[0]
            self.rcx        = unpack("<Q", self.FR.read(8))[0]
            self.rdx        = unpack("<Q", self.FR.read(8))[0]
            self.rdi        = unpack("<Q", self.FR.read(8))[0]
            self.rsi        = unpack("<Q", self.FR.read(8))[0]
            self.rbp        = unpack("<Q", self.FR.read(8))[0]
            self.rsp        = unpack("<Q", self.FR.read(8))[0]
            self.r8         = unpack("<Q", self.FR.read(8))[0]
            self.r9         = unpack("<Q", self.FR.read(8))[0]
            self.r10        = unpack("<Q", self.FR.read(8))[0]
            self.r11        = unpack("<Q", self.FR.read(8))[0]
            self.r12        = unpack("<Q", self.FR.read(8))[0]
            self.r13        = unpack("<Q", self.FR.read(8))[0]
            self.r14        = unpack("<Q", self.FR.read(8))[0]
            self.r15        = unpack("<Q", self.FR.read(8))[0]
            self.rip        = unpack("<Q", self.FR.read(8))[0]
            self.rflags     = unpack("<Q", self.FR.read(8))[0]
            self.cs         = unpack("<Q", self.FR.read(8))[0]
            self.fs         = unpack("<Q", self.FR.read(8))[0]
            self.gs         = unpack("<Q", self.FR.read(8))[0]
            self.entry      = self.rip
        
        elif self.flavor == ARM_THREAD_STATE64:
            self.x0         = unpack("<Q", self.FR.read(8))[0]
            self.x1         = unpack("<Q", self.FR.read(8))[0]
            self.x2         = unpack("<Q", self.FR.read(8))[0]
            self.x3         = unpack("<Q", self.FR.read(8))[0]
            self.x4         = unpack("<Q", self.FR.read(8))[0]
            self.x5         = unpack("<Q", self.FR.read(8))[0]
            self.x6         = unpack("<Q", self.FR.read(8))[0]
            self.x7         = unpack("<Q", self.FR.read(8))[0]
            self.x8         = unpack("<Q", self.FR.read(8))[0]
            self.x9         = unpack("<Q", self.FR.read(8))[0]
            self.x10        = unpack("<Q", self.FR.read(8))[0]
            self.x11        = unpack("<Q", self.FR.read(8))[0]
            self.x12        = unpack("<Q", self.FR.read(8))[0]
            self.x13        = unpack("<Q", self.FR.read(8))[0]
            self.x14        = unpack("<Q", self.FR.read(8))[0]
            self.x15        = unpack("<Q", self.FR.read(8))[0]
            self.x16        = unpack("<Q", self.FR.read(8))[0]
            self.x17        = unpack("<Q", self.FR.read(8))[0]
            self.x18        = unpack("<Q", self.FR.read(8))[0]
            self.x19        = unpack("<Q", self.FR.read(8))[0]
            self.x20        = unpack("<Q", self.FR.read(8))[0]
            self.x21        = unpack("<Q", self.FR.read(8))[0]            
            self.r22        = unpack("<Q", self.FR.read(8))[0]
            self.x23        = unpack("<Q", self.FR.read(8))[0]
            self.x24        = unpack("<Q", self.FR.read(8))[0]
            self.x25        = unpack("<Q", self.FR.read(8))[0]
            self.x26        = unpack("<Q", self.FR.read(8))[0]
            self.x27        = unpack("<Q", self.FR.read(8))[0]            
            self.x28        = unpack("<Q", self.FR.read(8))[0]
            self.x29        = unpack("<Q", self.FR.read(8))[0]
            self.x30        = unpack("<Q", self.FR.read(8))[0]            
            self.sp         = unpack("<Q", self.FR.read(8))[0]            
            self.pc         = unpack("<Q", self.FR.read(8))[0]
            self.entry      = self.pc

    #def __str__(self):
    #    return (" Unixthread: entry 0x%X" %self.entry)  

    def get_complete(self):
        pass


class LoadSegmentSplitInfo(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset    = unpack("<L", self.FR.read(4))[0]
        self.data_size      = unpack("<L", self.FR.read(4))[0]

    def get_complete(self):
        pass


class LoadFunctionStarts(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset    = unpack("<L", self.FR.read(4))[0]
        self.data_size      = unpack("<L", self.FR.read(4))[0]

    def get_complete(self):
        pass


class LoadDataInCode(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset    = unpack("<L", self.FR.read(4))[0]
        self.data_size      = unpack("<L", self.FR.read(4))[0]

    # def __str__(self):
    #     return (" Data in code: offset 0x%X" % self.data_offset)

    def get_complete(self):
        pass


class LoadCodeSignature(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.data_offset    = unpack("<L", self.FR.read(4))[0]
        self.data_size      = unpack("<L", self.FR.read(4))[0]

    # def __str__(self):
    #     return (" CodeSignature: offset 0x%X" % self.data_offset)

    def get_complete(self):
        pass


class LoadDyldInfoOnly(LoadCommand):

    def __init__(self, data):
        super().__init__(data)
        self.rebase_info_offset         = unpack("<L", self.FR.read(4))[0]
        self.rebase_info_size           = unpack("<L", self.FR.read(4))[0]
        self.binding_info_offset        = unpack("<L", self.FR.read(4))[0]
        self.binding_info_size          = unpack("<L", self.FR.read(4))[0]
        self.weak_binding_info_offset   = unpack("<L", self.FR.read(4))[0]
        self.weak_binding_info_size     = unpack("<L", self.FR.read(4))[0]
        self.lazy_binding_info_offset   = unpack("<L", self.FR.read(4))[0]
        self.lazy_binding_info_size     = unpack("<L", self.FR.read(4))[0]
        self.export_info_offset         = unpack("<L", self.FR.read(4))[0]
        self.export_info_size           = unpack("<L", self.FR.read(4))[0]

#     def __str__(self):
#         return (" DyldInfoOnly: rebase offset: 0x%X, rebase size 0x%X, binding offset 0x%X, binding size 0x%X,\
#  weak offset 0x%X, weak size 0x%X, lazy offset 0x%X, lazy size 0x%X, export offset 0x%X, export size 0x%X" %(
#             self.rebase_info_offset, self.rebase_info_size, self.binding_info_offset, self.binding_info_size,
#             self.weak_binding_info_offset, self.weak_binding_info_size, self.lazy_binding_info_offset,
#             self.lazy_binding_info_size, self.export_info_offset, self.export_info_size 
#         ))

    def get_complete(self):
        pass


class LoadSection:

    def __init__(self, data):
        self.FR = FileReader(data)
        self.section_name   = self.FR.read(0x10).decode("utf-8")
        self.segment_name   = self.FR.read(0x10).decode("utf-8")
        

class LoadSection32(LoadSection):

    # size 0x44
    def __init__(self, data):
        super().__init__(data)
        self.address                = unpack("<L", self.FR.read(4))[0]
        self.size                   = unpack("<L", self.FR.read(4))[0]
        self.offset                 = unpack("<L", self.FR.read(4))[0]
        self.alignment              = unpack("<L", self.FR.read(4))[0]
        self.relocations_offset     = unpack("<L", self.FR.read(4))[0]
        self.number_of_relocations  = unpack("<L", self.FR.read(4))[0]
        self.flags                  = unpack("<L", self.FR.read(4))[0]
        self.reserved1              = unpack("<L", self.FR.read(4))[0]
        self.reserved2              = unpack("<L", self.FR.read(4))[0]
  
    # def __str__(self):
    #     return ("     Section name %s, Seg name %s, addr 0x%X, size 0x%X, offset 0x%X, align 0x%X, rel offset 0x%X, rel num %d, flags 0x%X" % (
    #         self.section_name, self.segment_name, self.address, self.size, self.offset, self.alignment, self.relocations_offset,
    #         self.number_of_relocations, self.flags
    #     ))


class LoadSection64(LoadSection):

    # size 0x50
    def __init__(self, data):
        super().__init__(data)
        self.address                = unpack("<Q", self.FR.read(8))[0]
        self.size                   = unpack("<Q", self.FR.read(8))[0]
        self.offset                 = unpack("<L", self.FR.read(4))[0]
        self.alignment              = unpack("<L", self.FR.read(4))[0]
        self.relocations_offset     = unpack("<L", self.FR.read(4))[0]
        self.number_of_relocations  = unpack("<L", self.FR.read(4))[0]
        self.flags                  = unpack("<L", self.FR.read(4))[0]
        self.reserved1              = unpack("<L", self.FR.read(4))[0]
        self.reserved2              = unpack("<L", self.FR.read(4))[0]
        self.reserved3              = unpack("<L", self.FR.read(4))[0]
        
    # def __str__(self):
    #     return ("     Sec64: Section name %s, Seg name %s, addr 0x%X, size 0x%X, offset 0x%X, align 0x%X, rel offset 0x%X, rel num %d, flags 0x%X" % (
    #         self.section_name, self.segment_name, self.address, self.size, self.offset, self.alignment, self.relocations_offset,
    #         self.number_of_relocations, self.flags
    #     ))


class LoadEncryptionInfo64(LoadCommand):

    def __init__(self, data):
        super().__init__(data)

    def get_complete(self):
        pass        


class LoadDyldExportTrie(LoadCommand):

    def __init__(self, data):
        super().__init__(data)

    def get_complete(self):
        pass       


class LoadDyldChainedFixups(LoadCommand):

    def __init__(self, data):
        super().__init__(data)

    def get_complete(self):
        pass           


class LoadBuildVersion(LoadCommand):

    def __init__(self, data):
        super().__init__(data)

    def get_complete(self):
        pass        
    

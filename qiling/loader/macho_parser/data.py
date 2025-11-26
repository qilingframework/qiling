#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from struct import unpack

class Segment:

    def __init__(self, lc, data):
        self.name = lc.segment_name
        self.section_num = lc.number_of_sections
        self.vm_address = lc.vm_address
        self.vm_size = lc.vm_size
        self.file_offset = lc.file_offset
        self.file_size = lc.file_size
        self.max_vm_protection = lc.maximum_vm_protection
        self.init_vm_protection = lc.initial_vm_protection
        self.flags = lc.flags
        self.content = data[self.file_offset : self.file_offset + self.file_size]
        self.sections = []
        self.sections_index = []
        for i in range(self.section_num):
            self.sections.append(Section(lc.sections[i], data))

    # def __str__(self):
    #     return (" Segment {}: content {}".format(self.name, self.content))


class Section:
    
    def __init__(self, lc, data):
        self.name = lc.section_name
        self.segment_name = lc.segment_name
        self.address = lc.address 
        self.size = lc.size
        self.offset = lc.offset
        self.align = lc.alignment
        self.rel_offset = lc.relocations_offset
        self.rel_num = lc.number_of_relocations
        self.flags = lc.flags
        self.reserved1 = lc.reserved1
        self.reserved2 = lc.reserved2
        self.reserved3 = lc.reserved3
        self.content = data[self.offset : self.offset + self.size]

    # def __str__(self):
    #     return (" Section {}: content {}".format(self.name,self.content))


class FunctionStarts:

    def __init__(self, lc, data):
        self.offset = lc.data_offset
        self.size = lc.data_size
        self.content = data[self.offset : self.offset + self.size]

    # def __str__(self):
    #     return (" FunctionStarts: content {}".format(self.content))


class Symbol64(object):
    def __init__(self, data):
        self.n_strx = unpack("<i", data[:4])[0]
        self.n_type = unpack("<B", data[4:5])[0]
        self.n_sect = unpack("<B", data[5:6])[0]
        self.n_desc = unpack("<H", data[6:8])[0]
        self.n_value = unpack("<Q", data[8:])[0]

    def __str__(self):
        return """
        n_strx = {}
        n_type = {}
        n_sect = {}
        n_desc = {}
        n_value = {}
        """.format(self.n_strx, hex(self.n_type), self.n_sect, hex(self.n_desc), hex(self.n_value))

 
class SymbolTable:
    def __init__(self, lc, data):
        self.offset = lc.symbol_table_offset
        self.sym_num = lc.number_of_symbols 
        self.content = data[self.offset : self.offset + self.sym_num * 0x10]

        self.symbols = []
        for i in range(self.sym_num):
            tmp = Symbol64(self.content[16*i:16*(i + 1)])
            self.symbols.append(tmp)

    def update(self, base):
        for sym in self.symbols:
            sym.n_value += base

    def details(self, index, size, strtab):
        result = {}
        for local_idx, sym in enumerate(self.symbols[index: index + size]):
            if sym.n_strx != 1: # Why I have an index 1 from string table?
                symname = strtab[sym.n_strx]
                tmp = {}
                tmp["n_strx"] = sym.n_strx
                tmp["n_type"] = sym.n_type
                tmp["n_sect"] = sym.n_sect
                tmp["n_desc"] = sym.n_desc
                tmp["n_value"] = sym.n_value
                tmp["index"] = local_idx + index
                if symname in result:
#                     print("Symbol name:", symname)
#                     from pprint import pprint
#                     pprint(tmp)
#                     pprint(result[symname])
                    if sym.n_value == 0:
                        continue
                result[symname] = tmp
        return result
 
    # def __str__(self):
    #     return (" SymbolTable: content {}".format(self.content))


import bisect
class StringTable:
    def __init__(self, lc, data):
        self.offset = lc.string_table_offset
        self.size = lc.string_table_size
        self.content = data[self.offset : self.offset + self.size]
        tmp_table = self.content.split(b'\0')
        self.table = []
        str_offset = 0
        for s in tmp_table:
            self.table.append((s, str_offset))
            str_offset += len(s) + 1
        self.str_off = [x[1] for x in self.table]

    def __getitem__(self, key):
        i = bisect.bisect_left(self.str_off, key)
        if i != len(self.str_off) and self.str_off[i] == key:
            return self.table[i][0]
        raise ValueError

    # def __str__(self):
    #     return (" StringTable: content {}".format(self.content))


class DataInCode:

    def __init__(self, lc, data):
        self.offset = lc.data_offset
        self.size = lc.data_size
        self.content = data[self.offset : self.offset + self.size]

    # def __str__(self): 
    #     return (" DataInCode: content {}".format(self.content))


class CodeSignature:

    def __init__(self, lc, data):
        self.offset = lc.data_offset
        self.size = lc.data_size
        self.content = data[self.offset : self.offset + self.size]

    # def __str__(self): 
    #     return (" CodeSignature: content {}".format(self.content))


class SegmentSplitInfo:

    def __init__(self, lc, data):
        self.offset = lc.data_offset
        self.size = lc.data_size
        self.content = data[self.offset : self.offset + self.size]

    # def __str__(self): 
    #     return (" SegSplitInfo: content {}".format(self.content))


class Relocation64(object):
    def __init__(self, data):
        self.address, tmp = unpack("<II", data)
        self.symbolnum = tmp & 0xffffff
        tmp >>= 24
        self.pcrel = tmp & 0x1
        tmp >>= 1
        self.length = tmp & 0x3
        tmp >>= 2
        self.extern = tmp & 0x1
        tmp >>= 1
        self.rtype = tmp & 0xf
    
    def __str__(self):
        return """Relocation header:
        address = {}
        symbolnum = {}
        pcrel = {}
        length = {}
        extern = {}
        rtype = {}
        """.format(hex(self.address), self.symbolnum, self.pcrel, self.length, self.extern, self.rtype)


class DySymbolTable:
    # TODO: finish parser
    def __init__(self, lc, data):
        self.locsymbol_index = lc.locsymbol_index
        self.locsymbol_num = lc.locsymbol_number
        self.defext_index = lc.defined_extsymbol_index
        self.defext_num = lc.defined_extsymbol_number
        self.undefext_index = lc.undef_extsymbol_index
        self.undefext_num = lc.undef_extsymbol_number
        self.indsym_offset = lc.indsym_table_offset
        self.indsym_num = lc.indsym_table_entries
        self.indirect_symbols = []
        self.extreloc_offset = lc.extreloc_table_offset
        self.extreloc_num = lc.extreloc_table_entries
        self.extreloc = []
        self.locreloc_offset = lc.locreloc_table_offset
        self.locreloc_num = lc.locreloc_table_entries
        self.locreloc = []

        if self.indsym_num:
            slide = 0
            for i in range(self.indsym_num):
                self.indirect_symbols.append(unpack("<L", data[self.indsym_offset + slide : self.indsym_offset + slide + 4]))
                slide += 4

        if self.extreloc_num:
            slide = 0
            for i in range(self.extreloc_num):
                self.extreloc.append(Relocation64(data[self.extreloc_offset + slide : self.extreloc_offset + slide + 8]))
                slide += 8

        if self.locreloc_num:
            slide = 0
            for i in range(self.locreloc_num):
                self.locreloc.append(Relocation64(data[self.locreloc_offset + slide : self.locreloc_offset + slide + 8]))
                slide += 8

    def __str__(self):
        pass

class DyldChainedHeader:
    def __init__(self, data):
        '''
        struct dyld_chained_header {
            uint32_t    fixups_version;
            uint32_t    starts_offset;
            uint32_t    imports_offset;
            uint32_t    symbols_offset;
            uint32_t    imports_count;
            uint32_t    imports_format;
            uint32_t    symbols_format;
        };
        '''
        self.fixups_version = unpack("<L", data[0:4])[0]
        self.starts_offset = unpack("<L", data[4:8])[0]
        self.imports_offset = unpack("<L", data[8:12])[0]
        self.symbols_offset = unpack("<L", data[12:16])[0]
        self.imports_count = unpack("<L", data[16:20])[0]
        self.imports_format = unpack("<L", data[20:24])[0]
        self.symbols_format = unpack("<L", data[24:28])[0]

class DyldChainedStartsInImage:
    def __init__(self, data):
        '''
        struct dyld_chained_starts_in_image {
            uint32_t    seg_count;
            uint32_t    seg_info_offset[1];
        };
        '''
        self.seg_count = unpack("<L", data[0:4])[0]
        self.seg_info_offset = []
        slide = 4
        for i in range(self.seg_count):
            self.seg_info_offset.append(unpack("<L", data[slide:slide +4])[0])
            slide +=4


class DyldChainedStartsInSegment:
    def __init__(self, data):
        '''
        struct dyld_chained_starts_in_segment {
            uint32_t    size;
            uint16_t    page_size;
            uint16_t    pointer_format;
            uint64_t    segment_offset;
            uint32_t    max_valid_pointer;
            uint16_t    page_count;
            uint16_t    page_start[1];
        };
        '''
        self.size = unpack("<L", data[0:4])[0]
        self.page_size = unpack("<H", data[4:6])[0]
        self.pointer_format = unpack("<H", data[6:8])[0]
        self.segment_offset = unpack("<Q", data[8:16])[0]
        self.max_valid_pointer = unpack("<L", data[16:20])[0]
        self.page_count = unpack("<H", data[20:22])[0]
        self.page_start = []
        slide = 22
        for i in range(self.page_count):
            self.page_start.append(unpack("<H", data[slide:slide +2])[0])
            slide +=2

class DyldChainedImport:
    def __init__(self, data):
        '''
        struct dyld_chained_import {
            uint32_t lib_ordinal : 8;
            uint32_t weak_import : 1;
            uint32_t name_offset : 23;
        };
        '''
        tmp = unpack("<L", data[0:4])[0]
        self.lib_ordinal = tmp & 0xff
        tmp >>= 8
        self.weak_import = tmp & 0x1
        tmp >>= 1
        self.name_offset = tmp & 0x7fffff

        self.symbol_name = None  # to be filled later

class ChainedFixups:
    def __init__(self, lc, data):
        self.offset = lc.data_offset
        self.size = lc.data_size
        self.content = data[self.offset : self.offset + self.size]

        self.header = DyldChainedHeader(self.content)
        self.starts_in_image = DyldChainedStartsInImage(self.content[self.header.starts_offset:])
        self.starts_in_segment = []
        for i in range(self.starts_in_image.seg_count):
            seg_offset = self.starts_in_image.seg_info_offset[i]
            if seg_offset == 0:
                self.starts_in_segment.append(None)
                continue

            seg_data = self.content[self.header.starts_offset + seg_offset:]
            self.starts_in_segment.append(DyldChainedStartsInSegment(seg_data))

        self.imports = []
        symbol_pool = self.content[self.header.symbols_offset:]
        for i in range(self.header.imports_count):
            import_offset = self.header.imports_offset + i * 4
            import_data = self.content[import_offset : import_offset + 4]

            import_entry = DyldChainedImport(import_data)
            import_entry.symbol_name = symbol_pool[import_entry.name_offset :].split(b'\0', 1)[0].decode()
            self.imports.append(import_entry)



    # def __str__(self):
    #     return (" ChainedFixupsInfo: content {}".format(self.content))

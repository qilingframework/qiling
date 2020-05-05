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


class SymbolTable:

    def __init__(self, lc, data):
        self.offset = lc.symbol_table_offset
        self.sym_num = lc.number_of_symbols 
        self.content = data[self.offset : self.offset + self.sym_num * 0x10]
        # TODO: parse table 

    # def __str__(self):
    #     return (" SymbolTable: content {}".format(self.content))


class StringTable:

    def __init__(self, lc, data):
        self.offset = lc.string_table_offset
        self.size = lc.string_table_size
        self.content = data[self.offset : self.offset + self.size]
        # TODO: parse table

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


class DySymbolTable:

    # TODO: finish parser
    def __init__(self, lc, data):
        self.indsym_offset = lc.indsym_table_offset
        self.indsym_num = lc.indsym_table_entries
        self.indirect_symbols = []

        if self.indsym_num:
            slide = 0
            for i in range(self.indsym_num):
                self.indirect_symbols.append(unpack("<L", data[self.indsym_offset + slide : self.indsym_offset + slide + 4]))
                slide += 4

    def __str__(self):
        pass

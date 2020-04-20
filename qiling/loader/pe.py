#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys
import os
import string
import pefile
import pickle

from unicorn.x86_const import *
from qiling.os.windows.utils import *
from qiling.os.windows.structs import *
from qiling.exception import *
from qiling.const import *
from qiling.arch.x86_const import *
from .loader import QlLoader

class Process(QlLoader):
    def __init__(self, ql):
        super(QlLoader, self).__init__()
        self.ql = ql

    def load_dll(self, dll_name):
        dll_name = dll_name.lower().decode()

        if self.ql.archtype== QL_ARCH.X86:
            self.ql.dlls = os.path.join("Windows", "SysWOW64")
        elif self.ql.archtype== QL_ARCH.X8664:
            self.ql.dlls = os.path.join("Windows", "System32")

        if not is_file_library(dll_name):
            dll_name = dll_name + ".dll"

        path = os.path.join(self.ql.rootfs, self.ql.dlls, dll_name)

        if not os.path.exists(path):
            raise QlErrorFileNotFound("[!] Cannot find dll in %s" % path)

        # If the dll is already loaded
        if dll_name in self.dlls:
            return self.dlls[dll_name]
        else:
            self.dlls[dll_name] = self.DLL_LAST_ADDR

        self.ql.nprint("[+] Loading %s to 0x%x" % (path, self.DLL_LAST_ADDR))

        # cache depends on address base
        fcache = path + ".%x.cache" % self.DLL_LAST_ADDR

        # Add dll to IAT
        try:
            self.import_address_table[dll_name] = {}
        except KeyError as ke:
            pass

        if self.ql.libcache and os.path.exists(fcache):
            (data, cmdlines, self.import_symbols, self.import_address_table) = \
                pickle.load(open(fcache, "rb"))
            for entry in cmdlines:
                self.set_cmdline(entry['name'], entry['address'], data)
        else:
            dll = pefile.PE(path, fast_load=True)
            dll.parse_data_directories()
            data = bytearray(dll.get_memory_mapped_image())
            cmdlines = []

            for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                self.import_symbols[self.DLL_LAST_ADDR + entry.address] = {"name": entry.name,
                                                                              "ordinal": entry.ordinal,
                                                                              "dll": dll_name.split('.')[0]
                                                                              }
                self.import_address_table[dll_name][entry.name] = self.DLL_LAST_ADDR + entry.address
                self.import_address_table[dll_name][entry.ordinal] = self.DLL_LAST_ADDR + entry.address
                cmdline_entry = self.set_cmdline(entry.name, entry.address, data)
                if cmdline_entry:
                    cmdlines.append(cmdline_entry)

            if self.ql.libcache:
                # cache this dll file
                pickle.dump((data, cmdlines,
                             self.import_symbols,
                             self.import_address_table),
                            open(fcache, "wb"))
                self.ql.nprint("[+] Cached %s" % path)

        dll_base = self.DLL_LAST_ADDR
        dll_len = self.ql.os.heap._align(len(bytes(data)), 0x1000)
        self.DLL_SIZE += dll_len
        self.ql.mem.map(dll_base, dll_len, info="[dlls]")
        self.ql.mem.write(dll_base, bytes(data))
        self.DLL_LAST_ADDR += dll_len

        # add dll to ldr data
        self.add_ldr_data_table_entry(dll_name)

        self.ql.nprint("[+] Done with loading %s" % path)
        return dll_base

    def set_cmdline(self, name, address, memory):
        if self.ql.archtype== QL_ARCH.X86:
            addr = self.ql.os.heap.mem_alloc(len(self.cmdline))
            packed_addr = self.ql.pack32(addr)
        else:
            addr = self.ql.os.heap.mem_alloc(2 * len(self.cmdline))
            packed_addr = self.ql.pack64(addr)

        cmdline_entry = None
        if name == b"_acmdln":
            cmdline_entry = {"name": name, "address": address}
            memory[address:address + self.ql.pointersize] = packed_addr
            self.ql.mem.write(addr, self.cmdline)
        elif name == b"_wcmdln":
            cmdline_entry = {"name": name, "address": address}
            memory[address:address + self.ql.pointersize] = packed_addr
            self.ql.mem.write(addr, str(self.cmdline).encode("utf-16le"))

        return cmdline_entry

    def init_tib(self):
        if self.ql.archtype== QL_ARCH.X86:
            teb_addr = self.STRUCTERS_LAST_ADDR
        else:
            gs = self.STRUCTERS_LAST_ADDR
            self.STRUCTERS_LAST_ADDR += 0x30
            teb_addr = self.STRUCTERS_LAST_ADDR

        self.ql.nprint("[+] TEB addr is 0x%x" %teb_addr)

        teb_size = len(TEB(self.ql).bytes())
        teb_data = TEB(
            self.ql,
            base=teb_addr,
            peb_address=teb_addr + teb_size,
            stack_base=self.ql.stack_address + self.ql.stack_size,
            stack_limit=self.ql.stack_size,
            Self=teb_addr)

        self.ql.mem.write(teb_addr, teb_data.bytes())

        self.STRUCTERS_LAST_ADDR += teb_size
        if self.ql.archtype== QL_ARCH.X8664:
            # TEB
            self.ql.mem.write(gs + 0x30, self.ql.pack64(teb_addr))
            # PEB
            self.ql.mem.write(gs + 0x60, self.ql.pack64(teb_addr + teb_size))

        self.TEB = self.ql.TEB = teb_data

    def init_peb(self):
        peb_addr = self.STRUCTERS_LAST_ADDR

        self.ql.nprint("[+] PEB addr is 0x%x" % peb_addr)

        peb_size = len(PEB(self.ql).bytes())

        # we must set an heap, will try to retrieve this value. Is ok to be all \x00
        process_heap = self.ql.os.heap.mem_alloc(0x50)

        peb_data = PEB(self.ql, base=peb_addr, ldr_address=peb_addr + peb_size, process_heap=process_heap)
        self.ql.mem.write(peb_addr, peb_data.bytes())
        self.STRUCTERS_LAST_ADDR += peb_size
        self.PEB = self.ql.PEB = peb_data

    def init_ldr_data(self):
        ldr_addr = self.STRUCTERS_LAST_ADDR
        ldr_size = len(LdrData(self.ql).bytes())
        ldr_data = LdrData(
            self.ql,
            base=ldr_addr,
            in_load_order_module_list={
                'Flink': ldr_addr + 2 * self.ql.pointersize,
                'Blink': ldr_addr + 2 * self.ql.pointersize
            },
            in_memory_order_module_list={
                'Flink': ldr_addr + 4 * self.ql.pointersize,
                'Blink': ldr_addr + 4 * self.ql.pointersize
            },
            in_initialization_order_module_list={
                'Flink': ldr_addr + 6 * self.ql.pointersize,
                'Blink': ldr_addr + 6 * self.ql.pointersize
            }
        )
        self.ql.mem.write(ldr_addr, ldr_data.bytes())
        self.STRUCTERS_LAST_ADDR += ldr_size
        self.LDR = self.ql.LDR = ldr_data

    def add_ldr_data_table_entry(self, dll_name):
        dll_base = self.dlls[dll_name]
        path = "C:\\Windows\\System32\\" + dll_name
        ldr_table_entry_size = len(LdrDataTableEntry(self.ql).bytes())
        base = self.ql.os.heap.mem_alloc(ldr_table_entry_size)
        ldr_table_entry = LdrDataTableEntry(self.ql,
                                            base=base,
                                            in_load_order_links={'Flink': 0, 'Blink': 0},
                                            in_memory_order_links={'Flink': 0, 'Blink': 0},
                                            in_initialization_order_links={'Flink': 0, 'Blink': 0},
                                            dll_base=dll_base,
                                            entry_point=0,
                                            full_dll_name=path,
                                            base_dll_name=dll_name)

        # Flink
        if len(self.ldr_list) == 0:
            flink = self.LDR
            ldr_table_entry.InLoadOrderLinks['Flink'] = flink.InLoadOrderModuleList['Flink']
            ldr_table_entry.InMemoryOrderLinks['Flink'] = flink.InMemoryOrderModuleList['Flink']
            ldr_table_entry.InInitializationOrderLinks['Flink'] = flink.InInitializationOrderModuleList['Flink']

            flink.InLoadOrderModuleList['Flink'] = ldr_table_entry.base
            flink.InMemoryOrderModuleList['Flink'] = ldr_table_entry.base + 2 * self.ql.pointersize
            flink.InInitializationOrderModuleList['Flink'] = ldr_table_entry.base + 4 * self.ql.pointersize

        else:
            flink = self.ldr_list[-1]
            ldr_table_entry.InLoadOrderLinks['Flink'] = flink.InLoadOrderLinks['Flink']
            ldr_table_entry.InMemoryOrderLinks['Flink'] = flink.InMemoryOrderLinks['Flink']
            ldr_table_entry.InInitializationOrderLinks['Flink'] = flink.InInitializationOrderLinks['Flink']

            flink.InLoadOrderLinks['Flink'] = ldr_table_entry.base
            flink.InMemoryOrderLinks['Flink'] = ldr_table_entry.base + 2 * self.ql.pointersize
            flink.InInitializationOrderLinks['Flink'] = ldr_table_entry.base + 4 * self.ql.pointersize

        # Blink
        blink = self.LDR
        ldr_table_entry.InLoadOrderLinks['Blink'] = blink.InLoadOrderModuleList['Blink']
        ldr_table_entry.InMemoryOrderLinks['Blink'] = blink.InMemoryOrderModuleList['Blink']
        ldr_table_entry.InInitializationOrderLinks['Blink'] = blink.InInitializationOrderModuleList['Blink']

        blink.InLoadOrderModuleList['Blink'] = ldr_table_entry.base
        blink.InMemoryOrderModuleList['Blink'] = ldr_table_entry.base + 2 * self.ql.pointersize
        blink.InInitializationOrderModuleList['Blink'] = ldr_table_entry.base + 4 * self.ql.pointersize

        self.ql.mem.write(flink.base, flink.bytes())
        self.ql.mem.write(blink.base, blink.bytes())
        self.ql.mem.write(ldr_table_entry.base, ldr_table_entry.bytes())

        self.ldr_list.append(ldr_table_entry)


class QlLoaderPE(Process, QlLoader):
    def __init__(self, ql):
        super()
        self.ql = ql
        self.path = self.ql.path
        self.init_dlls = [b"ntdll.dll", b"kernel32.dll", b"user32.dll"]
        self.filepath = ''
        self.PE_IMAGE_BASE = 0
        self.PE_IMAGE_SIZE = 0
        self.PE_ENTRY_POINT = 0
        self.sizeOfStackReserve = 0

        if self.ql.archtype== QL_ARCH.X86:
            self.STRUCTERS_LAST_ADDR = FS_SEGMENT_ADDR
            self.DEFAULT_IMAGE_BASE = 0x400000
            self.DLL_BASE_ADDR = 0x10000000
            self.code_address = 0x40000  
             
        elif self.ql.archtype== QL_ARCH.X8664:
            self.STRUCTERS_LAST_ADDR = GS_SEGMENT_ADDR 
            self.DEFAULT_IMAGE_BASE = 0x400000
            self.DLL_BASE_ADDR = 0x7ffff0000000
            self.code_address = 0x140000000
            
        self.code_size = 10 * 1024 * 1024            
        self.cmdline = b"D:\\" + bytes(self.ql.path.replace("/", "\\"), "utf-8") + b"\x00"             
        self.dlls = {}
        self.import_symbols = {}
        self.import_address_table = {}
        self.ldr_list = []
        self.PE_IMAGE_BASE = 0
        self.PE_IMAGE_SIZE = 0
        self.DLL_SIZE = 0
        self.DLL_LAST_ADDR = self.DLL_BASE_ADDR      
        # compatible with ql.__enable_bin_patch()
        self.loadbase = 0  
        self.ql.os.setupComponents()
        self.load()

    def init_thread_information_block(self): 
        super().init_tib()
        super().init_peb()
        super().init_ldr_data()

    def load(self):
        if self.path and not self.ql.shellcoder:
            
            self.pe = pefile.PE(self.path, fast_load=True)
            # for simplicity, no image base relocation
            self.PE_IMAGE_BASE = self.PE_IMAGE_BASE = self.pe.OPTIONAL_HEADER.ImageBase
            self.PE_IMAGE_SIZE = self.PE_IMAGE_SIZE = self.pe.OPTIONAL_HEADER.SizeOfImage

            if self.PE_IMAGE_BASE + self.PE_IMAGE_SIZE > self.ql.os.HEAP_BASE_ADDR:
                # pe reloc
                self.PE_IMAGE_BASE = self.PE_IMAGE_BASE = self.DEFAULT_IMAGE_BASE
                self.pe.relocate_image(self.DEFAULT_IMAGE_BASE)

            self.entry_point = self.PE_ENTRY_POINT = self.PE_IMAGE_BASE + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.sizeOfStackReserve = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
            self.ql.nprint("[+] Loading %s to 0x%x" % (self.path, self.PE_IMAGE_BASE))
            self.ql.nprint("[+] PE entry point at 0x%x" % self.entry_point)

            # set stack pointer
            self.ql.nprint("[+] Initiate stack address at 0x%x " % self.ql.stack_address)
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size, info="[stack]")

            # Stack should not init at the very bottom. Will cause errors with Dlls
            sp = self.ql.stack_address + self.ql.stack_size - 0x1000

            if self.ql.archtype== QL_ARCH.X86:
                self.ql.register(UC_X86_REG_ESP, sp)
                self.ql.register(UC_X86_REG_EBP, sp)

                if self.pe.is_dll():
                    self.ql.dprint(D_INFO, '[+] Setting up DllMain args')
                    load_addr_bytes = self.PE_IMAGE_BASE.to_bytes(length=4, byteorder='little')

                    self.ql.dprint(D_INFO, '[+] Writing 0x%08X (IMAGE_BASE) to [ESP+4](0x%08X)' % (self.PE_IMAGE_BASE, sp + 0x4))
                    self.ql.mem.write(sp + 0x4, load_addr_bytes)

                    self.ql.dprint(D_INFO, '[+] Writing 0x01 (DLL_PROCESS_ATTACH) to [ESP+8](0x%08X)' % (sp + 0x8))
                    self.ql.mem.write(sp + 0x8, int(1).to_bytes(length=4, byteorder='little'))

            elif self.ql.archtype== QL_ARCH.X8664:
                self.ql.register(UC_X86_REG_RSP, sp)
                self.ql.register(UC_X86_REG_RBP, sp)

                if self.pe.is_dll():
                    self.ql.dprint(D_INFO, '[+] Setting up DllMain args')

                    self.ql.dprint(D_INFO, '[+] Setting RCX (arg1) to %16X (IMAGE_BASE)' % (self.PE_IMAGE_BASE))
                    self.ql.register(UC_X86_REG_RCX, self.PE_IMAGE_BASE)

                    self.ql.dprint(D_INFO, '[+] Setting RDX (arg2) to 1 (DLL_PROCESS_ATTACH)')
                    self.ql.register(UC_X86_REG_RDX, 1)
            else:
                raise QlErrorArch("[!] Unknown ql.arch")

            self.init_thread_information_block()

            # mmap PE file into memory
            self.ql.mem.map(self.PE_IMAGE_BASE, self.PE_IMAGE_SIZE, info="[PE]")
            self.pe.parse_data_directories()
            data = bytearray(self.pe.get_memory_mapped_image())
            self.ql.mem.write(self.PE_IMAGE_BASE, bytes(data))

            # Add main PE to ldr_data_table
            mod_name = os.path.basename(self.path)
            self.dlls[mod_name] = self.PE_IMAGE_BASE
            super().add_ldr_data_table_entry(mod_name)

            # parse directory entry import
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = str(entry.dll.lower(), 'utf-8', 'ignore')
                super().load_dll(entry.dll)
                for imp in entry.imports:
                    # fix IAT
                    # self.ql.nprint(imp.name)
                    # self.ql.nprint(self.import_address_table[imp.name])
                    if imp.name:
                        addr = self.import_address_table[dll_name][imp.name]
                    else:
                        addr = self.import_address_table[dll_name][imp.ordinal]

                    if self.ql.archtype== QL_ARCH.X86:
                        address = self.ql.pack32(addr)
                    else:
                        address = self.ql.pack64(addr)
                    self.ql.mem.write(imp.address, address)

            self.ql.nprint("[+] Done with loading %s" % self.path)
            self.filepath = b"D:\\" + bytes(self.path.replace("/", "\\"), "utf-8")

        elif self.ql.shellcoder:
            # setup stack memory
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size, info="[stack]")
            if self.ql.archtype== QL_ARCH.X86:
                self.ql.register(UC_X86_REG_ESP, self.ql.stack_address + 0x3000)
                self.ql.register(UC_X86_REG_EBP, self.ql.stack_address + 0x3000)
            else:
                self.ql.register(UC_X86_REG_RSP, self.ql.stack_address + 0x3000)
                self.ql.register(UC_X86_REG_RBP, self.ql.stack_address + 0x3000)

            # load shellcode in
            self.ql.mem.map(self.code_address, self.code_size, info="[shellcode_base]")
            self.ql.mem.write(self.code_address, self.ql.shellcoder)

            self.init_thread_information_block()

            # load dlls
            for each in self.init_dlls:
                super().load_dll(each)            

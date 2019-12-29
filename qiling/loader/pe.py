#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
import sys
import os
import string
import pefile
import pickle

from unicorn.x86_const import *
from qiling.os.windows.utils import *
from qiling.os.windows.memory import align
from qiling.os.windows.structs import *
from qiling.exception import *


class Process:
    def __init__(self, ql):
        self.ql = ql
        self.dlls = {}
        self.import_symbols = {}
        self.import_address_table = {}
        self.ldr_list = []
        self.cmdline = b"D:\\" + bytes(self.ql.path.replace("/", "\\"), "utf-8") + b"\x00"

    def load_dll(self, dll_name):
        dll_name = dll_name.lower().decode()

        if not dll_name.endswith(".dll"):
            dll_name = dll_name + '.dll'
        path = os.path.join(self.ql.rootfs, "dlls", dll_name)

        if not os.path.exists(path):
            raise QlErrorFileNotFound("[!] Cannot find dll in %s" % path)

        # If the dll is already loaded
        if dll_name in self.dlls:
            return self.dlls[dll_name]
        else:
            self.dlls[dll_name] = self.ql.DLL_LAST_ADDR

        self.ql.nprint("[+] Loading %s to 0x%x" % (path, self.ql.DLL_LAST_ADDR))

        # cache depends on address base
        fcache = path + ".%x.cache" % self.ql.DLL_LAST_ADDR

        # Add dll to IAT
        try:
            self.import_address_table[dll_name] = {}
        except KeyError as ke:
            pass

        if not os.path.exists(fcache):
            dll = pefile.PE(path, fast_load=True)
            dll.parse_data_directories()
            data = bytearray(dll.get_memory_mapped_image())

            for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                self.import_symbols[self.ql.DLL_LAST_ADDR + entry.address] = {'name': entry.name, 'ordinal': entry.ordinal}
                self.import_address_table[dll_name][entry.name] = self.ql.DLL_LAST_ADDR + entry.address
                self.import_address_table[dll_name][entry.ordinal] = self.ql.DLL_LAST_ADDR + entry.address
                self.set_cmdline(entry, data)
            if self.ql.libcache:
                # cache this dll file
                pickle.dump((data,
                    self.import_symbols,
                    self.import_address_table),
                    open(fcache, "wb"))
                self.ql.nprint("[+] Cached %s" % path)
        else:
            (data, self.import_symbols, self.import_address_table) = \
                pickle.load(open(fcache, "rb"))

        dll_base = self.ql.DLL_LAST_ADDR
        dll_len = align(len(bytes(data)), 0x1000)
        self.ql.DLL_SIZE += dll_len
        self.ql.uc.mem_map(dll_base, dll_len)
        self.ql.uc.mem_write(dll_base, bytes(data))
        self.ql.DLL_LAST_ADDR += dll_len

        # add dll to ldr data
        self.add_ldr_data_table_entry(dll_name)

        self.ql.nprint("[+] Done with loading %s" % path)
        return dll_base

    def set_cmdline(self, entry, memory):
        if self.ql.arch == QL_X86:
            addr = self.ql.heap.mem_alloc(len(self.cmdline))
            packed_addr = self.ql.pack32(addr)
        else:
            addr = self.ql.heap.mem_alloc(2 * len(self.cmdline))
            packed_addr = self.ql.pack64(addr)

        if entry.name == b"_acmdln":
            memory[entry.address:entry.address + self.ql.pointersize] = packed_addr
            self.ql.uc.mem_write(addr, self.cmdline)
        elif entry.name == b"_wcmdln":
            memory[entry.address:entry.address + self.ql.pointersize] = packed_addr
            self.ql.uc.mem_write(addr, str(self.cmdline).encode("utf-16le"))

    def init_tib(self):
        if self.ql.arch == QL_X86:
            teb_addr = self.ql.STRUCTERS_LAST_ADDR
        else:
            gs = self.ql.STRUCTERS_LAST_ADDR
            self.ql.STRUCTERS_LAST_ADDR += 0x30
            teb_addr = self.ql.STRUCTERS_LAST_ADDR

        self.ql.nprint("[+] TEB addr is " + hex(teb_addr))

        teb_size = len(TEB(self.ql).bytes())
        teb_data = TEB(
            self.ql,
            base=teb_addr,
            PEB_Address=teb_addr + teb_size,
            StackBase=self.ql.stack_address + self.ql.stack_size,
            StackLimit=self.ql.stack_size,
            Self=teb_addr)

        self.ql.uc.mem_write(teb_addr, teb_data.bytes())

        self.ql.STRUCTERS_LAST_ADDR += teb_size
        if self.ql.arch == QL_X8664:
            # TEB
            self.ql.uc.mem_write(gs + 0x30, self.ql.pack64(teb_addr))
            # PEB
            self.ql.uc.mem_write(gs + 0x60, self.ql.pack64(teb_addr + teb_size))

        self.TEB = self.ql.TEB = teb_data

    def init_peb(self):
        peb_addr = self.ql.STRUCTERS_LAST_ADDR

        self.ql.nprint("[+] PEB addr is " + hex(peb_addr))

        peb_size = len(PEB(self.ql).bytes())
        peb_data = PEB(self.ql, base=peb_addr, LdrAddress=peb_addr + peb_size)
        self.ql.uc.mem_write(peb_addr, peb_data.bytes())
        self.ql.STRUCTERS_LAST_ADDR += peb_size
        self.PEB = self.ql.PEB = peb_data

    def init_ldr_data(self):
        ldr_addr = self.ql.STRUCTERS_LAST_ADDR
        ldr_size = len(LDR_DATA(self.ql).bytes())
        ldr_data = LDR_DATA(
                    self.ql,
                    base=ldr_addr,
                    InLoadOrderModuleList={
                        'Flink': ldr_addr + 2 * self.ql.pointersize,
                        'Blink': ldr_addr + 2 * self.ql.pointersize
                    },
                    InMemoryOrderModuleList={
                        'Flink': ldr_addr + 4 * self.ql.pointersize,
                        'Blink': ldr_addr + 4 * self.ql.pointersize
                    },
                    InInitializationOrderModuleList={
                        'Flink': ldr_addr + 6 * self.ql.pointersize,
                        'Blink': ldr_addr + 6 * self.ql.pointersize
                    }
        )
        self.ql.uc.mem_write(ldr_addr, ldr_data.bytes())
        self.ql.STRUCTERS_LAST_ADDR += ldr_size
        self.LDR = self.ql.LDR = ldr_data

    def add_ldr_data_table_entry(self, dll_name):
        dll_base = self.dlls[dll_name]
        path = "C:\\Windows\\System32\\" + dll_name
        ldr_table_entry_size = len(LDR_DATA_TABLE_ENTRY(self.ql).bytes())
        base = self.ql.heap.mem_alloc(ldr_table_entry_size)
        ldr_table_entry = LDR_DATA_TABLE_ENTRY(self.ql,
                    base=base,
                    InLoadOrderLinks={'Flink': 0, 'Blink': 0},
                    InMemoryOrderLinks={'Flink': 0, 'Blink': 0},
                    InInitializationOrderLinks={'Flink': 0, 'Blink': 0},
                    DllBase=dll_base,
                    EntryPoint=0,
                    FullDllName=path,
                    BaseDllName=dll_name)

        #Flink
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

        #Blink
        blink = self.LDR
        ldr_table_entry.InLoadOrderLinks['Blink'] = blink.InLoadOrderModuleList['Blink']
        ldr_table_entry.InMemoryOrderLinks['Blink'] = blink.InMemoryOrderModuleList['Blink']
        ldr_table_entry.InInitializationOrderLinks['Blink'] = blink.InInitializationOrderModuleList['Blink']

        blink.InLoadOrderModuleList['Blink'] = ldr_table_entry.base
        blink.InMemoryOrderModuleList['Blink'] = ldr_table_entry.base + 2 * self.ql.pointersize
        blink.InInitializationOrderModuleList['Blink'] = ldr_table_entry.base + 4 * self.ql.pointersize

        self.ql.uc.mem_write(flink.base, flink.bytes())
        self.ql.uc.mem_write(blink.base, blink.bytes())
        self.ql.uc.mem_write(ldr_table_entry.base, ldr_table_entry.bytes())

        self.ldr_list.append(ldr_table_entry)


class Shellcode(Process):
    def __init__(self, ql, dlls=[]):
        self.ql = ql
        self.init_dlls = dlls
        super().__init__(ql)

    def load(self):
        # setup stack memory
        self.ql.uc.mem_map(self.ql.stack_address, self.ql.stack_size)
        if self.ql.arch == QL_X86:
            self.ql.uc.reg_write(UC_X86_REG_ESP, self.ql.stack_address + 0x3000)
            self.ql.uc.reg_write(UC_X86_REG_EBP, self.ql.stack_address + 0x3000)
        else:
            self.ql.uc.reg_write(UC_X86_REG_RSP, self.ql.stack_address + 0x3000)
            self.ql.uc.reg_write(UC_X86_REG_RBP, self.ql.stack_address + 0x3000)

        # load shellcode in
        self.ql.uc.mem_map(self.ql.code_address, self.ql.code_size)
        self.ql.mem_write(self.ql.code_address, self.ql.shellcoder)

        # init tib/peb/ldr
        super().init_tib()
        super().init_peb()
        super().init_ldr_data()

        # load dlls
        for each in self.init_dlls:
            super().load_dll(each)


class PE(Process):
    def __init__(self, ql, path=""):
        self.ql = ql
        self.path = path
        self.filepath = ''
        self.PE_IMAGE_BASE = 0
        self.PE_IMAGE_SIZE = 0
        self.PE_ENTRY_POINT = 0
        self.sizeOfStackReserve = 0
        super().__init__(ql)

    def load(self):
        self.pe = pefile.PE(self.path, fast_load=True)

        # for simplicity, no image base relocation
        self.ql.PE_IMAGE_BASE = self.PE_IMAGE_BASE = self.pe.OPTIONAL_HEADER.ImageBase
        self.ql.PE_IMAGE_SIZE = self.PE_IMAGE_SIZE = self.pe.OPTIONAL_HEADER.SizeOfImage

        if self.PE_IMAGE_BASE + self.PE_IMAGE_SIZE > self.ql.HEAP_BASE_ADDR:
            # pe reloc
            self.ql.PE_IMAGE_BASE = self.PE_IMAGE_BASE = self.ql.DEFAULT_IMAGE_BASE
            self.pe.relocate_image(self.ql.DEFAULT_IMAGE_BASE)

        self.ql.entry_point = self.PE_ENTRY_POINT = self.PE_IMAGE_BASE + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.sizeOfStackReserve = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
        self.ql.nprint("[+] Loading %s to 0x%x" % (self.path, self.PE_IMAGE_BASE))
        self.ql.nprint("[+] PE entry point at 0x%x" % self.ql.entry_point)

        # set stack pointer
        self.ql.nprint("[+] Initiate stack address at 0x%x " % self.ql.stack_address)
        self.ql.uc.mem_map(self.ql.stack_address, self.ql.stack_size)

        # Stack should not init at the very bottom. Will cause errors with Dlls
        sp = self.ql.stack_address + self.ql.stack_size - 0x1000

        if self.ql.arch == QL_X86:
            self.ql.uc.reg_write(UC_X86_REG_ESP, sp)
            self.ql.uc.reg_write(UC_X86_REG_EBP, sp)

            if self.pe.is_dll():
                self.ql.dprint('[+] Setting up DllMain args')
                load_addr_bytes = self.PE_IMAGE_BASE.to_bytes(length=4, byteorder='little')

                self.ql.dprint('[+] Writing 0x%08X (IMAGE_BASE) to [ESP+4](0x%08X)' % (self.PE_IMAGE_BASE, sp+0x4))
                self.ql.uc.mem_write(sp+0x4, load_addr_bytes)

                self.ql.dprint('[+] Writing 0x01 (DLL_PROCESS_ATTACH) to [ESP+8](0x%08X)' % (sp+0x8))
                self.ql.uc.mem_write(sp+0x8, int(1).to_bytes(length=4, byteorder='little'))

        elif self.ql.arch == QL_X8664:
            self.ql.uc.reg_write(UC_X86_REG_RSP, sp)
            self.ql.uc.reg_write(UC_X86_REG_RBP, sp)

            if self.pe.is_dll():
                self.ql.dprint('[+] Setting up DllMain args')
                load_addr_bytes = self.PE_IMAGE_BASE.to_bytes(length=8, byteorder='little')

                self.ql.dprint('[+] Setting RCX (arg1) to %16X (IMAGE_BASE)' % (self.PE_IMAGE_BASE))
                self.ql.uc.reg_write(UC_X86_REG_RCX, load_addr_bytes)

                self.ql.dprint('[+] Setting RDX (arg2) to 1 (DLL_PROCESS_ATTACH)')
                self.ql.uc.reg_write(UC_X86_REG_RDX, int(1).to_bytes(length=8, byteorder='little'))
        else:
            raise QlErrorArch("[!] Unknown ql.arch")

        super().init_tib()
        super().init_peb()
        super().init_ldr_data()

        # mmap PE file into memory
        self.ql.uc.mem_map(self.PE_IMAGE_BASE, self.PE_IMAGE_SIZE)
        self.pe.parse_data_directories()
        data = bytearray(self.pe.get_memory_mapped_image())
        self.ql.uc.mem_write(self.PE_IMAGE_BASE, bytes(data))

        #Add main PE to ldr_data_table
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

                if self.ql.arch == QL_X86:
                    address = self.ql.pack32(addr)
                else:
                    address = self.ql.pack64(addr)
                self.ql.uc.mem_write(imp.address, address)

        self.ql.nprint("[+] Done with loading %s" % self.path)
        self.filepath = b"D:\\" + bytes(self.path.replace("/", "\\"), "utf-8")

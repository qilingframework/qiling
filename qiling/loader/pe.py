#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, pefile, pickle, secrets, traceback
from typing import Any, MutableMapping, Optional, Mapping, Sequence

from qiling import Qiling
from qiling.arch.x86_const import *
from qiling.const import *
from qiling.os.const import POINTER
from qiling.os.memory import QlMemoryHeap
from qiling.os.windows.fncc import CDECL
from qiling.os.windows.utils import *
from qiling.os.windows.structs import *
from .loader import QlLoader, Image

class QlPeCacheEntry:
    def __init__(self, ba: int, data: bytearray, cmdlines: Sequence, import_symbols: Mapping, import_table: Mapping):
        self. ba = ba
        self.data = data
        self.cmdlines = cmdlines
        self.import_symbols = import_symbols
        self.import_table = import_table

# A default simple cache implementation
class QlPeCache:
    def create_filename(self, path: str) -> str:
        return f'{path}.cache2'

    def restore(self, path: str) -> Optional[QlPeCacheEntry]:
        fcache = self.create_filename(path)

        # pickle file cannot be outdated
        if os.path.exists(fcache) and os.stat(fcache).st_mtime > os.stat(path).st_mtime:
            with open(fcache, "rb") as fcache_file:
                return QlPeCacheEntry(*pickle.load(fcache_file))

        return None

    def save(self, path: str, entry: QlPeCacheEntry):
        fcache = self.create_filename(path)

        data = (entry.ba, entry.data, entry.cmdlines, entry.import_symbols, entry.import_table)
        # cache this dll file
        with open(fcache, "wb") as fcache_file:
            pickle.dump(data, fcache_file)

class Process():
    # let linter recognize mixin members
    dlls: MutableMapping[str, int]
    import_address_table: MutableMapping[str, Any]
    import_symbols: MutableMapping[int, Any]
    export_symbols: MutableMapping[int, Any]
    libcache: Optional[QlPeCache]

    def __init__(self, ql: Qiling):
        self.ql = ql

    def align(self, size: int, unit: int) -> int:
        return (size // unit + (1 if size % unit else 0)) * unit

    def load_dll(self, name: bytes, driver: bool = False) -> int:
        dll_name = name.decode()

        self.ql.dlls = os.path.join("Windows", "System32")

        if dll_name.upper().startswith('C:\\'):
            path = self.ql.os.path.transform_to_real_path(dll_name)
            dll_name = path_leaf(dll_name)
        else:
            dll_name = dll_name.lower()

            if not is_file_library(dll_name):
                dll_name = dll_name + ".dll"

            path = os.path.join(self.ql.rootfs, self.ql.dlls, dll_name)

        if dll_name.startswith("api-ms-win-"):
            self.ql.log.warning("Refusing to load virtual DLL %s" % dll_name)
            # Usually we should not reach this point and instead imports from such DLLs should be redirected earlier
            return 0

        if not os.path.exists(path):
            raise QlErrorFileNotFound("Cannot find dll in %s" % path)

        # If the dll is already loaded
        if dll_name in self.dlls:
            return self.dlls[dll_name]

        self.ql.log.info(f'Loading {path} ...')

        cached = None
        loaded = False

        if self.libcache:
            cached = self.libcache.restore(path)

        if cached:
            data = cached.data

            image_base = cached.ba
            image_size = self.ql.mem.align(len(data), 0x1000)

            # verify whether we can load the dll to the same address it was loaded when it was cached.
            # if not, the dll will have to be realoded in order to have its symbols relocated using the
            # new address
            if self.ql.mem.is_available(image_base, image_size):
                import_symbols = cached.import_symbols
                import_table = cached.import_table

                for entry in cached.cmdlines:
                    self.set_cmdline(entry['name'], entry['address'], data)

                self.ql.log.info(f'Loaded {path} from cache')
                loaded = True

        # either file was not cached, or could not be loaded to the same location in memory
        if not cached or not loaded:
            dll = pefile.PE(path, fast_load=True)
            dll.parse_data_directories()
            warnings = dll.get_warnings()

            if warnings:
                self.ql.log.warning(f'Warnings while loading {path}:')

                for warning in warnings:
                    self.ql.log.warning(f' - {warning}')

            data = bytearray(dll.get_memory_mapped_image())

            image_base = dll.OPTIONAL_HEADER.ImageBase or self.dll_last_address
            image_size = self.ql.mem.align(len(data), 0x1000)

            self.ql.log.debug(f'DLL preferred base address: {image_base:#x}')

            if (image_base + image_size) > self.ql.mem.max_mem_addr:
                image_base = self.dll_last_address
                self.ql.log.debug(f'DLL preferred base address exceeds memory upper bound, loading to: {image_base:#x}')
                dll.relocate_image(image_base)  # Apply code patches as described by .reloc section
                data = bytearray(dll.get_memory_mapped_image())
                image_size = self.ql.mem.align(len(data), 0x1000)

            if not self.ql.mem.is_available(image_base, image_size):
                image_base = self.ql.mem.find_free_space(image_size, minaddr=image_base, align=0x10000)
                self.ql.log.debug(f'DLL preferred base address is taken, loading to: {image_base:#x}')
                dll.relocate_image(image_base) # Apply code patches as described by .reloc section
                data = bytearray(dll.get_memory_mapped_image())
                image_size = self.ql.mem.align(len(data), 0x1000)

            cmdlines = []
            import_symbols = {}
            import_table = {}

            dll_symbols = getattr(getattr(dll, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
            for entry in dll_symbols:
                import_symbols[image_base + entry.address] = {
                    "name": entry.name,
                    "ordinal": entry.ordinal,
                    "dll": dll_name.split('.')[0]
                }

                if entry.name:
                    import_table[entry.name] = image_base + entry.address

                import_table[entry.ordinal] = image_base + entry.address
                cmdline_entry = self.set_cmdline(entry.name, entry.address, data)

                if cmdline_entry:
                    cmdlines.append(cmdline_entry)

            if self.libcache:
                cached = QlPeCacheEntry(image_base, data, cmdlines, import_symbols, import_table)
                self.libcache.save(path, cached)
                self.ql.log.info("Cached %s" % path)

        # Add dll to IAT
        try:
            self.import_address_table[dll_name] = import_table
        except Exception as ex:
            self.ql.log.exception(f'Unable to add {dll_name} to IAT')

        try:
            self.import_symbols.update(import_symbols)
        except Exception as ex:
            self.ql.log.exception(f'Unable to add {dll_name} import symbols')

        dll_base = image_base
        dll_len = image_size

        self.dll_size += dll_len
        self.ql.mem.map(dll_base, dll_len, info=dll_name)
        self.ql.mem.write(dll_base, bytes(data))

        self.dlls[dll_name] = dll_base

        if dll_base == self.dll_last_address:
            self.dll_last_address += dll_len

        # if this is NOT a driver, add dll to ldr data
        if not driver:
            self.add_ldr_data_table_entry(dll_name)

        # add DLL to coverage images
        self.images.append(Image(dll_base, dll_base + dll_len, path))

        if not cached or not loaded:
            # parse directory entry import
            self.ql.log.debug("Init imports for %s" % dll_name)
            self.init_imports(dll, driver)

            self.call_dll_entrypoint(dll, dll_base, dll_len, dll_name)

        self.ql.log.info(f'Done with loading {path}')
        return dll_base

    def call_dll_entrypoint(self, dll, dll_base, dll_len, dll_name):
        if dll.get_section_by_rva(dll.OPTIONAL_HEADER.AddressOfEntryPoint) is not None:
            entry_point = dll_base + dll.OPTIONAL_HEADER.AddressOfEntryPoint

            if dll_name in ["kernelbase.dll", "kernel32.dll"]:
                self.ql.log.debug("Ignore calling entry point of %s" % dll_name)
            else:
                self.ql.log.info("Calling entry point of dll %s at 0x%x" % (dll_name, entry_point))
                # Strategy: Write a "call entrypoint" instruction into memory and execute it. Setup stack/regs manually

                code_loc = dll_base + dll_len - 16  # location to put the "call entrypoint" instructions to

                # make relative call to entry point, followed by NOP so that we can break there
                asmstr = f"call {hex(entry_point - code_loc)};nop;"

                # Assemble and write to location
                assembler = self.ql.create_assembler()
                bs, sz = assembler.asm(asmstr)
                bi = bytes(bs)
                code_loc_end = code_loc + len(bi)
                self.ql.mem.write(code_loc, bi)

                # Setup registers/stack for call
                if self.ql.archtype == QL_ARCH.X86:
                    self.ql.log.debug('Setting up DllMain args')
                    self.ql.stack_push(dll_base)  # hinstDLL = base address of DLL
                    self.ql.stack_push(1)  # fdwReason = DLL_PROCESS_ATTACH
                    self.ql.stack_push(0)  # lpReserved = 0

                elif self.ql.archtype == QL_ARCH.X8664:
                    self.ql.log.debug('Setting up DllMain args')
                    self.ql.reg.rcx = dll_base  # hinstDLL = base address of DLL
                    self.ql.reg.rdx = 1  # fdwReason = DLL_PROCESS_ATTACH
                else:
                    raise QlErrorArch("Unknown ql.arch")

                # Execute the call to the entry point
                try:
                    self.ql.emu_start(code_loc, code_loc_end, 0, 0)
                except UcError as e:
                    self.ql.os.emu_error()
                    raise e
                self.ql.log.info("Done calling entry point of dll %s at 0x%x" % (dll_name, entry_point))

    def _alloc_cmdline(self, wide):
        addr = self.ql.os.heap.alloc(len(self.cmdline) * (2 if wide else 1))
        packed_addr = self.ql.pack(addr)
        return addr, packed_addr

    def set_cmdline(self, name, address, memory):
        cmdline_entry = None
        if name == b"_acmdln":
            addr, packed_addr = self._alloc_cmdline(wide=False)
            cmdline_entry = {"name": name, "address": address}
            memory[address:address + self.ql.pointersize] = packed_addr
            self.ql.mem.write(addr, self.cmdline)
        elif name == b"_wcmdln":
            addr, packed_addr = self._alloc_cmdline(wide=True)
            cmdline_entry = {"name": name, "address": address}
            memory[address:address + self.ql.pointersize] = packed_addr
            encoded = self.cmdline.decode('ascii').encode('UTF-16LE')
            self.ql.mem.write(addr, encoded)

        return cmdline_entry

    def init_tib(self):
        if self.ql.archtype == QL_ARCH.X86:
            teb_addr = self.structure_last_addr
        else:
            gs = self.structure_last_addr
            self.structure_last_addr += 0x30
            teb_addr = self.structure_last_addr

        self.ql.log.info("TEB addr is 0x%x" %teb_addr)

        teb_size = len(TEB(self.ql).bytes())
        teb_data = TEB(
            self.ql,
            base=teb_addr,
            peb_address=teb_addr + teb_size,
            stack_base=self.stack_address + self.stack_size,
            stack_limit=self.stack_size,
            Self=teb_addr)

        self.ql.mem.write(teb_addr, teb_data.bytes())

        self.structure_last_addr += teb_size
        if self.ql.archtype == QL_ARCH.X8664:
            # TEB
            self.ql.mem.write(gs + 0x30, self.ql.pack64(teb_addr))
            # PEB
            self.ql.mem.write(gs + 0x60, self.ql.pack64(teb_addr + teb_size))

        self.TEB = self.ql.TEB = teb_data

    def init_peb(self):
        peb_addr = self.structure_last_addr

        self.ql.log.info("PEB addr is 0x%x" % peb_addr)

        # we must set an heap, will try to retrieve this value. Is ok to be all \x00
        process_heap = self.ql.os.heap.alloc(0x100)
        peb_data = PEB(self.ql, base=peb_addr, process_heap=process_heap,
                       number_processors=self.ql.os.profile.getint("HARDWARE",
                                                                   "number_processors"))
        peb_data.LdrAddress = peb_addr + peb_data.size
        peb_data.write(peb_addr)
        self.structure_last_addr += peb_data.size
        self.PEB = self.ql.PEB = peb_data

    def init_ldr_data(self):
        ldr_addr = self.structure_last_addr
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
        self.structure_last_addr += ldr_size
        self.LDR = self.ql.LDR = ldr_data

    def add_ldr_data_table_entry(self, dll_name):
        dll_base = self.dlls[dll_name]
        path = "C:\\Windows\\System32\\" + dll_name
        ldr_table_entry_size = len(LdrDataTableEntry(self.ql).bytes())
        base = self.ql.os.heap.alloc(ldr_table_entry_size)
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

    def init_imports(self, pe, driver):
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
            self.pe.full_load()
        else:
            return

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_loaded = False
            dll_name = str(entry.dll.lower(), 'utf-8', 'ignore')
            original_dll_name = dll_name
            replaced_dll = False
            self.ql.log.debug("Requesting imports from %s" % dll_name)

            if dll_name.startswith("api-ms-win-"):
                # DLLs starting with this prefix contain no actual code.
                # Instead the windows loader loads the actual code from one of the main windows dlls.
                # https://github.com/lucasg/Dependencies shows the correct replacement dlls
                #
                # The correct way to find the dll that replaces all symbols from this dll involves using the hashmap
                # inside of apisetschema.dll (see https://lucasg.github.io/2017/10/15/Api-set-resolution/ ).
                # Currently, we use a simpler, more hacky approach, that seems to work in a lot of cases:
                #  We just scan through some key dlls and hope that we find the requested symbols there
                # Note: You might be tempted to load the actual dll (dll_name), because they also contain a reference to
                #  the replacement dll. However, chances are, that these dlls do not exist in the rootfs and maybe they
                #  don't even exist on windows. Therefore this approach is a bad idea.

                first_imp = entry.imports[0]
                key_dlls = ["ntdll.dll", "kernelbase.dll"]  # DLLs that seem to contain most of the requested symbols
                for key_dll in key_dlls:
                    if first_imp.name in self.import_address_table[key_dll]:
                        self.ql.log.debug(f"Redirect {dll_name} to {key_dll}")
                        dll_name = key_dll
                        break
                if dll_name == original_dll_name:
                    self.ql.log.warning(f"Failed to resolve {original_dll_name}")
                    continue
                replaced_dll = True

            for imp in entry.imports:
                if imp.bound:
                    continue

                # Only load dll if encounter unbound symbol
                if not dll_loaded and not replaced_dll:
                    self.load_dll(entry.dll, driver)
                    dll_loaded = True

                if imp.name:
                    try:
                        addr = self.import_address_table[dll_name][imp.name]
                    except KeyError:
                        self.ql.log.warning(f"Error in loading function {original_dll_name}.{imp.name.decode()}")
                        continue
                else:
                    addr = self.import_address_table[dll_name][imp.ordinal]

                if self.ql.archtype == QL_ARCH.X86:
                    address = self.ql.pack32(addr)
                else:
                    address = self.ql.pack64(addr)
                try:
                    self.ql.mem.write(imp.address, address)
                except BaseException as e:
                    self.ql.log.warning(f"Cannot write mem for import of dll {dll_name}: {e}")
                    raise e

    def init_exports(self):
        if self.ql.code:
            return
        if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress != 0:
            # Do a full load if IMAGE_DIRECTORY_ENTRY_EXPORT is present so we can load the exports
            self.pe.full_load()
        else:
            return

        try:
            # parse directory entry export
            dll_name = os.path.basename(self.path)
            self.import_address_table[dll_name] = {} 
            for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.export_symbols[self.pe_image_address + entry.address] = {'name': entry.name, 'ordinal': entry.ordinal}
                self.import_address_table[dll_name][entry.name] = self.pe_image_address + entry.address
                self.import_address_table[dll_name][entry.ordinal] = self.pe_image_address + entry.address
        except:
            self.ql.log.info('Failed to load exports for %s:\n%s' % (self.ql.argv, traceback.format_exc()))

    def init_driver_object(self):
        # PDRIVER_OBJECT DriverObject
        driver_object_addr = self.structure_last_addr
        self.ql.log.info("Driver object addr is 0x%x" %driver_object_addr)

        if self.ql.archtype == QL_ARCH.X86:
            self.driver_object = DRIVER_OBJECT32(self.ql, driver_object_addr)
        elif self.ql.archtype == QL_ARCH.X8664:
            self.driver_object = DRIVER_OBJECT64(self.ql, driver_object_addr)

        driver_object_size = ctypes.sizeof(self.driver_object)
        self.ql.mem.write(driver_object_addr, bytes(self.driver_object))
        self.structure_last_addr += driver_object_size
        self.driver_object_address = driver_object_addr


    def init_registry_path(self):
        # PUNICODE_STRING RegistryPath
        regitry_path_addr = self.structure_last_addr
        self.ql.log.info("Registry path addr is 0x%x" %regitry_path_addr)

        if self.ql.archtype == QL_ARCH.X86:
            regitry_path_data = UNICODE_STRING32(0, 0, regitry_path_addr)
        elif self.ql.archtype == QL_ARCH.X8664:
            regitry_path_data = UNICODE_STRING64(0, 0, regitry_path_addr)

        regitry_path_size = ctypes.sizeof(regitry_path_data)
        self.ql.mem.write(regitry_path_addr, bytes(regitry_path_data))
        self.structure_last_addr += regitry_path_size
        self.regitry_path_address = regitry_path_addr


    def init_eprocess(self):
        addr = self.structure_last_addr
        self.ql.log.info("EPROCESS is is 0x%x" %addr)


        if self.ql.archtype == QL_ARCH.X86:
            self.eprocess_object = EPROCESS32(self.ql, addr)
        elif self.ql.archtype == QL_ARCH.X8664:
            self.eprocess_object = EPROCESS64(self.ql, addr)            

        size = ctypes.sizeof(self.eprocess_object)
        self.ql.mem.write(addr, bytes(self.driver_object))
        self.structure_last_addr += size
        self.ql.eprocess_address = addr


    def init_ki_user_shared_data(self):
        '''
        https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data/index.htm

		struct information:
		https://doxygen.reactos.org/d8/dae/modules_2rostests_2winetests_2ntdll_2time_8c_source.html
        '''
        if self.ql.archtype == QL_ARCH.X86:
            KI_USER_SHARED_DATA = 0xFFDF0000
        elif self.ql.archtype == QL_ARCH.X8664:
            KI_USER_SHARED_DATA = 0xFFFFF78000000000

        self.ql.log.info("KI_USER_SHARED_DATA is 0x%x" %KI_USER_SHARED_DATA)

        shared_user_data = KUSER_SHARED_DATA()

        shared_user_data_len = self.align(ctypes.sizeof(KUSER_SHARED_DATA), 0x1000)
        self.ql.mem.map(KI_USER_SHARED_DATA, shared_user_data_len)
        self.ql.mem.write(KI_USER_SHARED_DATA, bytes(shared_user_data))


class QlLoaderPE(QlLoader, Process):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ql         = ql
        self.path       = self.ql.path
        self.is_driver  = False

        if ql.libcache is True:
            self.libcache = QlPeCache()
        else:
            self.libcache = ql.libcache or None

    def run(self):
        self.init_dlls = [b"ntdll.dll", b"kernel32.dll", b"user32.dll"]
        self.sys_dlls = [b"ntdll.dll", b"kernel32.dll"]
        self.pe_entry_point = 0
        self.sizeOfStackReserve = 0        

        if not self.ql.code:
            self.pe = pefile.PE(self.path, fast_load=True)
            self.is_driver = self.pe.is_driver()
            if self.is_driver == True:
                self.init_dlls.append(b"ntoskrnl.exe")
                self.sys_dlls.append(b"ntoskrnl.exe")
            
        if self.ql.archtype == QL_ARCH.X86:
            self.stack_address = int(self.ql.os.profile.get("OS32", "stack_address"), 16)
            self.stack_size = int(self.ql.os.profile.get("OS32", "stack_size"), 16)
            self.image_address = int(self.ql.os.profile.get("OS32", "image_address"), 16)
            self.dll_address = int(self.ql.os.profile.get("OS32", "dll_address"), 16)
            self.entry_point = int(self.ql.os.profile.get("OS32", "entry_point"), 16)
            self.ql.os.heap_base_address = int(self.ql.os.profile.get("OS32", "heap_address"), 16)
            self.ql.os.heap_base_size = int(self.ql.os.profile.get("OS32", "heap_size"), 16)
            self.structure_last_addr = FS_SEGMENT_ADDR
        elif self.ql.archtype == QL_ARCH.X8664:
            self.stack_address = int(self.ql.os.profile.get("OS64", "stack_address"), 16)
            self.stack_size = int(self.ql.os.profile.get("OS64", "stack_size"), 16)
            self.image_address = int(self.ql.os.profile.get("OS64", "image_address"), 16)
            self.dll_address = int(self.ql.os.profile.get("OS64", "dll_address"), 16)
            self.entry_point = int(self.ql.os.profile.get("OS64", "entry_point"), 16)
            self.ql.os.heap_base_address = int(self.ql.os.profile.get("OS64", "heap_address"), 16)
            self.ql.os.heap_base_size = int(self.ql.os.profile.get("OS64", "heap_size"), 16)
            self.structure_last_addr = GS_SEGMENT_ADDR

        self.dlls = {}
        self.import_symbols = {}
        self.export_symbols = {}
        self.import_address_table = {}
        self.ldr_list = []
        self.pe_image_address = 0
        self.pe_image_address_size = 0
        self.dll_size = 0
        self.dll_last_address = self.dll_address
        # compatible with ql.__enable_bin_patch()
        self.load_address = 0
        self.ql.os.heap = QlMemoryHeap(self.ql, self.ql.os.heap_base_address, self.ql.os.heap_base_address + self.ql.os.heap_base_size)
        self.ql.os.setupComponents()
        self.ql.os.entry_point = self.entry_point
        cmdline = (str(self.ql.os.userprofile)) + "Desktop\\" + self.ql.targetname
        self.filepath = bytes(cmdline + "\x00", "utf-8")
        for arg in self.argv[1:]:
            if ' ' in arg:
                cmdline += f' "{arg}"'
            else:
                cmdline += f' {arg}'
        cmdline += "\x00"
        self.cmdline = bytes(cmdline, "utf-8")

        self.load()

    def init_thread_information_block(self):
        super().init_tib()
        super().init_peb()
        super().init_ldr_data()
        super().init_exports()

    def load(self):
        # set stack pointer
        self.ql.log.info("Initiate stack address at 0x%x " % self.stack_address)
        self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")

        if self.path and not self.ql.code:
            # for simplicity, no image base relocation
            self.pe_image_address = self.pe.OPTIONAL_HEADER.ImageBase
            self.pe_image_address_size = self.ql.mem.align(self.pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

            if self.pe_image_address + self.pe_image_address_size > self.ql.os.heap_base_address:
                # pe reloc
                self.pe_image_address = self.image_address
                self.pe.relocate_image(self.image_address)

            self.entry_point = self.pe_entry_point = self.pe_image_address + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.sizeOfStackReserve = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
            self.ql.log.info("Loading %s to 0x%x" % (self.path, self.pe_image_address))
            self.ql.log.info("PE entry point at 0x%x" % self.entry_point)
            self.images.append(Image(self.pe_image_address, self.pe_image_address + self.pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfImage, self.path))

            # Stack should not init at the very bottom. Will cause errors with Dlls
            sp = self.stack_address + self.stack_size - 0x1000

            if self.ql.archtype == QL_ARCH.X86:
                self.ql.reg.esp = sp
                self.ql.reg.ebp = sp

                if self.pe.is_dll():
                    self.ql.log.debug('Setting up DllMain args')
                    load_addr_bytes = self.pe_image_address.to_bytes(length=4, byteorder='little')

                    self.ql.log.debug('Writing 0x%08X (IMAGE_BASE) to [ESP+4](0x%08X)' % (self.pe_image_address, sp + 0x4))
                    self.ql.mem.write(sp + 0x4, load_addr_bytes)

                    self.ql.log.debug('Writing 0x01 (DLL_PROCESS_ATTACH) to [ESP+8](0x%08X)' % (sp + 0x8))
                    self.ql.mem.write(sp + 0x8, int(1).to_bytes(length=4, byteorder='little'))

            elif self.ql.archtype == QL_ARCH.X8664:
                self.ql.reg.rsp = sp
                self.ql.reg.rbp = sp

                if self.pe.is_dll():
                    self.ql.log.debug('Setting up DllMain args')

                    self.ql.log.debug('Setting RCX (arg1) to %16X (IMAGE_BASE)' % (self.pe_image_address))
                    self.ql.reg.rcx = self.pe_image_address

                    self.ql.log.debug('Setting RDX (arg2) to 1 (DLL_PROCESS_ATTACH)')
                    self.ql.reg.rdx = 1
            else:
                raise QlErrorArch("Unknown ql.arch")

            # if this is NOT a driver, init tib/peb/ldr
            if not self.is_driver:  # userland program
                self.init_thread_information_block()
            else:   # Windows kernel driver
                super().init_driver_object()
                super().init_registry_path()
                super().init_eprocess()
                super().init_ki_user_shared_data()

                # setup IRQ Level in CR8 to PASSIVE_LEVEL (0)
                self.ql.reg.write(UC_X86_REG_CR8, 0)

                # setup CR4, some drivers may check this at initialized time
                self.ql.reg.write(UC_X86_REG_CR4, 0x6f8)

                self.ql.log.debug('Setting up DriverEntry args')
                self.ql.stop_execution_pattern = 0xDEADC0DE

                if self.ql.archtype == QL_ARCH.X86:  # Win32
                    if not self.ql.stop_options.any:
                        # We know that a driver will return,
                        # so if the user did not configure stop options, write a sentinel return value
                        self.ql.mem.write(sp, self.ql.stop_execution_pattern.to_bytes(length=4, byteorder='little'))

                    self.ql.log.debug('Writing 0x%08X (PDRIVER_OBJECT) to [ESP+4](0x%08X)' % (self.ql.loader.driver_object_address, sp+0x4))
                    self.ql.log.debug('Writing 0x%08X (RegistryPath) to [ESP+8](0x%08X)' % (self.ql.loader.regitry_path_address, sp+0x8))
                elif self.ql.archtype == QL_ARCH.X8664:  # Win64
                    if not self.ql.stop_options.any:
                        # We know that a driver will return,
                        # so if the user did not configure stop options, write a sentinel return value
                        self.ql.mem.write(sp, self.ql.stop_execution_pattern.to_bytes(length=8, byteorder='little'))

                    self.ql.log.debug('Setting RCX (arg1) to %16X (PDRIVER_OBJECT)' % (self.ql.loader.driver_object_address))
                    self.ql.log.debug('Setting RDX (arg2) to %16X (PUNICODE_STRING)' % (self.ql.loader.regitry_path_address))

                # setup args for DriverEntry()
                self.ql.os.fcall = self.ql.os.fcall_select(CDECL)
                self.ql.os.fcall.writeParams(((POINTER, self.ql.loader.driver_object_address), (POINTER, self.ql.loader.regitry_path_address)))

            # mmap PE file into memory
            self.ql.mem.map(self.pe_image_address, self.align(self.pe_image_address_size, 0x1000), info="[PE]")
            self.pe.parse_data_directories()
            data = bytearray(self.pe.get_memory_mapped_image())
            self.ql.mem.write(self.pe_image_address, bytes(data))
            # setup IMAGE_LOAD_CONFIG_DIRECTORY
            if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].VirtualAddress != 0:
                SecurityCookie_rva = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie - self.pe.OPTIONAL_HEADER.ImageBase
                SecurityCookie_value = default_security_cookie_value = self.ql.mem.read(self.pe_image_address+SecurityCookie_rva, self.ql.pointersize)
                while SecurityCookie_value == default_security_cookie_value:
                    SecurityCookie_value = secrets.token_bytes(self.ql.pointersize)
                    # rol     rcx, 10h (rcx: cookie)
                    # test    cx, 0FFFFh
                    SecurityCookie_value_array = bytearray(SecurityCookie_value)
                    # Sanity question: We are always little endian, right?
                    SecurityCookie_value_array[-2:] = b'\x00\x00'
                    SecurityCookie_value = bytes(SecurityCookie_value_array)
                self.ql.mem.write(self.pe_image_address+SecurityCookie_rva, SecurityCookie_value)

            # Add main PE to ldr_data_table
            mod_name = os.path.basename(self.path)
            self.dlls[mod_name] = self.pe_image_address
            # only userland code need LDR table
            if not self.is_driver:
                super().add_ldr_data_table_entry(mod_name)

            # load system dlls
            sys_dlls = self.sys_dlls
            for each in sys_dlls:
                super().load_dll(each, self.is_driver)
            # parse directory entry import
            self.ql.log.debug("Init imports for %s" % self.path)
            super().init_imports(self.pe, self.is_driver)

            self.ql.log.debug("Done with loading %s" % self.path)
            self.ql.os.entry_point = self.entry_point
            self.ql.os.pid = 101

        elif self.ql.code:
            self.filepath = b""
            if self.ql.archtype == QL_ARCH.X86:
                self.ql.reg.esp = self.stack_address + 0x3000
                self.ql.reg.ebp = self.ql.reg.esp
            elif self.ql.archtype == QL_ARCH.X8664:
                self.ql.reg.rsp = self.stack_address + 0x3000
                self.ql.reg.rbp = self.ql.reg.rsp

            # load shellcode in
            self.ql.mem.map(self.entry_point, self.ql.os.code_ram_size, info="[shellcode_base]")
            # rewrite entrypoint for windows shellcode
            self.ql.os.entry_point = self.entry_point
            self.ql.os.pid = 101

            self.ql.mem.write(self.entry_point, self.ql.code)
            
            self.init_thread_information_block()
            # load dlls
            for each in self.init_dlls:
                super().load_dll(each)

        # move entry_point to ql.os
        self.ql.os.entry_point = self.entry_point
        self.init_sp = self.ql.reg.arch_sp

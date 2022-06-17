#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, pefile, pickle, secrets, ntpath
from typing import Any, Dict, MutableMapping, NamedTuple, Optional, Mapping, Sequence, Tuple, Union

from unicorn import UcError
from unicorn.x86_const import UC_X86_REG_CR4, UC_X86_REG_CR8

from qiling import Qiling
from qiling.arch.x86_const import FS_SEGMENT_ADDR, GS_SEGMENT_ADDR
from qiling.const import QL_ARCH
from qiling.exception import QlErrorArch
from qiling.os.const import POINTER
from qiling.os.windows.api import HINSTANCE, DWORD, LPVOID
from qiling.os.windows.fncc import CDECL
from qiling.os.windows.utils import has_lib_ext
from qiling.os.windows.structs import *
from .loader import QlLoader, Image

class QlPeCacheEntry(NamedTuple):
    ba: int
    data: bytearray
    cmdlines: Sequence
    import_symbols: MutableMapping[int, dict]
    import_table: MutableMapping[Union[str, int], int]


class QlPeCache:
    @staticmethod
    def cache_filename(path: str) -> str:
        dirname, basename = os.path.split(path)

        # canonicalize basename while preserving the path
        path = os.path.join(dirname, basename.casefold())

        return f'{path}.cache2'

    def restore(self, path: str) -> Optional[QlPeCacheEntry]:
        fcache = QlPeCache.cache_filename(path)

        # check whether cache file exists and it is not older than the cached file itself
        if os.path.exists(fcache) and os.stat(fcache).st_mtime > os.stat(path).st_mtime:
            with open(fcache, "rb") as fcache_file:
                return QlPeCacheEntry(*pickle.load(fcache_file))

        return None

    def save(self, path: str, entry: QlPeCacheEntry) -> None:
        fcache = QlPeCache.cache_filename(path)

        # cache this dll file
        with open(fcache, "wb") as fcache_file:
            pickle.dump(entry, fcache_file)


class Process:
    # let linter recognize mixin members
    cmdline: bytes
    pe_image_address: int
    stack_address: int
    stack_size: int

    dlls: MutableMapping[str, int]
    import_address_table: MutableMapping[str, Mapping]
    import_symbols: MutableMapping[int, Dict[str, Any]]
    export_symbols: MutableMapping[int, Dict[str, Any]]
    libcache: Optional[QlPeCache]

    def __init__(self, ql: Qiling):
        self.ql = ql

    def __get_path_elements(self, name: str) -> Tuple[str, str]:
        """Translate DLL virtual path into host path.

        Args:
            name: dll virtual path; either absolute or relative

        Returns: dll path on the host and dll basename in a canonicalized form
        """

        dirname, basename = ntpath.split(name)

        if not has_lib_ext(basename):
            basename = f'{basename}.dll'

        # if only filename was specified assume it is located at the
        # system32 folder to prevent potential dll hijacking
        if not dirname:
            dirname = self.ql.os.winsys

        # reconstruct the dll virtual path
        vpath = ntpath.join(dirname, basename)

        return self.ql.os.path.virtual_to_host_path(vpath), basename.casefold()

    def load_dll(self, name: str, is_driver: bool = False) -> int:
        dll_path, dll_name = self.__get_path_elements(name)

        if dll_name.startswith('api-ms-win-'):
            # Usually we should not reach this point and instead imports from such DLLs should be redirected earlier
            self.ql.log.debug(f'Refusing to load virtual DLL {dll_name}')
            return 0

        # see if this dll was already loaded
        image = self.get_image_by_name(dll_name, casefold=True)

        if image is not None:
            return image.base

        if not os.path.exists(dll_path):
            # posix hosts may not find the requested filename if it was saved under a different case.
            # For example, 'KernelBase.dll' may not be found because it is stored as 'kernelbase.dll'.
            #
            # try to locate the requested file while ignoring the case of its path elements.
            dll_casefold_path = self.ql.os.path.host_casefold_path(dll_path)

            if dll_casefold_path is None:
                self.ql.log.error(f'Could not find DLL file: {dll_path}')
                return 0

            dll_path = dll_casefold_path

        self.ql.log.info(f'Loading {dll_name} ...')

        import_symbols = {}
        import_table = {}

        cached = None
        loaded = False

        if self.libcache:
            cached = self.libcache.restore(dll_path)

        if cached:
            data = cached.data

            image_base = cached.ba
            image_size = self.ql.mem.align_up(len(data))

            # verify whether we can load the dll to the same address it was loaded when it was cached.
            # if not, the dll will have to be realoded in order to have its symbols relocated using the
            # new address
            if self.ql.mem.is_available(image_base, image_size):
                import_symbols = cached.import_symbols
                import_table = cached.import_table

                for entry in cached.cmdlines:
                    self.set_cmdline(entry['name'], entry['address'], data)

                self.ql.log.info(f'Loaded {dll_name} from cache')
                loaded = True

        # either file was not cached, or could not be loaded to the same location in memory
        if not cached or not loaded:
            dll = pefile.PE(dll_path, fast_load=True)
            dll.parse_data_directories()
            warnings = dll.get_warnings()

            if warnings:
                self.ql.log.debug(f'Warnings while loading {dll_name}:')

                for warning in warnings:
                    self.ql.log.debug(f' - {warning}')

            image_base = dll.OPTIONAL_HEADER.ImageBase or self.dll_last_address
            image_size = self.ql.mem.align_up(dll.OPTIONAL_HEADER.SizeOfImage)
            relocate = False

            self.ql.log.debug(f'DLL preferred base address: {image_base:#x}')

            if (image_base + image_size) > self.ql.mem.max_mem_addr:
                image_base = self.dll_last_address
                self.ql.log.debug(f'DLL preferred base address exceeds memory upper bound, loading to: {image_base:#x}')
                relocate = True

            if not self.ql.mem.is_available(image_base, image_size):
                image_base = self.ql.mem.find_free_space(image_size, minaddr=image_base, align=0x10000)
                self.ql.log.debug(f'DLL preferred base address is taken, loading to: {image_base:#x}')
                relocate = True

            if relocate:
                with ShowProgress(0.1337):
                    dll.relocate_image(image_base)

            data = bytearray(dll.get_memory_mapped_image())
            assert image_size >= len(data)

            cmdlines = []

            for sym in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                ea = image_base + sym.address

                import_symbols[ea] = {
                    'name'    : sym.name,
                    'ordinal' : sym.ordinal,
                    'dll'     : dll_name.split('.')[0]
                }

                if sym.name:
                    import_table[sym.name] = ea

                import_table[sym.ordinal] = ea
                cmdline_entry = self.set_cmdline(sym.name, sym.address, data)

                if cmdline_entry:
                    cmdlines.append(cmdline_entry)

            if self.libcache:
                cached = QlPeCacheEntry(image_base, data, cmdlines, import_symbols, import_table)
                self.libcache.save(dll_path, cached)
                self.ql.log.info(f'Cached {dll_name}')

        # Add dll to IAT
        self.import_address_table[dll_name] = import_table
        self.import_symbols.update(import_symbols)

        dll_base = image_base
        dll_len = image_size

        self.dll_size += dll_len
        self.ql.mem.map(dll_base, dll_len, info=dll_name)
        self.ql.mem.write(dll_base, bytes(data))

        if dll_base == self.dll_last_address:
            self.dll_last_address = self.ql.mem.align_up(self.dll_last_address + dll_len, 0x10000)

        # add DLL to coverage images
        self.images.append(Image(dll_base, dll_base + dll_len, dll_path))

        # if this is NOT a driver, add dll to ldr data
        if not is_driver:
            self.add_ldr_data_table_entry(dll_name)

        if not cached or not loaded:
            # parse directory entry import
            self.ql.log.debug(f'Init imports for {dll_name}')
            self.init_imports(dll, is_driver)

            # calling DllMain is essential for dlls to initialize properly. however
            # DllMain of system libraries may fail due to incomplete or inaccurate
            # mock implementation. due to unicorn limitations, recovering from such
            # errors may be possible only if the function was not invoked from within
            # a hook.
            #
            # in case of a dll loaded from a hooked API call, failures would not be
            # recoverable and we have to give up its DllMain.
            if not self.ql.os.PE_RUN:
                self.call_dll_entrypoint(dll, dll_base, dll_len, dll_name)

        self.ql.log.info(f'Done loading {dll_name}')

        return dll_base

    def call_dll_entrypoint(self, dll: pefile.PE, dll_base: int, dll_len: int, dll_name: str):
        entry_address = dll.OPTIONAL_HEADER.AddressOfEntryPoint

        if dll.get_section_by_rva(entry_address) is None:
            return

        if dll_name in ('kernelbase.dll', 'kernel32.dll'):
            self.ql.log.debug(f'Ignoring {dll_name} entry point')
            return

        # DllMain functions often call many APIs that may crash the program if they
        # are not implemented correctly (if at all). here we blacklist the problematic
        # DLLs whose DllMain functions are known to be crashing.
        #
        # the blacklist may be revisited from time to time to see if any of the file
        # can be safely unlisted.
        blacklist = {
            32 : ('gdi32.dll',),
            64 : ('gdi32.dll',)
        }[self.ql.arch.bits]

        if dll_name in blacklist:
            self.ql.log.debug(f'Ignoring {dll_name} entry point (blacklisted)')
            return

        entry_point = dll_base + entry_address
        exit_point = dll_base + dll_len - 16

        args = (
            (HINSTANCE, dll_base),  # hinstDLL = base address of DLL
            (DWORD, 1),             # fdwReason = DLL_PROCESS_ATTACH
            (LPVOID, 0)             # lpReserved = 0
        )

        self.ql.log.info(f'Calling {dll_name} DllMain at {entry_point:#x}')

        regs_state = self.ql.arch.regs.save()

        fcall = self.ql.os.fcall_select(CDECL)
        fcall.call_native(entry_point, args, exit_point)

        # Execute the call to the entry point
        try:
            self.ql.emu_start(entry_point, exit_point)
        except UcError:
            self.ql.log.error(f'Error encountered while running {dll_name} DllMain, bailing')

            self.ql.arch.regs.restore(regs_state)
        else:
            fcall.cc.unwind(len(args))

            self.ql.log.info(f'Returned from {dll_name} DllMain')

    def set_cmdline(self, name: bytes, address: int, memory: bytearray):
        cmdln = {
            b'_acmdln' : 1,
            b'_wcmdln' : 2
        }

        clen = cmdln.get(name, None)

        if clen is None:
            return None

        addr = self.ql.os.heap.alloc(len(self.cmdline) * clen)
        memory[address:address + self.ql.arch.pointersize] = self.ql.pack(addr)
        data = self.cmdline

        if clen == 2:
            data = data.decode('ascii').encode('UTF-16LE')

        self.ql.mem.write(addr, data)

        return {"name": name, "address": address}

    def init_teb(self):
        teb_obj = make_teb(self.ql.arch.bits)

        teb_addr = self.structure_last_addr
        peb_addr = self.ql.mem.align_up(teb_addr + ctypes.sizeof(teb_obj), 0x10)

        teb_obj.StackBase  = self.stack_address + self.stack_size
        teb_obj.StackLimit = self.stack_address
        teb_obj.TebAddress = teb_addr
        teb_obj.PebAddress = peb_addr

        self.ql.log.info(f'TEB is at {teb_addr:#x}')
        self.ql.mem.write(teb_addr, bytes(teb_obj))

        self.structure_last_addr = peb_addr
        self.TEB = teb_obj

    def init_peb(self):
        peb_obj = make_peb(self.ql.arch.bits)

        peb_addr = self.structure_last_addr
        ldr_addr = self.ql.mem.align_up(peb_addr + ctypes.sizeof(peb_obj), 0x10)

        # we must set an heap, will try to retrieve this value. Is ok to be all \x00
        peb_obj.LdrAddress         = ldr_addr
        peb_obj.ProcessParameters  = self.ql.os.heap.alloc(0x100)
        peb_obj.ProcessHeap        = self.ql.os.heap.alloc(0x100)
        peb_obj.NumberOfProcessors = self.ql.os.profile.getint('HARDWARE', 'number_processors')

        self.ql.log.info(f'PEB is at {peb_addr:#x}')
        self.ql.mem.write(peb_addr, bytes(peb_obj))

        self.structure_last_addr = ldr_addr
        self.PEB = peb_obj

    def init_ldr_data(self):
        ldr_obj = make_ldr_data(self.ql.arch.bits)
        ldr_cls = ldr_obj.__class__

        ldr_addr = self.structure_last_addr
        nobj_addr = self.ql.mem.align_up(ldr_addr + ctypes.sizeof(ldr_obj), 0x10)

        ldr_obj.InLoadOrderModuleList.Flink = ldr_addr + ldr_cls.InLoadOrderModuleList.offset
        ldr_obj.InLoadOrderModuleList.Blink = ldr_addr + ldr_cls.InLoadOrderModuleList.offset

        ldr_obj.InMemoryOrderModuleList.Flink = ldr_addr + ldr_cls.InMemoryOrderModuleList.offset
        ldr_obj.InMemoryOrderModuleList.Blink = ldr_addr + ldr_cls.InMemoryOrderModuleList.offset

        ldr_obj.InInitializationOrderModuleList.Flink = ldr_addr + ldr_cls.InInitializationOrderModuleList.offset
        ldr_obj.InInitializationOrderModuleList.Blink = ldr_addr + ldr_cls.InInitializationOrderModuleList.offset

        self.ql.log.info(f'LDR is at {ldr_addr:#x}')
        self.ql.mem.write(ldr_addr, bytes(ldr_obj))

        self.structure_last_addr = nobj_addr
        self.LDR = ldr_obj

    def add_ldr_data_table_entry(self, dll_name: str):
        entry_obj = make_ldr_data_table_entry(self.ql.arch.bits)
        entry_cls = entry_obj.__class__

        entry_size = ctypes.sizeof(entry_obj)
        entry_addr = self.ql.os.heap.alloc(entry_size)

        def populate_unistr(obj, s: str) -> None:
            encoded = s.encode('utf-16le')
            ucslen = len(encoded)
            ucsbuf = self.ql.os.heap.alloc(ucslen + 2)

            self.ql.mem.write(ucsbuf, encoded + b'\x00\x00')

            obj.Length = ucslen
            obj.MaximumLength = ucslen + 2
            obj.Buffer = ucsbuf

        image = self.get_image_by_name(dll_name, casefold=True)
        assert image, 'image should have been added to loader.images first'

        entry_obj.DllBase = image.base
        populate_unistr(entry_obj.FullDllName, ntpath.join(self.ql.os.winsys, dll_name))
        populate_unistr(entry_obj.BaseDllName, dll_name)

        # Flink
        if self.ldr_list:
            flink_base, flink = self.ldr_list[-1]

            entry_obj.InLoadOrderLinks.Flink = flink.InLoadOrderLinks.Flink
            entry_obj.InMemoryOrderLinks.Flink = flink.InMemoryOrderLinks.Flink
            entry_obj.InInitializationOrderLinks.Flink = flink.InInitializationOrderLinks.Flink

            flink.InLoadOrderLinks.Flink = entry_addr + entry_cls.InLoadOrderLinks.offset
            flink.InMemoryOrderLinks.Flink = entry_addr + entry_cls.InMemoryOrderLinks.offset
            flink.InInitializationOrderLinks.Flink = entry_addr + entry_cls.InInitializationOrderLinks.offset

        else:
            flink_base, flink = (self.PEB.LdrAddress, self.LDR)

            entry_obj.InLoadOrderLinks.Flink = flink.InLoadOrderModuleList.Flink
            entry_obj.InMemoryOrderLinks.Flink = flink.InMemoryOrderModuleList.Flink
            entry_obj.InInitializationOrderLinks.Flink = flink.InInitializationOrderModuleList.Flink

            flink.InLoadOrderModuleList.Flink = entry_addr + entry_cls.InLoadOrderLinks.offset
            flink.InMemoryOrderModuleList.Flink = entry_addr + entry_cls.InMemoryOrderLinks.offset
            flink.InInitializationOrderModuleList.Flink = entry_addr + entry_cls.InInitializationOrderLinks.offset

        # Blink
        blink_base = self.PEB.LdrAddress
        blink = self.LDR

        entry_obj.InLoadOrderLinks.Blink = blink.InLoadOrderModuleList.Blink
        entry_obj.InMemoryOrderLinks.Blink = blink.InMemoryOrderModuleList.Blink
        entry_obj.InInitializationOrderLinks.Blink = blink.InInitializationOrderModuleList.Blink

        blink.InLoadOrderModuleList.Blink = entry_addr + entry_cls.InLoadOrderLinks.offset
        blink.InMemoryOrderModuleList.Blink = entry_addr + entry_cls.InMemoryOrderLinks.offset
        blink.InInitializationOrderModuleList.Blink = entry_addr + entry_cls.InInitializationOrderLinks.offset

        self.ql.mem.write(flink_base, bytes(flink))
        self.ql.mem.write(blink_base, bytes(blink))
        self.ql.mem.write(entry_addr, bytes(entry_obj))

        self.ldr_list.append((entry_addr, entry_obj))

    @staticmethod
    def directory_exists(pe: pefile.PE, entry: str) -> bool:
        ent = pefile.DIRECTORY_ENTRY[entry]

        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[ent].VirtualAddress != 0

    def init_imports(self, pe: pefile.PE, is_driver: bool):
        if not Process.directory_exists(pe, 'IMAGE_DIRECTORY_ENTRY_IMPORT'):
            return

        pe.full_load()

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().casefold()
            self.ql.log.debug(f'Requesting imports from {dll_name}')

            orig_dll_name = dll_name
            redirected = False

            if dll_name.startswith('api-ms-win-'):
                # DLLs starting with this prefix contain no actual code. Instead, the windows loader loads the actual
                # code from one of the main windows dlls.
                # see https://github.com/lucasg/Dependencies for correct replacement dlls
                #
                # The correct way to find the dll that replaces all symbols from this dll involves using the hashmap
                # inside of apisetschema.dll (see https://lucasg.github.io/2017/10/15/Api-set-resolution/ ).
                #
                # Currently, we use a simpler, more hacky approach, that seems to work in a lot of cases: we just scan
                # through some key dlls and hope that we find the requested symbols there. some symbols may appear on
                # more than one dll though; in that case we proceed to the next symbol to see which key dll includes it.
                #
                # Note: You might be tempted to load the actual dll (dll_name), because they also contain a reference to
                # the replacement dll. However, chances are, that these dlls do not exist in the rootfs and maybe they
                # don't even exist on windows. Therefore this approach is a bad idea.

                # DLLs that seem to contain most of the requested symbols
                key_dlls = (
                    'ntdll.dll',
                    'kernelbase.dll',
                    'ucrtbase.dll'
                )

                imports = iter(entry.imports)
                failed = False
                fallback = None

                while not redirected and not failed:
                    # find all possible redirection options by scanning key dlls for the current imported symbol
                    imp = next(imports, None)
                    redirection_options = [fallback] if imp is None else [filename for filename in key_dlls if filename in self.import_address_table and imp.name in self.import_address_table[filename]]

                    # no redirection options: failed to redirect dll
                    if not redirection_options:
                        failed = True

                    # exactly one redirection options: use it
                    elif len(redirection_options) == 1:
                        key_dll = redirection_options[0]
                        redirected = True

                    # more than one redirection options: remember one of them and proceed to next symbol
                    else:
                        fallback = redirection_options[-1]

                if not redirected:
                    self.ql.log.warning(f'Failed to resolve {dll_name}')
                    continue

                self.ql.log.debug(f'Redirecting {dll_name} to {key_dll}')
                dll_name = key_dll

            unbound_imports = [imp for imp in entry.imports if not imp.bound]

            if unbound_imports:
                # Only load dll if encountered unbound symbol
                if not redirected:
                    dll_base = self.load_dll(entry.dll.decode(), is_driver)

                    if not dll_base:
                        continue

                for imp in unbound_imports:
                    iat = self.import_address_table[dll_name]

                    if imp.name:
                        if imp.name not in iat:
                            self.ql.log.debug(f'Error in loading function {imp.name.decode()} ({orig_dll_name}){", probably misdirected" if redirected else ""}')
                            continue

                        addr = iat[imp.name]
                    else:
                        addr = iat[imp.ordinal]

                    self.ql.mem.write_ptr(imp.address, addr)

    def init_exports(self, pe: pefile.PE):
        if not Process.directory_exists(pe, 'IMAGE_DIRECTORY_ENTRY_EXPORT'):
            return

        # Do a full load if IMAGE_DIRECTORY_ENTRY_EXPORT is present so we can load the exports
        pe.full_load()

        iat = {}

        # parse directory entry export
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            ea = self.pe_image_address + entry.address

            self.export_symbols[ea] = {
                'name'    : entry.name,
                'ordinal' : entry.ordinal
            }

            if entry.name:
                iat[entry.name] = ea

            iat[entry.ordinal] = ea

        dll_name = os.path.basename(self.path)
        self.import_address_table[dll_name.casefold()] = iat

    def init_driver_object(self):
        drv_addr = self.structure_last_addr

        # PDRIVER_OBJECT DriverObject
        drv_obj = make_driver_object(self.ql, drv_addr, self.ql.arch.bits)
        nobj_addr = self.ql.mem.align_up(drv_addr + ctypes.sizeof(drv_obj), 0x10)

        self.ql.log.info(f'DriverObject is at {drv_addr:#x}')
        self.ql.mem.write(drv_addr, bytes(drv_obj))

        self.structure_last_addr = nobj_addr
        self.driver_object_address = drv_addr
        self.driver_object = drv_obj

    def init_registry_path(self):
        regpath_addr = self.structure_last_addr

        # PUNICODE_STRING RegistryPath
        regpath_obj = make_unicode_string(self.ql.arch.bits,
                Length=0,
                MaximumLength=0,
                Buffer=regpath_addr
        )

        nobj_addr = self.ql.mem.align_up(regpath_addr + ctypes.sizeof(regpath_obj), 0x10)

        self.ql.log.info(f'RegistryPath is at {regpath_addr:#x}')
        self.ql.mem.write(regpath_addr, bytes(regpath_obj))

        self.structure_last_addr = nobj_addr
        self.regitry_path_address = regpath_addr

    def init_eprocess(self):
        eproc_obj = make_eprocess(self.ql.arch.bits)

        eproc_addr = self.structure_last_addr
        nobj_addr = self.ql.mem.align_up(eproc_addr + ctypes.sizeof(eproc_obj), 0x10)

        self.ql.mem.write(eproc_addr, bytes(eproc_obj))

        self.structure_last_addr = nobj_addr
        self.eprocess_address = eproc_addr

    def init_ki_user_shared_data(self):
        addr = self.ql.os.profile.getint(f'OS{self.ql.arch.bits}', 'KI_USER_SHARED_DATA')

        user_shared_data_obj = KUSER_SHARED_DATA()
        user_shared_data_size = ctypes.sizeof(KUSER_SHARED_DATA)

        self.ql.mem.map(addr, self.ql.mem.align_up(user_shared_data_size))
        self.ql.mem.write(addr, bytes(user_shared_data_obj))

    def init_security_cookie(self, pe: pefile.PE, image_base: int):
        if not Process.directory_exists(pe, 'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'):
            return

        cookie_rva = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie - pe.OPTIONAL_HEADER.ImageBase

        # get a random cookie value but keep the two most significant bytes zeroes
        #
        #   rol   rcx, 10h    ; rcx = cookie
        #   test  cx, 0FFFFh
        cookie = secrets.randbits(self.ql.arch.bits - 16)

        self.ql.mem.write_ptr(cookie_rva + image_base, cookie)

class QlLoaderPE(QlLoader, Process):
    def __init__(self, ql: Qiling, libcache: bool):
        super().__init__(ql)

        self.ql       = ql
        self.path     = self.ql.path
        self.libcache = QlPeCache() if libcache else None

    def run(self):
        self.init_dlls = (
            'ntdll.dll',
            'kernel32.dll',
            'user32.dll'
        )

        self.sys_dlls = (
            'ntdll.dll',
            'kernel32.dll',
            'ucrtbase.dll'
        )

        if self.ql.code:
            pe = None
            self.is_driver = False
        else:
            pe = pefile.PE(self.path, fast_load=True)
            self.is_driver = pe.is_driver()

        ossection = f'OS{self.ql.arch.bits}'

        self.stack_address = self.ql.os.profile.getint(ossection, 'stack_address')
        self.stack_size    = self.ql.os.profile.getint(ossection, 'stack_size')
        self.image_address = self.ql.os.profile.getint(ossection, 'image_address')
        self.dll_address   = self.ql.os.profile.getint(ossection, 'dll_address')
        self.entry_point   = self.ql.os.profile.getint(ossection, 'entry_point')

        self.structure_last_addr = {
            32 : FS_SEGMENT_ADDR,
            64 : GS_SEGMENT_ADDR
        }[self.ql.arch.bits]

        self.import_symbols = {}
        self.export_symbols = {}
        self.import_address_table = {}
        self.ldr_list = []
        self.pe_image_address = 0
        self.pe_image_size = 0
        self.dll_size = 0
        self.dll_last_address = self.dll_address

        # not used, but here to remain compatible with ql.do_bin_patch
        self.load_address = 0

        cmdline = ntpath.join(self.ql.os.userprofile, 'Desktop', self.ql.targetname)
        cmdargs = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in self.argv[1:])

        self.filepath = bytes(f'{cmdline}\x00', "utf-8")
        self.cmdline = bytes(f'{cmdline} {cmdargs}\x00', "utf-8")

        self.load(pe)

    def load(self, pe: Optional[pefile.PE]):
        # set stack pointer
        self.ql.log.info("Initiate stack address at 0x%x " % self.stack_address)
        self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")

        if pe is not None:
            image_name = os.path.basename(self.path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            image_size = self.ql.mem.align_up(pe.OPTIONAL_HEADER.SizeOfImage)

            # if default base address is taken, use the one specified in profile
            if not self.ql.mem.is_available(image_base, image_size):
                image_base = self.image_address
                pe.relocate_image(image_base)

            self.entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.pe_image_address = image_base
            self.pe_image_size = image_size

            self.ql.log.info(f'Loading {self.path} to {image_base:#x}')
            self.ql.log.info(f'PE entry point at {self.entry_point:#x}')

            self.ql.mem.map(image_base, image_size, info=f'[{image_name}]')
            self.images.append(Image(image_base, image_base + pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfImage, os.path.abspath(self.path)))

            if self.is_driver:
                self.init_driver_object()
                self.init_registry_path()
                self.init_eprocess()
                self.init_ki_user_shared_data()

                # set IRQ Level in CR8 to PASSIVE_LEVEL
                self.ql.arch.regs.write(UC_X86_REG_CR8, 0)

                # setup CR4, enabling: DE, PSE, PAE, MCE, PGE, OSFXSR and OSXMMEXCPT.
                # some drivers may check this at initialized
                self.ql.arch.regs.write(UC_X86_REG_CR4, 0b0000011011111000)

            else:
                # initialize thread information block
                self.init_teb()
                self.init_peb()
                self.init_ldr_data()
                self.init_exports(pe)

                # add image to ldr table
                self.add_ldr_data_table_entry(image_name)

            pe.parse_data_directories()

            # done manipulating pe file; write its contents into memory
            self.ql.mem.write(image_base, bytes(pe.get_memory_mapped_image()))

            if self.is_driver:
                # security cookie can be written only after image has been loaded to memory
                self.init_security_cookie(pe, image_base)

            # Stack should not init at the very bottom. Will cause errors with Dlls
            top_of_stack = self.stack_address + self.stack_size - 0x1000

            if self.ql.arch.type == QL_ARCH.X86:
                bp_reg = 'ebp'
                sp_reg = 'esp'
            elif self.ql.arch.type == QL_ARCH.X8664:
                bp_reg = 'rbp'
                sp_reg = 'rsp'
            else:
                raise QlErrorArch(f'unexpected arch type: {self.ql.arch.type}')

            # we are about to load some dlls and call their DllMain functions.
            # the stack should be set first
            self.ql.arch.regs.write(bp_reg, top_of_stack)
            self.ql.arch.regs.write(sp_reg, top_of_stack)

            # load system dlls
            for each in self.sys_dlls:
                super().load_dll(each, self.is_driver)

            # parse directory entry import
            self.ql.log.debug(f'Init imports for {self.path}')
            super().init_imports(pe, self.is_driver)

            self.ql.log.debug(f'Done loading {self.path}')

            if pe.is_driver():
                args = (
                    (POINTER, self.driver_object_address),
                    (POINTER, self.regitry_path_address)
                )

                self.ql.log.debug('Setting up call frame for DriverEntry:')
                self.ql.log.debug(f'  PDRIVER_OBJECT   DriverObject : {args[0][1]:#010x}')
                self.ql.log.debug(f'  PUNICODE_STRING  RegistryPath : {args[1][1]:#010x}')

                # We know that a driver will return, so if the user did not configure stop
                # options, write a sentinel return value
                ret = None if self.ql.stop_options else self.ql.stack_write(0, 0xdeadc0de)

                # set up call frame for DriverEntry
                self.ql.os.fcall.call_native(self.entry_point, args, ret)

            elif pe.is_dll():
                args = (
                    (POINTER, image_base),
                    (DWORD, 1),    # DLL_PROCESS_ATTACH
                    (POINTER, 0)
                )

                self.ql.log.debug('Setting up call frame for DllMain:')
                self.ql.log.debug(f'  HINSTANCE hinstDLL   : {args[0][1]:#010x}')
                self.ql.log.debug(f'  DWORD     fdwReason  : {args[1][1]:#010x}')
                self.ql.log.debug(f'  LPVOID    lpReserved : {args[2][1]:#010x}')

                # set up call frame for DllMain
                self.ql.os.fcall.call_native(self.entry_point, args, None)

        elif pe is None:
            self.filepath = b""

            self.ql.mem.map(self.entry_point, self.ql.os.code_ram_size, info="[shellcode]")

            self.init_teb()
            self.init_peb()
            self.init_ldr_data()

            # write shellcode to memory
            self.ql.mem.write(self.entry_point, self.ql.code)

            top_of_stack = self.stack_address + self.stack_size

            if self.ql.arch.type == QL_ARCH.X86:
                bp_reg = 'ebp'
                sp_reg = 'esp'
            elif self.ql.arch.type == QL_ARCH.X8664:
                bp_reg = 'rbp'
                sp_reg = 'rsp'
            else:
                raise QlErrorArch(f'unexpected arch type: {self.ql.arch.type}')

            self.ql.arch.regs.write(bp_reg, top_of_stack)
            self.ql.arch.regs.write(sp_reg, top_of_stack)

            # load dlls
            for each in self.init_dlls:
                super().load_dll(each, self.is_driver)

        # move entry_point to ql.os
        self.ql.os.entry_point = self.entry_point
        self.init_sp = self.ql.arch.regs.arch_sp

class ShowProgress:
    """Display a progress animation while performing a time
    consuming task.

    Example:
        >>> with ShowProgress(0.1):
        ...     do_some_time_consuming_task()
    """

    def __init__(self, interval: float) -> None:
        import sys
        from threading import Thread, Event

        # animation frames; any sequence of chars or strings may be used, as long
        # as they are of the same length. e.g. ['>   ', '>>  ', ' >> ', '  >>', '   >', '    ']
        frames = r'/-\|'
        stream = sys.stderr

        def show_animation():
            i = 0

            while not self.stopped.wait(interval):
                # TODO: find a proper way to use the logger for that
                print(f'[{frames[i % len(frames)]}]', end='\r', flush=True, file=stream)
                i += 1

        def show_nothing():
            pass

        # avoid flooding log files with animation frames
        action = show_animation if stream.isatty() else show_nothing

        self.stopped = Event()
        self.thread = Thread(target=action)

    def __enter__(self):
        self.thread.start()

        return self

    def __exit__(self, *args) -> None:
        self.stopped.set()
